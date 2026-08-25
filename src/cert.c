
#include "debug.h"
#include "error.h"
#include "fs_port.h"
#include "fs_ext.h"
#include "os_ext.h"
#include "rsa.h"
#include "rand.h"
#include "pem_import.h"
#include "pem_export.h"
#include "x509_cert_parse.h"
#include "x509_cert_create.h"
#include "x509_key_format.h"
#include "encoding/asn1.h"
#include "ecc/ec.h"
#include "ecc/ec_curves.h"
#include "ecc/ecdsa.h"
#include "pkcs8_key_format.h"
#include "server_helpers.h"

#include "tls_adapter.h"
#include "settings.h"
#include "cert.h"

static int hex2int(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return -1;
}

static void hex_string_to_bytes(const char *hex_string, uint8_t *output)
{
    while (*hex_string)
    {
        char hi = hex2int(*hex_string++);
        char lo = hex2int(*hex_string++);
        *output++ = (hi << 4) | lo;
    }
}

error_t cert_generate_rsa(int size, RsaPrivateKey *cert_privkey, RsaPublicKey *cert_pubkey)
{
    TRACE_INFO("Generating RSA Key... (slow, very slow!!!)\r\n");

    osMemset(cert_privkey, 0x00, sizeof(RsaPrivateKey));
    osMemset(cert_pubkey, 0x00, sizeof(RsaPublicKey));

    if (rsaGenerateKeyPair(rand_get_algo(), rand_get_context(), size, 65537, cert_privkey, cert_pubkey) != NO_ERROR)
    {
        TRACE_ERROR("rsaGenerateKeyPair failed\r\n");
        return ERROR_FAILURE;
    }
    return NO_ERROR;
}

error_t cert_get_rsa_priv(RsaPrivateKey *cert_privkey, uint8_t **priv_data, size_t *priv_size)
{
    if (x509ExportRsaPrivateKey(cert_privkey, NULL, priv_size) != NO_ERROR)
    {
        TRACE_ERROR("x509ExportRsaPrivateKey failed\r\n");
        return ERROR_FAILURE;
    }

    *priv_data = osAllocMem(*priv_size);

    if (x509ExportRsaPrivateKey(cert_privkey, *priv_data, priv_size) != NO_ERROR)
    {
        TRACE_ERROR("x509ExportRsaPrivateKey failed\r\n");
        return ERROR_FAILURE;
    }
    return NO_ERROR;
}

error_t cert_load_ca(X509CertInfo *cert, RsaPrivateKey *cert_priv)
{
    const char *server_ca = settings_get_string("internal.server.ca");
    const char *server_key = settings_get_string("internal.server.ca_key");

    size_t ca_size = 0;
    TRACE_INFO("Load CA certificate...\r\n");
    if (pemImportCertificate(server_ca, strlen(server_ca), NULL, &ca_size, NULL) != NO_ERROR)
    {
        TRACE_ERROR("pemImportCertificate failed\r\n");
        return ERROR_FAILURE;
    }

    uint8_t *server_ca_der = osAllocMem(ca_size);
    if (pemImportCertificate(server_ca, strlen(server_ca), server_ca_der, &ca_size, NULL) != NO_ERROR)
    {
        TRACE_ERROR("pemImportCertificate failed\r\n");
        return ERROR_FAILURE;
    }

    osMemset(cert, 0x00, sizeof(X509CertInfo));
    if (x509ParseCertificateEx(server_ca_der, ca_size, cert, true) != NO_ERROR)
    {
        TRACE_ERROR("x509ParseCertificateEx failed\r\n");
        return ERROR_FAILURE;
    }

    /* now export private key */
    osMemset(cert_priv, 0x00, sizeof(RsaPrivateKey));

    TRACE_INFO("Load CA key...\r\n");
    if (pemImportRsaPrivateKey(server_key, osStrlen(server_key), NULL, cert_priv) != NO_ERROR)
    {
        TRACE_ERROR("pemImportRsaPrivateKey failed\r\n");
        return ERROR_FAILURE;
    }

    /* we must not free this DER because the parsed certificate seems to point there */
    // osFreeMem(server_ca_der);

    return NO_ERROR;
}

error_t cert_generate_signed(const char *subject, const uint8_t *serial_number, int serial_number_size, size_t key_size, bool self_sign, bool cert_der_format, const char *cert_file, const char *priv_file)
{
    /* load server CA certificate */
    X509CertInfo issuer_cert;
    RsaPrivateKey issuer_priv;

    if (!self_sign)
    {
        if (cert_load_ca(&issuer_cert, &issuer_priv) != NO_ERROR)
        {
            TRACE_ERROR("cert_load_ca failed\r\n");
            return ERROR_FAILURE;
        }
    }

    /* generate RSA key */
    RsaPrivateKey cert_privkey;
    RsaPublicKey cert_pubkey;
    size_t priv_size = 0;
    uint8_t *priv_data = NULL;

    if (cert_generate_rsa(key_size, &cert_privkey, &cert_pubkey) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_rsa failed\r\n");
        return ERROR_FAILURE;
    }
    if (cert_get_rsa_priv(&cert_privkey, &priv_data, &priv_size) != NO_ERROR)
    {
        TRACE_ERROR("cert_get_rsa_priv failed\r\n");
        return ERROR_FAILURE;
    }

    /* #115: if the private-key file uses a .pem/.key extension, also export the key
       as PEM (PKCS#8) so we write a real PEM file instead of raw DER. This must run
       while cert_privkey is still valid (it is freed below after signing); .der
       targets keep DER. */
    char_t *priv_pem_data = NULL;
    size_t priv_pem_size = 0;
    size_t priv_file_len = priv_file ? osStrlen(priv_file) : 0;
    if (priv_file_len > 4 && (!osStrcasecmp(&priv_file[priv_file_len - 4], ".pem") || !osStrcasecmp(&priv_file[priv_file_len - 4], ".key")))
    {
        /* Export into a fixed buffer, mirroring cert_generate_signed_ec. 8 KB holds
           a 4096-bit RSA key in PKCS#8 PEM with room to spare. (pemExportRsaPrivateKey
           must not be called with a NULL output buffer.) */
        char_t temp_pem_buf[8192];
        size_t temp_pem_size = sizeof(temp_pem_buf);
        if (pemExportRsaPrivateKey(&cert_privkey, temp_pem_buf, &temp_pem_size) == NO_ERROR && temp_pem_size > 0)
        {
            priv_pem_data = osAllocMem(temp_pem_size + 1);
            osMemcpy(priv_pem_data, temp_pem_buf, temp_pem_size);
            priv_pem_data[temp_pem_size] = '\0';
            priv_pem_size = temp_pem_size;
        }
        else
        {
            TRACE_WARNING("PEM export of RSA private key failed; writing DER to '%s'\r\n", priv_file);
        }
    }

    /* create and sign the certificate */
    X509CertRequestInfo cert_req;
    osMemset(&cert_req, 0x00, sizeof(cert_req));
    cert_req.version = X509_VERSION_1;
    cert_req.subject.name.value = subject;
    cert_req.subject.name.length = osStrlen(subject);
    cert_req.subject.commonName.value = subject;
    cert_req.subject.commonName.length = osStrlen(subject);
    cert_req.subject.organizationName.value = "Team RevvoX";
    cert_req.subject.organizationName.length = 11;
    cert_req.subject.countryName.value = "DE";
    cert_req.subject.countryName.length = 2;
    cert_req.subject.localityName.value = "Duesseldorf";
    cert_req.subject.localityName.length = 11;
    cert_req.subject.stateOrProvinceName.value = "NW";
    cert_req.subject.stateOrProvinceName.length = 2;

    cert_req.subjectPublicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
    cert_req.subjectPublicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

    /*
    cert_req.attributes.extensionReq.keyUsage.bitmap |= X509_KEY_USAGE_DIGITAL_SIGNATURE;
    cert_req.attributes.extensionReq.keyUsage.bitmap |= X509_KEY_USAGE_NON_REPUDIATION;
    cert_req.attributes.extensionReq.extKeyUsage.bitmap |= X509_EXT_KEY_USAGE_SERVER_AUTH;
    cert_req.attributes.extensionReq.extKeyUsage.bitmap |= X509_EXT_KEY_USAGE_CLIENT_AUTH;
    */

    if (self_sign)
    {
        cert_req.attributes.extensionReq.basicConstraints.cA = true;
        // cert_req.attributes.extensionReq.keyUsage.bitmap |= X509_KEY_USAGE_KEY_CERT_SIGN;
    }

    X509SerialNumber serial;
    osMemset(&serial, 0x00, sizeof(serial));
    serial.length = serial_number_size;
    serial.value = serial_number;

    X509Validity validity;
    osMemset(&validity, 0x00, sizeof(validity));
    getCurrentDate(&validity.notBefore);
    getCurrentDate(&validity.notAfter);

    validity.notBefore.year = 2015;
    validity.notBefore.month = 11;
    validity.notBefore.day = 3;
    validity.notBefore.hours = 15;
    validity.notBefore.minutes = 23;
    validity.notBefore.seconds = 19;

    validity.notAfter.year = 2040;
    validity.notAfter.month = 6;
    validity.notAfter.day = 24;
    validity.notAfter.hours = 15;
    validity.notAfter.minutes = 23;
    validity.notAfter.seconds = 19;

    X509SignAlgoId algo;
    osMemset(&algo, 0x00, sizeof(algo));
    algo.oid.value = SHA256_WITH_RSA_ENCRYPTION_OID;
    algo.oid.length = sizeof(SHA256_WITH_RSA_ENCRYPTION_OID);

    /* create certificate */
    uint8_t *cert_der_data = osAllocMem(8192);
    size_t cert_der_size = 0;
    error_t error = x509CreateCertificate(rand_get_algo(), rand_get_context(), &cert_req, &cert_pubkey, self_sign ? NULL : &issuer_cert, &serial, &validity, &algo, self_sign ? &cert_privkey : &issuer_priv, cert_der_data, &cert_der_size);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("x509CreateCertificate failed: %s\r\n", error2text(error));
        return ERROR_FAILURE;
    }

    rsaFreePublicKey(&cert_pubkey);
    rsaFreePrivateKey(&cert_privkey);

    /* export certificate */
    size_t cert_pem_size;
    if (pemExportCertificate(cert_der_data, cert_der_size, NULL, &cert_pem_size) != NO_ERROR)
    {
        TRACE_ERROR("pemExportCertificate failed\r\n");
        return ERROR_FAILURE;
    }

    char_t *cert_pem_data = osAllocMem(cert_pem_size + 1);
    if (pemExportCertificate(cert_der_data, cert_der_size, cert_pem_data, &cert_pem_size) != NO_ERROR)
    {
        TRACE_ERROR("pemExportCertificate failed\r\n");
        return ERROR_FAILURE;
    }

    if (cert_file)
    {
        char *cert_file_full = osAllocMem(256);
        settings_resolve_dir(&cert_file_full, (char *)cert_file, get_settings()->internal.basedirfull);

        /* save the cert as pem */
        FsFile *file = fsOpenFile(cert_file_full, FS_FILE_MODE_WRITE);
        osFreeMem(cert_file_full);
        if (!file)
        {
            TRACE_ERROR("fsOpenFile failed\r\n");
            return ERROR_FAILURE;
        }
        if (!cert_der_format)
        {
            fsWriteFile(file, cert_pem_data, cert_pem_size);
        }
        else
        {
            fsWriteFile(file, cert_der_data, cert_der_size);
        }
        fsCloseFile(file);
    }

    if (priv_file)
    {
        char *priv_file_full = osAllocMem(256);
        settings_resolve_dir(&priv_file_full, (char *)priv_file, get_settings()->internal.basedirfull);

        /* save the private key */
        FsFile *file = fsOpenFile(priv_file_full, FS_FILE_MODE_WRITE);
        osFreeMem(priv_file_full);
        if (!file)
        {
            TRACE_ERROR("fsOpenFile failed\r\n");
            return ERROR_FAILURE;
        }
        if (priv_pem_data)
        {
            fsWriteFile(file, priv_pem_data, priv_pem_size);
        }
        else
        {
            fsWriteFile(file, priv_data, priv_size);
        }
        fsCloseFile(file);
    }

    osFreeMem(cert_der_data);
    osFreeMem(cert_pem_data);
    osFreeMem(priv_data);
    if (priv_pem_data) osFreeMem(priv_pem_data);

    if (!self_sign)
    {
        rsaFreePrivateKey(&issuer_priv);
    }

    return NO_ERROR;
}

error_t cert_generate_mac(const char *mac, const char *dest)
{
    if (!dest || osStrlen(mac) != 12)
    {
        return ERROR_FAILURE;
    }

    uint8_t serial[7];
    size_t serial_length = 7;
    char_t subj[32];

    serial[0] = 0;
    hex_string_to_bytes(mac, &serial[1]);
    cert_truncate_serial(serial, &serial_length);

    osSprintf(subj, "b'%s'", mac);

    char_t *client_file = custom_asprintf("%s/client.der", dest);
    char_t *private_file = custom_asprintf("%s/private.der", dest);

    if (cert_generate_signed(subj, serial, 7, CERT_RSA_SIZE, false, true, client_file, private_file) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_signed failed\r\n");
        return ERROR_FAILURE;
    }
    osFreeMem(client_file);
    osFreeMem(private_file);

    return NO_ERROR;
}

void cert_truncate_serial(uint8_t *serial, size_t *serial_length)
{
    /* skip leadin zeroes, except if the next byte is > 127 */
    while (*serial_length > 1)
    {
        /* only skip leading zeroes */
        if (serial[0])
        {
            break;
        }
        /* only allow leading zeroes if the next byte would have highest bit set */
        if (serial[1] & 0x80)
        {
            break;
        }
        (*serial_length)--;
        osMemmove(&serial[0], &serial[1], *serial_length);
    }
}

void cert_generate_serial(uint8_t *serial, size_t *serial_length)
{
    time_t cur_time = getCurrentUnixTime();

    /* write the current time in big endian format with leading zero */
    //*serial_length = 18 + 1;
    serial[0] = 0;
    STORE64BE(cur_time, &serial[1]);

    /* now truncate the 9 byte BE buffer to no leading zeroes, except the number would be interpreted as negative */
    cert_truncate_serial(serial, serial_length);
}

error_t convert_PEM_to_DER(const char *pem_data, const char *der_target_file)
{
    size_t pem_data_len = strlen(pem_data);

    // Call pemDecodeFile to get the DER data size
    size_t der_data_len = 0;
    PemHeader pem_header;
    size_t consumed;
    error_t error = pemDecodeFile(pem_data, pem_data_len, "CERTIFICATE", NULL, &der_data_len, &pem_header, &consumed);

    if (error != NO_ERROR)
    {
        TRACE_ERROR("Error: Unable to decode PEM data for size.\r\n");
        return error;
    }

    // Allocate memory for the DER data
    uint8_t *der_data = osAllocMem(der_data_len);
    if (!der_data)
    {
        TRACE_ERROR("Error: Memory allocation failed.\r\n");
        return ERROR_OUT_OF_MEMORY;
    }

    // Call pemDecodeFile again to get the DER data
    error = pemDecodeFile(pem_data, pem_data_len, "CERTIFICATE", der_data, &der_data_len, &pem_header, &consumed);

    if (error != NO_ERROR)
    {
        TRACE_ERROR("Error: Unable to decode PEM data.\r\n");
        osFreeMem(der_data);
        return error;
    }

    // Open the DER file for writing
    char *der_target_file_full = osAllocMem(256);
    settings_resolve_dir(&der_target_file_full, (char *)der_target_file, get_settings()->internal.basedirfull);
    FsFile *der_file = fsOpenFile(der_target_file_full, FS_FILE_MODE_WRITE);
    osFreeMem(der_target_file_full);
    if (!der_file)
    {
        TRACE_ERROR("Error opening DER file for writing.\r\n");
        osFreeMem(der_data);
        return ERROR_FILE_OPENING_FAILED;
    }

    // Write DER content to the file
    error = fsWriteFile(der_file, der_data, der_data_len);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Error writing DER data to file.\r\n");
        fsCloseFile(der_file);
        osFreeMem(der_data);
        return error;
    }

    // Close the file
    fsCloseFile(der_file);

    // Clean up
    osFreeMem(der_data);

    return NO_ERROR;
}

error_t cert_generate_default()
{
    const char *cacert = settings_get_string("core.server_cert.file.ca");
    const char *cacert_key = settings_get_string("core.server_cert.file.ca_key");
    uint8_t serial[14];
    size_t serial_length = 14;

    error_t error_ca = load_cert("internal.server.ca", "core.server_cert.file.ca", "core.server_cert.data.ca", 0);
    error_t error_ca_key = load_cert("internal.server.ca_key", "core.server_cert.file.ca_key", "core.server_cert.data.ca_key", 0);

    if (error_ca != NO_ERROR || error_ca_key != NO_ERROR)
    {
        cert_generate_serial(serial, &serial_length);

        TRACE_INFO("Generating CA certificate...\r\n");
        if (cert_generate_signed("TeddyCloud CA Root Cert.", serial, serial_length, CA_RSA_SIZE, true, false, cacert, cacert_key) != NO_ERROR)
        {
            TRACE_ERROR("cert_generate_signed failed\r\n");
            return ERROR_FAILURE;
        }
    }
    else
    {
        TRACE_INFO("CA certificates already there, skipping generation!\r\n");
    }

    /* reload certs to reload the CA cert again */
    settings_try_load_certs_id(0);

    /* generate ca.der */
    const char *cacert_data = settings_get_string("internal.server.ca");
    const char *cacert_der = settings_get_string("core.server_cert.file.ca_der");

    char *cacert_der_full = osAllocMem(256);
    settings_resolve_dir(&cacert_der_full, (char *)cacert_der, get_settings()->internal.basedirfull);
    if (convert_PEM_to_DER(cacert_data, cacert_der_full) != NO_ERROR)
    {
        TRACE_ERROR("ca.pem to ca.der conversion failed\r\n");
        free(cacert_der_full);
        return ERROR_FAILURE;
    }
    free(cacert_der_full);

    const char *server_cert = settings_get_string("core.server_cert.file.crt");
    const char *server_key = settings_get_string("core.server_cert.file.key");

    cert_generate_serial(serial, &serial_length);

    TRACE_INFO("Generating Server certificate...\r\n");
    if (cert_generate_signed("TeddyCloud Server", serial, serial_length, CERT_RSA_SIZE, false, false, server_cert, server_key) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_signed failed\r\n");
        return ERROR_FAILURE;
    }

    /* reload certs to reload the other certs */
    return settings_try_load_certs_id(0);
}

error_t x509ExportEcPrivateKey(const EcCurveInfo *curveInfo,
   const EcPrivateKey *privateKey, const EcPublicKey *publicKey,
   uint8_t *output, size_t *written)
{
   uint8_t temp_buf[512];
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   Asn1Tag tag;

   p = temp_buf;
   length = 0;

   //Format Version field (refer to RFC 5915, section 3)
   error = asn1WriteInt32(1, FALSE, p, &n);
   if(error) return error;
   length += n;
   p += n;

   //Write the EC private key d as an octet string
   error = mpiWriteRaw(&privateKey->d, p, curveInfo->pLen);
   if(error) return error;

   tag.constructed = FALSE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_OCTET_STRING;
   tag.length = curveInfo->pLen;
   tag.value = p;

   error = asn1WriteTag(&tag, FALSE, p, &n);
   if(error) return error;

   n = tag.totalLength;
   length += n;
   p += n;

   //The parameters field is optional but some parsers require it
   if(curveInfo->oid != NULL)
   {
      //Write the curve OID
      tag.constructed = FALSE;
      tag.objClass = ASN1_CLASS_UNIVERSAL;
      tag.objType = ASN1_TYPE_OBJECT_IDENTIFIER;
      tag.length = curveInfo->oidSize;
      tag.value = curveInfo->oid;

      error = asn1WriteTag(&tag, FALSE, p, &n);
      if(error) return error;

      n = tag.totalLength;

      //Wrap in a context-specific tag [0]
      tag.constructed = TRUE;
      tag.objClass = ASN1_CLASS_CONTEXT_SPECIFIC;
      tag.objType = 0;
      tag.length = n;
      tag.value = p;

      error = asn1WriteTag(&tag, FALSE, p, &n);
      if(error) return error;

      n = tag.totalLength;
      length += n;
      p += n;
   }


   //The public key is optional
   if(publicKey != NULL)
   {
      error = pkcs8FormatEcPublicKey(curveInfo, publicKey, p, &n);
      if(error) return error;
      length += n;
      p += n;
   }

   //Format ECPrivateKey field
   tag.constructed = TRUE;
   tag.objClass = ASN1_CLASS_UNIVERSAL;
   tag.objType = ASN1_TYPE_SEQUENCE;
   tag.length = length;
   tag.value = temp_buf;

   error = asn1WriteTag(&tag, FALSE, temp_buf, &n);
   if(error) return error;

   *written = tag.totalLength;
   if(output != NULL)
   {
      osMemcpy(output, temp_buf, tag.totalLength);
   }
   return NO_ERROR;
}

error_t cert_load_ca_ec(const char *ca_cert_setting, const char *ca_key_setting, X509CertInfo *cert, EcPrivateKey *cert_priv, uint8_t **server_ca_der_out)
{
    const char *server_ca = settings_get_string(ca_cert_setting);
    const char *server_key = settings_get_string(ca_key_setting);

    if (!server_ca || !server_key)
    {
        TRACE_ERROR("CA certificate or key setting not found\r\n");
        return ERROR_FAILURE;
    }

    size_t ca_size = 0;
    TRACE_INFO("Load CA certificate...\r\n");
    if (pemImportCertificate(server_ca, strlen(server_ca), NULL, &ca_size, NULL) != NO_ERROR)
    {
        TRACE_ERROR("pemImportCertificate failed\r\n");
        return ERROR_FAILURE;
    }

    uint8_t *server_ca_der = osAllocMem(ca_size);
    if (pemImportCertificate(server_ca, strlen(server_ca), server_ca_der, &ca_size, NULL) != NO_ERROR)
    {
        TRACE_ERROR("pemImportCertificate failed\r\n");
        osFreeMem(server_ca_der);
        return ERROR_FAILURE;
    }

    osMemset(cert, 0x00, sizeof(X509CertInfo));
    if (x509ParseCertificateEx(server_ca_der, ca_size, cert, true) != NO_ERROR)
    {
        TRACE_ERROR("x509ParseCertificateEx failed\r\n");
        osFreeMem(server_ca_der);
        return ERROR_FAILURE;
    }

    /* now export private key */
    osMemset(cert_priv, 0x00, sizeof(EcPrivateKey));
    ecInitPrivateKey(cert_priv);

    TRACE_INFO("Load CA key...\r\n");
    if (pemImportEcPrivateKey(server_key, osStrlen(server_key), NULL, cert_priv) != NO_ERROR)
    {
        TRACE_ERROR("pemImportEcPrivateKey failed\r\n");
        osFreeMem(server_ca_der);
        return ERROR_FAILURE;
    }

    if (server_ca_der_out) {
        *server_ca_der_out = server_ca_der;
    } else {
        osFreeMem(server_ca_der);
    }
    return NO_ERROR;
}

error_t cert_generate_signed_ec(
    const char *subject,
    const uint8_t *serial_number,
    int serial_number_size,
    bool self_sign,
    bool cert_der_format,
    const char *cert_file,
    const char *priv_file,
    const char *ca_cert_setting,
    const char *ca_key_setting,
    const char *dns_names[],
    size_t dns_names_count
) {
    /* load server CA certificate */
    X509CertInfo issuer_cert;
    EcPrivateKey issuer_priv;
    osMemset(&issuer_cert, 0, sizeof(issuer_cert));
    osMemset(&issuer_priv, 0, sizeof(issuer_priv));
    ecInitPrivateKey(&issuer_priv);

    uint8_t *server_ca_der = NULL;
    if (!self_sign)
    {
        if (cert_load_ca_ec(ca_cert_setting, ca_key_setting, &issuer_cert, &issuer_priv, &server_ca_der) != NO_ERROR)
        {
            TRACE_ERROR("cert_load_ca_ec failed\r\n");
            ecFreePrivateKey(&issuer_priv);
            return ERROR_FAILURE;
        }
    }

    /* generate EC key */
    EcPrivateKey cert_privkey;
    EcPublicKey cert_pubkey;
    ecInitPrivateKey(&cert_privkey);
    ecInitPublicKey(&cert_pubkey);
    size_t priv_size = 0;
    uint8_t *priv_data = NULL;

    EcDomainParameters params;
    ecInitDomainParameters(&params);
    if (ecLoadDomainParameters(&params, SECP384R1_CURVE) != NO_ERROR)
    {
        TRACE_ERROR("ecLoadDomainParameters failed\r\n");
        ecFreePrivateKey(&cert_privkey);
        ecFreePublicKey(&cert_pubkey);
        ecFreeDomainParameters(&params);
        if (!self_sign) {
            ecFreePrivateKey(&issuer_priv);
            if (server_ca_der) osFreeMem(server_ca_der);
        }
        return ERROR_FAILURE;
    }

    if (ecGenerateKeyPair(rand_get_algo(), rand_get_context(), &params, &cert_privkey, &cert_pubkey) != NO_ERROR)
    {
        TRACE_ERROR("ecGenerateKeyPair failed\r\n");
        ecFreePrivateKey(&cert_privkey);
        ecFreePublicKey(&cert_pubkey);
        ecFreeDomainParameters(&params);
        if (!self_sign) {
            ecFreePrivateKey(&issuer_priv);
            if (server_ca_der) osFreeMem(server_ca_der);
        }
        return ERROR_FAILURE;
    }

    // Export private key to DER format (SEC-1 ECPrivateKey)
    if (x509ExportEcPrivateKey(SECP384R1_CURVE, &cert_privkey, &cert_pubkey, NULL, &priv_size) != NO_ERROR)
    {
        TRACE_ERROR("x509ExportEcPrivateKey size check failed\r\n");
        ecFreePrivateKey(&cert_privkey);
        ecFreePublicKey(&cert_pubkey);
        ecFreeDomainParameters(&params);
        if (!self_sign) {
            ecFreePrivateKey(&issuer_priv);
            if (server_ca_der) osFreeMem(server_ca_der);
        }
        return ERROR_FAILURE;
    }

    priv_data = osAllocMem(priv_size);
    if (x509ExportEcPrivateKey(SECP384R1_CURVE, &cert_privkey, &cert_pubkey, priv_data, &priv_size) != NO_ERROR)
    {
        TRACE_ERROR("x509ExportEcPrivateKey failed\r\n");
        osFreeMem(priv_data);
        ecFreePrivateKey(&cert_privkey);
        ecFreePublicKey(&cert_pubkey);
        ecFreeDomainParameters(&params);
        if (!self_sign) {
            ecFreePrivateKey(&issuer_priv);
            if (server_ca_der) osFreeMem(server_ca_der);
        }
        return ERROR_FAILURE;
    }

    // Export private key to PEM format
    char_t *priv_pem_data = NULL;
    size_t priv_pem_size = 0;
    char_t temp_pem_buf[2048];
    size_t temp_pem_size = sizeof(temp_pem_buf);

    if (pemExportEcPrivateKey(SECP384R1_CURVE, &cert_privkey, &cert_pubkey, temp_pem_buf, &temp_pem_size) == NO_ERROR)
    {
        priv_pem_data = osAllocMem(temp_pem_size + 1);
        osMemcpy(priv_pem_data, temp_pem_buf, temp_pem_size);
        priv_pem_data[temp_pem_size] = '\0';
        priv_pem_size = temp_pem_size;
    }

    /* create and sign the certificate */
    X509CertRequestInfo cert_req;
    osMemset(&cert_req, 0x00, sizeof(cert_req));
    cert_req.version = X509_VERSION_1;
    cert_req.subject.name.value = subject;
    cert_req.subject.name.length = osStrlen(subject);

    cert_req.subject.commonName.value = self_sign ? "TeddyCloud Root CA" : (osStrstr(subject, "ici.tonie.cloud") ? "ici.tonie.cloud" : (osStrstr(subject, "tbs2.tonie.cloud") ? "tbs2.tonie.cloud" : subject));
    cert_req.subject.commonName.length = osStrlen(cert_req.subject.commonName.value);
    cert_req.subject.organizationName.value = "Team RevvoX"; //"tonies GmbH";
    cert_req.subject.organizationName.length = 11;
    cert_req.subject.countryName.value = "DE";
    cert_req.subject.countryName.length = 2;
    cert_req.subject.localityName.value = "Duesseldorf";
    cert_req.subject.localityName.length = 11;
    cert_req.subject.stateOrProvinceName.value = "North Rhine-Westphalia";
    cert_req.subject.stateOrProvinceName.length = 22;

    cert_req.subjectPublicKeyInfo.oid.value = EC_PUBLIC_KEY_OID;
    cert_req.subjectPublicKeyInfo.oid.length = sizeof(EC_PUBLIC_KEY_OID);
    cert_req.subjectPublicKeyInfo.ecParams.namedCurve.value = SECP384R1_OID;
    cert_req.subjectPublicKeyInfo.ecParams.namedCurve.length = sizeof(SECP384R1_OID);

    if (self_sign)
    {
        cert_req.attributes.extensionReq.basicConstraints.critical = true;
        cert_req.attributes.extensionReq.basicConstraints.cA = true;
        cert_req.attributes.extensionReq.basicConstraints.pathLenConstraint = -1;

        cert_req.attributes.extensionReq.keyUsage.critical = true;
        cert_req.attributes.extensionReq.keyUsage.bitmap = X509_KEY_USAGE_DIGITAL_SIGNATURE | X509_KEY_USAGE_KEY_CERT_SIGN | X509_KEY_USAGE_CRL_SIGN;
    }
    else
    {
        cert_req.attributes.extensionReq.basicConstraints.critical = true;
        cert_req.attributes.extensionReq.basicConstraints.cA = false;
        cert_req.attributes.extensionReq.basicConstraints.pathLenConstraint = -1;

        if (dns_names_count == 0)
        {
            cert_req.attributes.extensionReq.keyUsage.critical = false;
            cert_req.attributes.extensionReq.keyUsage.bitmap = X509_KEY_USAGE_DIGITAL_SIGNATURE | X509_KEY_USAGE_KEY_AGREEMENT;
            cert_req.attributes.extensionReq.extKeyUsage.critical = false;
            cert_req.attributes.extensionReq.extKeyUsage.bitmap = X509_EXT_KEY_USAGE_CLIENT_AUTH;
        }
        else
        {
            cert_req.attributes.extensionReq.keyUsage.critical = true;
            cert_req.attributes.extensionReq.keyUsage.bitmap = X509_KEY_USAGE_DIGITAL_SIGNATURE | X509_KEY_USAGE_KEY_AGREEMENT;
            cert_req.attributes.extensionReq.extKeyUsage.critical = false;
            cert_req.attributes.extensionReq.extKeyUsage.bitmap = X509_EXT_KEY_USAGE_SERVER_AUTH;

            if (dns_names_count > 0 && dns_names_count <= X509_MAX_SUBJECT_ALT_NAMES)
            {
                cert_req.attributes.extensionReq.subjectAltName.critical = false;
                cert_req.attributes.extensionReq.subjectAltName.numGeneralNames = dns_names_count;
                for (size_t i = 0; i < dns_names_count; i++)
                {
                    cert_req.attributes.extensionReq.subjectAltName.generalNames[i].type = X509_GENERAL_NAME_TYPE_DNS;
                    cert_req.attributes.extensionReq.subjectAltName.generalNames[i].value = dns_names[i];
                    cert_req.attributes.extensionReq.subjectAltName.generalNames[i].length = osStrlen(dns_names[i]);
                }
            }
        }
    }

    X509SerialNumber serial;
    osMemset(&serial, 0x00, sizeof(serial));
    serial.length = serial_number_size;
    serial.value = serial_number;

    X509Validity validity;
    osMemset(&validity, 0x00, sizeof(validity));

    if (self_sign)
    {
        validity.notBefore.year = 2025;
        validity.notBefore.month = 1;
        validity.notBefore.day = 1;
        validity.notBefore.hours = 0;
        validity.notBefore.minutes = 0;
        validity.notBefore.seconds = 0;

        validity.notAfter.year = 2075;
        validity.notAfter.month = 1;
        validity.notAfter.day = 1;
        validity.notAfter.hours = 0;
        validity.notAfter.minutes = 0;
        validity.notAfter.seconds = 0;
    }
    else
    {
        validity.notBefore.year = 2025;
        validity.notBefore.month = 5;
        validity.notBefore.day = 7;
        validity.notBefore.hours = 9;
        validity.notBefore.minutes = 10;
        validity.notBefore.seconds = 18;

        validity.notAfter.year = 2075;
        validity.notAfter.month = 5;
        validity.notAfter.day = 7;
        validity.notAfter.hours = 9;
        validity.notAfter.minutes = 10;
        validity.notAfter.seconds = 18;
    }

    X509SignAlgoId algo;
    osMemset(&algo, 0x00, sizeof(algo));
    algo.oid.value = ECDSA_WITH_SHA384_OID;
    algo.oid.length = sizeof(ECDSA_WITH_SHA384_OID);

    /* create certificate */
    uint8_t *cert_der_data = osAllocMem(8192);
    size_t cert_der_size = 0;
    error_t error = x509CreateCertificate(rand_get_algo(), rand_get_context(), &cert_req, &cert_pubkey, self_sign ? NULL : &issuer_cert, &serial, &validity, &algo, self_sign ? &cert_privkey : &issuer_priv, cert_der_data, &cert_der_size);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("x509CreateCertificate failed: %s\r\n", error2text(error));
        osFreeMem(cert_der_data);
        osFreeMem(priv_data);
        if (priv_pem_data) osFreeMem(priv_pem_data);
        ecFreePublicKey(&cert_pubkey);
        ecFreePrivateKey(&cert_privkey);
        ecFreeDomainParameters(&params);
        if (!self_sign) {
            ecFreePrivateKey(&issuer_priv);
            if (server_ca_der) osFreeMem(server_ca_der);
        }
        return ERROR_FAILURE;
    }

    ecFreePublicKey(&cert_pubkey);
    ecFreePrivateKey(&cert_privkey);
    ecFreeDomainParameters(&params);
    if (!self_sign) {
        ecFreePrivateKey(&issuer_priv);
        if (server_ca_der) osFreeMem(server_ca_der);
    }

    /* export certificate to PEM */
    size_t cert_pem_size = 0;
    if (pemExportCertificate(cert_der_data, cert_der_size, NULL, &cert_pem_size) != NO_ERROR)
    {
        TRACE_ERROR("pemExportCertificate failed\r\n");
        osFreeMem(cert_der_data);
        osFreeMem(priv_data);
        if (priv_pem_data) osFreeMem(priv_pem_data);
        return ERROR_FAILURE;
    }

    char_t *cert_pem_data = osAllocMem(cert_pem_size + 1);
    if (pemExportCertificate(cert_der_data, cert_der_size, cert_pem_data, &cert_pem_size) != NO_ERROR)
    {
        TRACE_ERROR("pemExportCertificate failed\r\n");
        osFreeMem(cert_der_data);
        osFreeMem(priv_data);
        if (priv_pem_data) osFreeMem(priv_pem_data);
        osFreeMem(cert_pem_data);
        return ERROR_FAILURE;
    }

    if (cert_file)
    {
        char *cert_file_full = osAllocMem(256);
        settings_resolve_dir(&cert_file_full, (char *)cert_file, get_settings()->internal.basedirfull);

        FsFile *file = fsOpenFile(cert_file_full, FS_FILE_MODE_WRITE);
        osFreeMem(cert_file_full);
        if (!file)
        {
            TRACE_ERROR("fsOpenFile failed\r\n");
            osFreeMem(cert_der_data);
            osFreeMem(priv_data);
            if (priv_pem_data) osFreeMem(priv_pem_data);
            osFreeMem(cert_pem_data);
            return ERROR_FAILURE;
        }
        if (!cert_der_format)
        {
            fsWriteFile(file, cert_pem_data, cert_pem_size);
        }
        else
        {
            fsWriteFile(file, cert_der_data, cert_der_size);
        }
        fsCloseFile(file);
    }

    if (priv_file)
    {
        char *priv_file_full = osAllocMem(256);
        settings_resolve_dir(&priv_file_full, (char *)priv_file, get_settings()->internal.basedirfull);

        bool priv_pem_format = false;
        size_t priv_file_len = osStrlen(priv_file);
        if (priv_file_len > 4 && (!osStrcasecmp(&priv_file[priv_file_len - 4], ".pem") || !osStrcasecmp(&priv_file[priv_file_len - 4], ".key")))
        {
            priv_pem_format = true;
        }

        FsFile *file = fsOpenFile(priv_file_full, FS_FILE_MODE_WRITE);
        osFreeMem(priv_file_full);
        if (!file)
        {
            TRACE_ERROR("fsOpenFile failed\r\n");
            osFreeMem(cert_der_data);
            osFreeMem(priv_data);
            if (priv_pem_data) osFreeMem(priv_pem_data);
            osFreeMem(cert_pem_data);
            return ERROR_FAILURE;
        }

        if (priv_pem_format)
        {
            if (priv_pem_data)
            {
                fsWriteFile(file, priv_pem_data, priv_pem_size);
            }
            else
            {
                TRACE_ERROR("No PEM private key data available\r\n");
            }
        }
        else
        {
            fsWriteFile(file, priv_data, priv_size);
        }
        fsCloseFile(file);
    }

    osFreeMem(cert_der_data);
    osFreeMem(priv_data);
    if (priv_pem_data) osFreeMem(priv_pem_data);
    osFreeMem(cert_pem_data);

    return NO_ERROR;
}

error_t cert_generate_default_tb2()
{
    const char *cacert = settings_get_string("core.server_cert_tb2.file.ca");
    const char *cacert_key = settings_get_string("core.server_cert_tb2.file.ca_key");
    uint8_t serial[14];
    size_t serial_length = 14;

    error_t error_ca = load_cert("internal.server_tb2.ca", "core.server_cert_tb2.file.ca", "core.server_cert_tb2.data.ca", 0);
    error_t error_ca_key = load_cert("internal.server_tb2.ca_key", "core.server_cert_tb2.file.ca_key", "core.server_cert_tb2.data.ca_key", 0);

    if (error_ca != NO_ERROR || error_ca_key != NO_ERROR)
    {
        cert_generate_serial(serial, &serial_length);

        TRACE_INFO("Generating TB2 CA certificate...\r\n");
        if (cert_generate_signed_ec("TeddyCloud Root CA", serial, serial_length, true, false, cacert, cacert_key, NULL, NULL, NULL, 0) != NO_ERROR)
        {
            TRACE_ERROR("cert_generate_signed_ec failed for CA\r\n");
            return ERROR_FAILURE;
        }
    }
    else
    {
        TRACE_INFO("TB2 CA certificates already there, skipping generation!\r\n");
    }

    /* reload certs to reload the CA cert again */
    settings_try_load_certs_id(0);

    /* generate ca.der */
    const char *cacert_data = settings_get_string("internal.server_tb2.ca");
    const char *cacert_der = settings_get_string("core.server_cert_tb2.file.ca_der");

    char *cacert_der_full = osAllocMem(256);
    settings_resolve_dir(&cacert_der_full, (char *)cacert_der, get_settings()->internal.basedirfull);
    if (convert_PEM_to_DER(cacert_data, cacert_der_full) != NO_ERROR)
    {
        TRACE_ERROR("TB2 ca.pem to ca.der conversion failed\r\n");
        osFreeMem(cacert_der_full);
        return ERROR_FAILURE;
    }
    osFreeMem(cacert_der_full);

    const char *server_cert = settings_get_string("core.server_cert_tb2.file.crt");
    const char *server_key = settings_get_string("core.server_cert_tb2.file.key");

    cert_generate_serial(serial, &serial_length);

    TRACE_INFO("Generating TB2 Server certificate (tbs2.tonie.cloud)...\r\n");
    const char *server_dns_names[] = { "tbs2.tonie.cloud" };
    if (cert_generate_signed_ec("tbs2.tonie.cloud", serial, serial_length, false, false, server_cert, server_key, "internal.server_tb2.ca", "internal.server_tb2.ca_key", server_dns_names, 1) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_signed_ec failed for Server\r\n");
        return ERROR_FAILURE;
    }

    const char *mqtt_cert = settings_get_string("mqtt_server.cert.crt");
    const char *mqtt_key = settings_get_string("mqtt_server.cert.key");

    cert_generate_serial(serial, &serial_length);

    TRACE_INFO("Generating TB2 MQTT certificate (ici.tonie.cloud)...\r\n");
    const char *mqtt_dns_names[] = { "ici.tonie.cloud", "ici.dev.tonie.cloud", "ici.stage.tonie.cloud" };
    if (cert_generate_signed_ec("ici.tonie.cloud", serial, serial_length, false, false, mqtt_cert, mqtt_key, "internal.server_tb2.ca", "internal.server_tb2.ca_key", mqtt_dns_names, 3) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_signed_ec failed for MQTT Server\r\n");
        return ERROR_FAILURE;
    }

    /* reload certs to reload the other certs */
    return settings_try_load_certs_id(0);
}

error_t cert_generate_mac_tb2(const char *mac, const char *dest, bool add_to_settings)
{
    if (!mac || osStrlen(mac) != 12)
    {
        return ERROR_FAILURE;
    }

    char mac_upper[13];
    osStrncpy(mac_upper, mac, 13);
    mac_upper[12] = '\0';
    osStringToUpper(mac_upper);

    char mac_lower[13];
    osStrncpy(mac_lower, mac, 13);
    mac_lower[12] = '\0';
    osStringToLower(mac_lower);

    char *actual_dest = NULL;
    if (!dest) {
        char *certdir = get_settings()->internal.certdirfull;
        if (!certdir) certdir = "certs/client";
        actual_dest = custom_asprintf("%s/%s", certdir, mac_lower);
    } else {
        actual_dest = custom_asprintf("%s", dest);
    }

    char_t *client_der_file = custom_asprintf("%s/client.fake.der", actual_dest);
    char_t *private_der_file = custom_asprintf("%s/private.fake.der", actual_dest);
    char_t *ca_der_file = custom_asprintf("%s/ca.fake.der", actual_dest);

    if (fsFileExists(client_der_file) && fsFileExists(private_der_file) && fsFileExists(ca_der_file))
    {
        TRACE_INFO("Fake TB2 client certificates already exist for MAC %s in %s, skipping generation.\r\n", mac_upper, actual_dest);
    }
    else
    {
        if (!fsDirExists(actual_dest)) {
            fsCreateDirEx(actual_dest, true);
        }

        uint8_t serial[7];
        size_t serial_length = 7;
        char_t subj[32];

        serial[0] = 0;
        hex_string_to_bytes(mac_upper, &serial[1]);
        cert_truncate_serial(serial, &serial_length);

        osSprintf(subj, "%s", mac_upper);

        if (cert_generate_signed_ec(subj, serial, 7, false, true, client_der_file, private_der_file, "internal.server_tb2.ca", "internal.server_tb2.ca_key", NULL, 0) != NO_ERROR)
        {
            TRACE_ERROR("cert_generate_signed_ec (DER) failed for client cert\r\n");
            osFreeMem(client_der_file);
            osFreeMem(private_der_file);
            osFreeMem(ca_der_file);
            osFreeMem(actual_dest);
            return ERROR_FAILURE;
        }

        /* Copy the TB2 ca.der into the dir as ca.fake.der */
        char *server_ca_der = osAllocMem(256);
        settings_resolve_dir(&server_ca_der, (char*)settings_get_string("core.server_cert_tb2.file.ca_der"), get_settings()->internal.basedirfull);
        
        if (fsCopyFile(server_ca_der, ca_der_file, true) != NO_ERROR) {
            TRACE_ERROR("Failed to copy TB2 ca.der to %s\r\n", ca_der_file);
        }
        osFreeMem(server_ca_der);

        TRACE_INFO("Generated fake TB2 client certificates for MAC %s in %s\r\n", mac_upper, actual_dest);
    }

    /* Update the overlay for the MAC if appropriate */
    if (add_to_settings)
    {
        settings_t *overlay_settings = get_settings_cn(mac_upper);
        if (overlay_settings)
        {
            uint8_t overlayId = overlay_settings->internal.overlayNumber;
            settings_set_unsigned_id("toniebox.boxGeneration", 2, overlayId);
            settings_set_string_id("core.client_cert_fake.file.ca", ca_der_file, overlayId);
            settings_set_string_id("core.client_cert_fake.file.crt", client_der_file, overlayId);
            settings_set_string_id("core.client_cert_fake.file.key", private_der_file, overlayId);
            settings_save();
            TRACE_INFO("Added configuration overlay for %s\r\n", mac_upper);
        }
    }

    osFreeMem(ca_der_file);
    osFreeMem(client_der_file);
    osFreeMem(private_der_file);
    osFreeMem(actual_dest);

    return NO_ERROR;
}

