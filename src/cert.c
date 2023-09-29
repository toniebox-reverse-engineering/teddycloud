

#include "debug.h"
#include "error.h"
#include "fs_port.h"
#include "rsa.h"
#include "rand.h"
#include "pem_import.h"
#include "pem_export.h"
#include "x509_cert_parse.h"
#include "x509_cert_create.h"
#include "x509_key_format.h"
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
    TRACE_INFO("Generating RSA Key... (slow!)\r\n");

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

error_t cert_generate_signed(const char *subject, const uint8_t *serial_number, int serial_number_size, bool self_sign, bool cert_der_format, const char *cert_file, const char *priv_file)
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

    if (cert_generate_rsa(CERT_RSA_SIZE, &cert_privkey, &cert_pubkey) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_rsa failed\r\n");
        return ERROR_FAILURE;
    }
    if (cert_get_rsa_priv(&cert_privkey, &priv_data, &priv_size) != NO_ERROR)
    {
        TRACE_ERROR("cert_get_rsa_priv failed\r\n");
        return ERROR_FAILURE;
    }

    /* create and sign the certificate */
    X509CertRequestInfo cert_req;
    osMemset(&cert_req, 0x00, sizeof(cert_req));
    cert_req.version = X509_VERSION_1;
    cert_req.subject.name.value = subject;
    cert_req.subject.name.length = osStrlen(subject);
    cert_req.subject.commonName.value = subject;
    cert_req.subject.commonName.length = osStrlen(subject);
    cert_req.subjectPublicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
    cert_req.subjectPublicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

    cert_req.attributes.extensionReq.keyUsage.bitmap |= X509_KEY_USAGE_DIGITAL_SIGNATURE;
    cert_req.attributes.extensionReq.keyUsage.bitmap |= X509_KEY_USAGE_NON_REPUDIATION;
    cert_req.attributes.extensionReq.extKeyUsage.bitmap |= X509_EXT_KEY_USAGE_SERVER_AUTH;
    cert_req.attributes.extensionReq.extKeyUsage.bitmap |= X509_EXT_KEY_USAGE_CLIENT_AUTH;

    if (self_sign)
    {
        cert_req.attributes.extensionReq.basicConstraints.cA = true;
        cert_req.attributes.extensionReq.keyUsage.bitmap |= X509_KEY_USAGE_KEY_CERT_SIGN;
    }

    X509SerialNumber serial;
    osMemset(&serial, 0x00, sizeof(serial));
    serial.length = serial_number_size;
    serial.value = serial_number;

    X509Validity validity;
    osMemset(&validity, 0x00, sizeof(validity));
    getCurrentDate(&validity.notBefore);
    getCurrentDate(&validity.notAfter);
    validity.notBefore.year -= 20;
    validity.notAfter.year += 20;

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
        TRACE_ERROR("x509CreateCertificate failed: %d\r\n", error);
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
        /* save the cert as pem */
        FsFile *file = fsOpenFile(cert_file, FS_FILE_MODE_WRITE);
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
        /* save the private key */
        FsFile *file = fsOpenFile(priv_file, FS_FILE_MODE_WRITE);
        if (!file)
        {
            TRACE_ERROR("fsOpenFile failed\r\n");
            return ERROR_FAILURE;
        }
        fsWriteFile(file, priv_data, priv_size);
        fsCloseFile(file);
    }

    osFreeMem(cert_der_data);
    osFreeMem(cert_pem_data);
    osFreeMem(priv_data);

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

    if (cert_generate_signed(subj, serial, 7, false, true, client_file, private_file) != NO_ERROR)
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
    *serial_length = 9;
    serial[0] = 0;
    STORE64BE(cur_time, &serial[1]);

    /* now truncate the 9 byte BE buffer to no leading zeroes, except the number would be interpreted as negative */
    cert_truncate_serial(serial, serial_length);
}

error_t cert_generate_default()
{
    const char *cacert = settings_get_string("core.server_cert.file.ca");
    const char *cacert_key = settings_get_string("core.server_cert.file.ca_key");
    uint8_t serial[9];
    size_t serial_length;

    /* create a proper ASN.1 compatible serial with no leading zeroes */
    cert_generate_serial(serial, &serial_length);

    TRACE_INFO("Generating CA certificate...\r\n");
    if (cert_generate_signed("TeddyCloud CA Root Certificate", serial, serial_length, true, false, cacert, cacert_key) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_signed failed\r\n");
        return ERROR_FAILURE;
    }

    /* reload certs to reload the CA cert again */
    settings_try_load_certs_id(0);

    const char *server_cert = settings_get_string("core.server_cert.file.crt");
    const char *server_key = settings_get_string("core.server_cert.file.key");

    cert_generate_serial(serial, &serial_length);

    TRACE_INFO("Generating Server certificate...\r\n");
    if (cert_generate_signed("TeddyCloud Server", serial, serial_length, false, false, server_cert, server_key) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_signed failed\r\n");
        return ERROR_FAILURE;
    }

    /* reload certs to reload the other certs */
    return settings_try_load_certs_id(0);
}
