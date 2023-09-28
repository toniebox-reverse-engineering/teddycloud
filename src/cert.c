

#include "debug.h"
#include "error.h"
#include "fs_port.h"
#include "rsa.h"
#include "yarrow.h"
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

    if (rsaGenerateKeyPair(YARROW_PRNG_ALGO, &yarrowContext, size, 65537, cert_privkey, cert_pubkey) != NO_ERROR)
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

    cert_req.subjectPublicKeyInfo.rsaPublicKey.e.length = mpiGetByteLength(&cert_pubkey.e);
    cert_req.subjectPublicKeyInfo.rsaPublicKey.n.length = mpiGetByteLength(&cert_pubkey.n);
    uint8_t *rsa_e_buf = osAllocMem(cert_req.subjectPublicKeyInfo.rsaPublicKey.e.length);
    uint8_t *rsa_n_buf = osAllocMem(cert_req.subjectPublicKeyInfo.rsaPublicKey.n.length);
    cert_req.subjectPublicKeyInfo.rsaPublicKey.e.value = rsa_e_buf;
    cert_req.subjectPublicKeyInfo.rsaPublicKey.n.value = rsa_n_buf;
    mpiExport(&cert_pubkey.e, rsa_e_buf, cert_req.subjectPublicKeyInfo.rsaPublicKey.e.length, MPI_FORMAT_BIG_ENDIAN);
    mpiExport(&cert_pubkey.n, rsa_n_buf, cert_req.subjectPublicKeyInfo.rsaPublicKey.n.length, MPI_FORMAT_BIG_ENDIAN);

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
    error_t error = x509CreateCertificate(YARROW_PRNG_ALGO, &yarrowContext, &cert_req, NULL, self_sign ? NULL : &issuer_cert, &serial, &validity, &algo, self_sign ? &cert_privkey : &issuer_priv, cert_der_data, &cert_der_size);
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
    osFreeMem(rsa_n_buf);
    osFreeMem(rsa_e_buf);
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

    uint8_t ser[32];
    char_t subj[32];

    ser[0] = 0;
    ser[1] = 0;
    hex_string_to_bytes(mac, &ser[2]);

    osSprintf(subj, "b'%s'", mac);

    char_t *client_file = custom_asprintf("%s/client.der", dest);
    char_t *private_file = custom_asprintf("%s/private.der", dest);

    if (cert_generate_signed(subj, ser, 7, false, true, client_file, private_file) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_signed failed\r\n");
        return ERROR_FAILURE;
    }
    osFreeMem(client_file);
    osFreeMem(private_file);

    return NO_ERROR;
}

error_t cert_generate_certs()
{
    const char *cacert = settings_get_string("core.server_cert.file.ca");
    const char *cacert_key = settings_get_string("core.server_cert.file.ca_key");
    uint8_t serial;

    /* ToDo: create a proper ASN.1 compatible serial with no leading zeroes */
    serial = rand();

    TRACE_INFO("Generating CA certificate...\r\n");
    if (cert_generate_signed("TeddyCloud CA Root Certificate", &serial, 1, true, false, cacert, cacert_key) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_signed failed\r\n");
        return ERROR_FAILURE;
    }

    /* reload certs to reload the CA cert again */
    settings_load_all_certs();

    const char *server_cert = settings_get_string("core.server_cert.file.crt");
    const char *server_key = settings_get_string("core.server_cert.file.key");

    serial = rand();

    TRACE_INFO("Generating Server certificate...\r\n");
    if (cert_generate_signed("TeddyCloud Server", &serial, 1, false, false, server_cert, server_key) != NO_ERROR)
    {
        TRACE_ERROR("cert_generate_signed failed\r\n");
        return ERROR_FAILURE;
    }

    return NO_ERROR;
}
