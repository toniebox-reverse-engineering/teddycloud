

#include "debug.h"
#include "fs_port.h"
#include "rsa.h"
#include "yarrow.h"
#include "pem_import.h"
#include "pem_export.h"
#include "x509_cert_parse.h"
#include "x509_cert_create.h"
#include "x509_key_format.h"

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

int cert_generate(const char *mac, const char *dest)
{
    /*********************************************/
    /*         load server CA certificate        */
    /*********************************************/
    const char *server_ca = settings_get_string("internal.server.ca");
    const char *server_key = settings_get_string("internal.server.ca_key");

    size_t server_ca_der_size = 0;
    TRACE_INFO("Load CA certificate...\r\n");
    if (pemImportCertificate(server_ca, strlen(server_ca), NULL, &server_ca_der_size, NULL) != NO_ERROR)
    {
        TRACE_ERROR("pemImportCertificate failed\r\n");
        return -1;
    }

    uint8_t *server_ca_der = osAllocMem(server_ca_der_size);
    if (pemImportCertificate(server_ca, strlen(server_ca), server_ca_der, &server_ca_der_size, NULL) != NO_ERROR)
    {
        TRACE_ERROR("pemImportCertificate failed\r\n");
        return -1;
    }

    X509CertInfo issuer_certinfo;
    osMemset(&issuer_certinfo, 0x00, sizeof(issuer_certinfo));
    if (x509ParseCertificateEx(server_ca_der, server_ca_der_size, &issuer_certinfo, true) != NO_ERROR)
    {
        TRACE_ERROR("x509ParseCertificateEx failed\r\n");
        return -1;
    }

    RsaPrivateKey server_ca_priv;
    osMemset(&server_ca_priv, 0x00, sizeof(server_ca_priv));

    TRACE_INFO("Load CA key...\r\n");
    if (pemImportRsaPrivateKey(server_key, osStrlen(server_key), NULL, &server_ca_priv) != NO_ERROR)
    {
        TRACE_ERROR("pemImportRsaPrivateKey failed\r\n");
        return -1;
    }

    /*********************************************/
    /* now generate a RSA key for the new client */
    /*********************************************/
    TRACE_INFO("Generating RSA Key...\r\n");
    RsaPrivateKey cert_privkey;
    RsaPublicKey cert_pubkey;
    osMemset(&cert_privkey, 0x00, sizeof(cert_privkey));
    osMemset(&cert_pubkey, 0x00, sizeof(cert_pubkey));
    if (rsaGenerateKeyPair(YARROW_PRNG_ALGO, &yarrowContext, 4096, 65537, &cert_privkey, &cert_pubkey) != NO_ERROR)
    {
        TRACE_ERROR("rsaGenerateKeyPair failed\r\n");
        return -1;
    }

    size_t privateKey_der_size = 0;
    if (x509ExportRsaPrivateKey(&cert_privkey, NULL, &privateKey_der_size) != NO_ERROR)
    {
        TRACE_ERROR("x509ExportRsaPrivateKey failed\r\n");
        return -1;
    }
    uint8_t *der_data = osAllocMem(privateKey_der_size);
    if (x509ExportRsaPrivateKey(&cert_privkey, der_data, &privateKey_der_size) != NO_ERROR)
    {
        TRACE_ERROR("x509ExportRsaPrivateKey failed\r\n");
        return -1;
    }

    /* create and sign the certificate */
    char_t subj[32];
    osSprintf(subj, "b'%s'", mac);

    X509CertRequestInfo cert_req;
    osMemset(&cert_req, 0x00, sizeof(cert_req));
    cert_req.version = X509_VERSION_1;
    cert_req.subject.commonName.value = subj;
    cert_req.subject.commonName.length = osStrlen(subj);
    cert_req.subjectPublicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
    cert_req.subjectPublicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

    cert_req.subjectPublicKeyInfo.rsaPublicKey.e.length = mpiGetByteLength(&cert_pubkey.e);
    cert_req.subjectPublicKeyInfo.rsaPublicKey.n.length = mpiGetByteLength(&cert_pubkey.n);
    uint8_t *rsa_e_buf = osAllocMem(cert_req.subjectPublicKeyInfo.rsaPublicKey.e.length);
    uint8_t *rsa_n_buf = osAllocMem(cert_req.subjectPublicKeyInfo.rsaPublicKey.n.length);
    cert_req.subjectPublicKeyInfo.rsaPublicKey.e.value = rsa_e_buf;
    cert_req.subjectPublicKeyInfo.rsaPublicKey.n.value = rsa_n_buf;
    mpiExport(&cert_pubkey.e, rsa_e_buf, cert_req.subjectPublicKeyInfo.rsaPublicKey.e.length, MPI_FORMAT_BIG_ENDIAN);
    mpiExport(&cert_pubkey.n, rsa_n_buf, cert_req.subjectPublicKeyInfo.rsaPublicKey.n.length, MPI_FORMAT_BIG_ENDIAN);

    uint8_t ser[32];
    ser[0] = 0;
    hex_string_to_bytes(mac, &ser[1]);

    X509SerialNumber serial;
    osMemset(&serial, 0x00, sizeof(serial));
    serial.length = 7;
    serial.value = ser;

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

    uint8_t *cert_der = osAllocMem(8192);
    size_t cert_der_size = 0;
    if (x509CreateCertificate(YARROW_PRNG_ALGO, &yarrowContext, &cert_req, NULL, &issuer_certinfo, &serial, &validity, &algo, &server_ca_priv, cert_der, &cert_der_size) != NO_ERROR)
    {
        TRACE_ERROR("x509CreateCertificate failed\r\n");
        return -1;
    }

    size_t cert_pem_size;
    if (pemExportCertificate(cert_der, cert_der_size, NULL, &cert_pem_size) != NO_ERROR)
    {
        TRACE_ERROR("pemExportCertificate failed\r\n");
        return -1;
    }

    char_t *cert_pem = osAllocMem(cert_pem_size + 1);
    if (pemExportCertificate(cert_der, cert_der_size, cert_pem, &cert_pem_size) != NO_ERROR)
    {
        TRACE_ERROR("pemExportCertificate failed\r\n");
        return -1;
    }
    cert_pem[cert_pem_size] = 0;

    /* save the cert as pem */
    {
        char_t *path = osAllocMem(osStrlen(dest) + 32);
        osSprintf(path, "%s/client.pem", dest);
        FsFile *file = fsOpenFile(path, FS_FILE_MODE_WRITE);
        if (!file)
        {
            osFreeMem(path);
            TRACE_ERROR("fsOpenFile failed\r\n");
            return -1;
        }
        fsWriteFile(file, cert_pem, cert_pem_size);
        fsCloseFile(file);
        osFreeMem(path);
    }

    /* save the cert as der */
    {
        char_t *path = osAllocMem(osStrlen(dest) + 32);
        osSprintf(path, "%s/client.der", dest);
        FsFile *file = fsOpenFile(path, FS_FILE_MODE_WRITE);
        if (!file)
        {
            osFreeMem(path);
            TRACE_ERROR("fsOpenFile failed\r\n");
            return -1;
        }
        fsWriteFile(file, cert_der, cert_der_size);
        fsCloseFile(file);
        osFreeMem(path);
    }

    /* save the private key */
    {
        char_t *path = osAllocMem(osStrlen(dest) + 32);
        osSprintf(path, "%s/private.der", dest);
        FsFile *file = fsOpenFile(path, FS_FILE_MODE_WRITE);
        if (!file)
        {
            osFreeMem(path);
            TRACE_ERROR("fsOpenFile failed\r\n");
            return -1;
        }
        fsWriteFile(file, der_data, privateKey_der_size);
        fsCloseFile(file);
        osFreeMem(path);
    }

    rsaFreePublicKey(&cert_pubkey);
    rsaFreePrivateKey(&cert_privkey);

    osFreeMem(server_ca_der);
    osFreeMem(cert_der);
    osFreeMem(rsa_n_buf);
    osFreeMem(rsa_e_buf);
    osFreeMem(der_data);
    osFreeMem(cert_pem);

    return 0;
}
