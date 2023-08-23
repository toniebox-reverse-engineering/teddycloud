
// Platform-specific dependencies
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifdef WIN32
#else
#include <unistd.h>
#endif

#include "error.h"
#include "debug.h"
#include "cJSON.h"
#include "esp32.h"

#include "version.h"

#include "tls_adapter.h"
#include "cloud_request.h"

#include "settings.h"
#include "esp32.h"
#include "mqtt.h"

#include "x509_cert_create.h"
#include "rsa.h"
#include "yarrow.h"
#include "pem_import.h"
#include "pem_export.h"
#include "x509_cert_parse.h"
#include "x509_key_format.h"

void platform_init(void);
void platform_deinit(void);
void server_init(void);
#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTPS_PORT 443

typedef enum
{
    PROT_HTTP,
    PROT_HTTPS
} Protocol;

void get_directory_path(const char *filepath, char *dirpath, int maxLen)
{
    // Find the last occurrence of '/' or '\' in the file path
    int lastSlash = -1;
    for (int i = 0; filepath[i] != '\0'; i++)
    {
        if (filepath[i] == '/' || filepath[i] == '\\')
        {
            lastSlash = i;
        }
    }

    if (lastSlash == -1)
    {
        // No directory part found, use an empty string for the directory path
        dirpath[0] = '\0';
    }
    else
    {
        // Copy the characters before the last slash to the directory path buffer
        snprintf(dirpath, maxLen, "%.*s", lastSlash, filepath);
    }
}

bool parse_url(const char *url, char **hostname, uint16_t *port, char **uri, Protocol *protocol)
{
    if (strstr(url, "http://") == url)
    {
        *protocol = PROT_HTTP;
        url += strlen("http://");
    }
    else if (strstr(url, "https://") == url)
    {
        *protocol = PROT_HTTPS;
        url += strlen("https://");
    }
    else
    {
        TRACE_ERROR("Unknown protocol\r\n");
        return false;
    }

    char *port_start = strchr(url, ':');
    char *path_start = strchr(url, '/');
    if (path_start == NULL)
    {
        TRACE_ERROR("URL must contain a path\r\n");
        return false;
    }

    if (port_start != NULL)
    {
        // Port is specified
        int hostname_length = port_start - url;
        *hostname = (char *)malloc(hostname_length + 1);
        strncpy(*hostname, url, hostname_length);
        (*hostname)[hostname_length] = '\0';

        *port = (uint16_t)atoi(port_start + 1);
    }
    else
    {
        // Port is not specified, use default port based on protocol
        int hostname_length = path_start - url;
        *hostname = (char *)malloc(hostname_length + 1);
        strncpy(*hostname, url, hostname_length);
        (*hostname)[hostname_length] = '\0';

        *port = (*protocol == PROT_HTTP) ? DEFAULT_HTTP_PORT : DEFAULT_HTTPS_PORT;
    }

    *uri = strdup(path_start);

    return true;
}

int hex2int(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return -1;
}

void hex_string_to_bytes(const char *hex_string, uint8_t *output)
{
    while (*hex_string)
    {
        char hi = hex2int(*hex_string++);
        char lo = hex2int(*hex_string++);
        *output++ = (hi << 4) | lo;
    }
}

int_t main(int argc, char *argv[])
{
    TRACE_PRINTF(BUILD_FULL_NAME_LONG "\r\n\r\n");

    error_t error = 0;

    char cwd[256];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        get_directory_path(argv[0], cwd, sizeof(cwd));
    }

    /* platform specific init */
    settings_init(cwd);
    platform_init();

    cJSON_Hooks hooks = {.malloc_fn = osAllocMem, .free_fn = osFreeMem};
    cJSON_InitHooks(&hooks);

    /* load certificates and TLS RNG */
    if (tls_adapter_init() != NO_ERROR)
    {
        TRACE_ERROR("tls_adapter_init() failed\r\n");
        return -1;
    }

    if (argc > 1)
    {
        const char *type = argv[1];

        if (!strcasecmp(type, "GENERIC"))
        {
            TRACE_WARNING("**********************************\r\n");
            TRACE_WARNING("***       Generic URL test     ***\r\n");
            TRACE_WARNING("**********************************\r\n");

            char *request = NULL;
            uint8_t *hash = NULL;

            if (argc < 3)
            {
                TRACE_ERROR("Usage: %s GENERIC <url> [hash]\r\n", argv[0]);
                return -1;
            }
            if (argc > 2)
            {
                request = argv[2];
                TRACE_WARNING("Request URL: %s\r\n", request);
            }
            if (argc > 3)
            {
                hash = (uint8_t *)argv[3];
                TRACE_WARNING("Hash: %s\r\n", hash);
            }

            char *hostname;
            uint16_t port;
            char *uri;
            Protocol protocol;

            if (!parse_url(request, &hostname, &port, &uri, &protocol))
            {
                return ERROR_FAILURE;
            }

            TRACE_WARNING("Hostname: %s\n", hostname);
            TRACE_WARNING("Port: %u\n", port);
            TRACE_WARNING("URI: %s\n", uri);
            TRACE_WARNING("Protocol: %s\n", protocol == PROT_HTTP ? "HTTP" : "HTTPS");

            settings_set_bool("cloud.enabled", true);

            error = cloud_request(hostname, port, protocol == PROT_HTTPS, uri, "", "GET", NULL, 0, hash, NULL);

            free(hostname);
            free(uri);
        }
        else if (!strcasecmp(type, "CLOUD"))
        {
            TRACE_WARNING("**********************************\r\n");
            TRACE_WARNING("***       Cloud API test       ***\r\n");
            TRACE_WARNING("**********************************\r\n");

            char *request = NULL;
            uint8_t *hash = NULL;

            if (argc < 3)
            {
                TRACE_ERROR("Usage: %s CLOUD <request> [hash]\r\n", argv[0]);
                return -1;
            }
            if (argc > 2)
            {
                request = argv[2];
                TRACE_WARNING("Request URI: %s\r\n", request);
            }
            if (argc > 3)
            {
                hash = (uint8_t *)argv[3];
                TRACE_WARNING("Hash: %s\r\n", hash);
            }

            TRACE_WARNING("\r\n");

            error = cloud_request_get(NULL, 0, request, "", hash, NULL);
        }
        else if (!strcasecmp(type, "CERTGEN"))
        {
            /* sanity checks */
            if (argc != 4)
            {
                TRACE_ERROR("Usage: %s CERTGEN <mac_address> <target-dir>\r\n", argv[0]);
                return -1;
            }
            const char *mac = argv[2];
            const char *dest = argv[3];

            if (osStrlen(mac) != 12)
            {
                TRACE_ERROR("MAC address must be in format 001122334455\r\n");
                return -1;
            }
            if (!fsDirExists(dest))
            {
                TRACE_ERROR("Destination directory must exist\r\n");
                return -1;
            }

            /* create needed structures */
            X509CertRequestInfo cert_req;
            X509SerialNumber serial;
            X509Validity validity;
            X509SignAlgoId algo;
            X509CertInfo issuerCertInfo;

            osMemset(&cert_req, 0x00, sizeof(cert_req));
            osMemset(&serial, 0x00, sizeof(serial));
            osMemset(&validity, 0x00, sizeof(validity));
            osMemset(&algo, 0x00, sizeof(algo));
            osMemset(&issuerCertInfo, 0x00, sizeof(issuerCertInfo));

            /*********************************************/
            /*         load server CA certificate        */
            /*********************************************/
            const char *server_ca = settings_get_string("internal.server.ca");
            const char *server_key = settings_get_string("internal.server.ca_key");
            uint8_t *server_ca_der = osAllocMem(8192);
            size_t server_ca_der_size = 0;

            TRACE_INFO("Load CA certificate...\r\n");
            if (pemImportCertificate(server_ca, strlen(server_ca), server_ca_der, &server_ca_der_size, NULL) != NO_ERROR)
            {
                TRACE_ERROR("pemImportCertificate failed\r\n");
                return -1;
            }

            if (x509ParseCertificateEx(server_ca_der, server_ca_der_size, &issuerCertInfo, true) != NO_ERROR)
            {
                TRACE_ERROR("x509ParseCertificateEx failed\r\n");
                return -1;
            }

            RsaPrivateKey caPrivateKey;
            osMemset(&caPrivateKey, 0x00, sizeof(caPrivateKey));

            TRACE_INFO("Load CA key...\r\n");
            if (pemImportRsaPrivateKey(server_key, osStrlen(server_key), NULL, &caPrivateKey) != NO_ERROR)
            {
                TRACE_ERROR("pemImportRsaPrivateKey failed\r\n");
                return -1;
            }

            /*********************************************/
            /* now generate a RSA key for the new client */
            /*********************************************/
            TRACE_INFO("Generating RSA Key...\r\n");
            RsaPrivateKey privateKey;
            RsaPublicKey publicKey;
            osMemset(&privateKey, 0x00, sizeof(privateKey));
            osMemset(&publicKey, 0x00, sizeof(publicKey));
            if (rsaGenerateKeyPair(YARROW_PRNG_ALGO, &yarrowContext, 2048, 65537, &privateKey, &publicKey) != NO_ERROR)
            {
                TRACE_ERROR("rsaGenerateKeyPair failed\r\n");
                return -1;
            }

            size_t privateKey_der_size = 0;
            if (x509ExportRsaPrivateKey(&privateKey, NULL, &privateKey_der_size) != NO_ERROR)
            {
                TRACE_ERROR("x509ExportRsaPrivateKey failed\r\n");
                return -1;
            }
            uint8_t *privateKey_der_data = osAllocMem(privateKey_der_size);
            if (x509ExportRsaPrivateKey(&privateKey, privateKey_der_data, &privateKey_der_size) != NO_ERROR)
            {
                TRACE_ERROR("x509ExportRsaPrivateKey failed\r\n");
                return -1;
            }

            /* create and sign the certificate */
            char_t subj[32];
            osSprintf(subj, "b'%s'", mac);

            cert_req.version = X509_VERSION_1;
            cert_req.subject.commonName.value = subj;
            cert_req.subject.commonName.length = 15;
            cert_req.subjectPublicKeyInfo.oid.value = RSA_ENCRYPTION_OID;
            cert_req.subjectPublicKeyInfo.oid.length = sizeof(RSA_ENCRYPTION_OID);

            cert_req.subjectPublicKeyInfo.rsaPublicKey.e.length = mpiGetByteLength(&publicKey.e);
            cert_req.subjectPublicKeyInfo.rsaPublicKey.n.length = mpiGetByteLength(&publicKey.n);
            uint8_t *rsa_e_buf = osAllocMem(cert_req.subjectPublicKeyInfo.rsaPublicKey.e.length);
            uint8_t *rsa_n_buf = osAllocMem(cert_req.subjectPublicKeyInfo.rsaPublicKey.n.length);
            cert_req.subjectPublicKeyInfo.rsaPublicKey.e.value = rsa_e_buf;
            cert_req.subjectPublicKeyInfo.rsaPublicKey.n.value = rsa_n_buf;
            mpiExport(&publicKey.e, rsa_e_buf, cert_req.subjectPublicKeyInfo.rsaPublicKey.e.length, MPI_FORMAT_BIG_ENDIAN);
            mpiExport(&publicKey.n, rsa_n_buf, cert_req.subjectPublicKeyInfo.rsaPublicKey.n.length, MPI_FORMAT_BIG_ENDIAN);

            uint8_t ser[32];
            ser[0] = 0;
            hex_string_to_bytes(mac, &ser[1]);
            serial.length = 7;
            serial.value = ser;

            getCurrentDate(&validity.notBefore);
            getCurrentDate(&validity.notAfter);
            validity.notBefore.year -= 20;
            validity.notAfter.year += 20;

            algo.oid.value = SHA256_WITH_RSA_ENCRYPTION_OID;
            algo.oid.length = sizeof(SHA256_WITH_RSA_ENCRYPTION_OID);

            uint8_t *derOutput = osAllocMem(8192);
            size_t derSize;

            TRACE_INFO("Generating Certificate...\r\n");
            if (x509CreateCertificate(YARROW_PRNG_ALGO, &yarrowContext, &cert_req, NULL, &issuerCertInfo, &serial, &validity, &algo, &caPrivateKey, derOutput, &derSize) != NO_ERROR)
            {
                TRACE_ERROR("x509CreateCertificate failed\r\n");
                return -1;
            }

            size_t pemSize;
            if (pemExportCertificate(derOutput, derSize, NULL, &pemSize) != NO_ERROR)
            {
                TRACE_ERROR("pemExportCertificate failed\r\n");
                return -1;
            }

            char_t *pemOutput = osAllocMem(pemSize + 1);
            if (pemExportCertificate(derOutput, derSize, pemOutput, &pemSize) != NO_ERROR)
            {
                TRACE_ERROR("pemExportCertificate failed\r\n");
                return -1;
            }
            pemOutput[pemSize] = 0;

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
                fsWriteFile(file, pemOutput, pemSize);
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
                fsWriteFile(file, derOutput, derSize);
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
                fsWriteFile(file, privateKey_der_data, privateKey_der_size);
                fsCloseFile(file);
                osFreeMem(path);
            }

            osFreeMem(server_ca_der);
            osFreeMem(derOutput);
            osFreeMem(rsa_n_buf);
            osFreeMem(rsa_e_buf);
            osFreeMem(privateKey_der_data);
        }
        else if (!strcasecmp(type, "ESP32CERT"))
        {
            if (argc < 5)
            {
                TRACE_ERROR("Usage: %s ESP32CERT (extract/inject) <esp32-image-bin> <source/target-dir>\r\n", argv[0]);
                return -1;
            }
            const char *cmd = argv[2];
            if (!strcasecmp(cmd, "inject"))
            {
                esp32_fat_inject((const char *)argv[3], "CERT", (const char *)argv[4]);
            }
            else if (!strcasecmp(cmd, "extract"))
            {
                esp32_fat_extract((const char *)argv[3], "CERT", (const char *)argv[4]);
            }
        }
        else if (!strcasecmp(type, "ESP32FIXUP"))
        {
            if (argc < 3)
            {
                TRACE_ERROR("Usage: %s ESP32FIXUP <esp32-image-bin>\r\n", argv[0]);
                return -1;
            }
            esp32_fixup((const char *)argv[2], true);
        }
    }
    else
    {
        mqtt_init();
        server_init();
    }

    tls_adapter_deinit();
    platform_deinit();
    settings_deinit_all();

    return error;
}
