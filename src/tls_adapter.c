
#include "error_text.h"
#include "tls_adapter.h"              // for load_cert, tls_adapter_deinit

#include <errno.h>                    // for error_t
#include <stdint.h>                   // for uint8_t, uint32_t
#include <stdio.h>                    // for sprintf
#include <stdlib.h>                   // for free
#include <string.h>                   // for NULL, size_t, memcpy, strlen

#include "compiler_port.h"            // for char_t, uint_t
#include "cpu_endian.h"               // for LOAD24BE
#include "debug.h"                    // for TRACE_ERROR, TRACE_INFO, TRACE_...
#include "encoding/asn1.h"            // for asn1DumpObject
#include "error.h"                    // for NO_ERROR, ERROR_BAD_CERTIFICATE
#include "fs_ext.h"                   // for fsOpenFileEx
#include "fs_port.h"                  // for FS_FILE_MODE_READ
#include "fs_port_posix.h"            // for fsReadFile, fsCloseFile, fsOpen...
#include "hash/sha256.h"              // for sha256Compute
#include "os_port.h"                  // for osFreeMem, osAllocMem, osMemset
#include "pem_common.h"               // for pemEncodeFile
#include "pkix/pem_import.h"          // for pemImportCertificate
#include "pkix/x509_cert_parse.h"     // for x509ParseCertificate
#include "pkix/x509_cert_validate.h"  // for x509CheckNameConstraints, x509C...
#include "settings.h"                 // for settings_get_string_id, setting...
#include "stdbool.h"                  // for false, bool, true
#include "tls.h"                      // for _TlsContext, TLS_VERSION_1_3
#include "tls_certificate.h"          // for tlsValidateCertificate, tlsChec...
#include "tls_misc.h"                 // for tlsGetCurveInfo
#include "x509_common.h"              // for X509CertInfo, X509TbsCertificate

TlsCache *tlsCache;

/**
 * @enum eDerType
 * @brief Enumeration for the types of DER data
 */
typedef enum
{
    eDerTypeUnknown,
    eDerTypeKey,
    eDerTypeEcKey,
    eDerTypeCertificate
} eDerType;

/**
 * @brief Reads a length field from ASN.1 DER data
 *
 * This function reads a length field from ASN.1 DER data from the given file.
 * The length is encoded either in short form (single byte) or long form
 * (multiple bytes with the high bit set in the first byte).
 *
 * @param[in] fp The file to read from
 * @return The length read from the file
 */
error_t der_get_length(FsFile *fp, size_t *outLength)
{
    uint8_t derLen;
    size_t len;
    error_t err = fsReadFile(fp, &derLen, 1, &len);

    if (err != NO_ERROR || len != 1)
    {
        *outLength = 0;
        return err;
    }

    if ((derLen & 0x80) == 0)
    {
        *outLength = derLen; // Short form
    }
    else
    {
        uint8_t num_bytes = derLen & 0x7f; // Long form
        uint32_t length = 0;
        for (uint8_t i = 0; i < num_bytes; i++)
        {
            err = fsReadFile(fp, &derLen, 1, &len);
            if (err != NO_ERROR || len != 1)
            {
                *outLength = 0;
                return err;
            }

            length = (length << 8) | derLen;
        }
        *outLength = length;
    }
    return NO_ERROR;
}

/**
 * @brief Determines the type of DER data in a file
 *
 * This function attempts to determine whether the given file contains
 * an X.509 certificate or an RSA private key encoded in ASN.1 DER format.
 * The type is determined based on the first few bytes of the data.
 *
 * @param[in] filename The name of the file to check
 * @return The type of the DER data in the file, or eDerTypeUnknown if the type could not be determined
 */
error_t der_detect(const char *filename, eDerType *type)
{
    error_t ret = NO_ERROR;
    *type = eDerTypeUnknown;

    FsFile *fp = fsOpenFile(filename, FS_FILE_MODE_READ);
    if (!fp)
    {
        return ERROR_FAILURE;
    }

    /* while loop to break out and clean up commonly */
    do
    {
        uint8_t tag;
        size_t len;

        /* read first byte */
        error_t err = fsReadFile(fp, &tag, 1, &len);
        if (err != NO_ERROR || len != 1)
        {
            ret = ERROR_FAILURE;
            break;
        }

        /* check for DER SEQUENCE format */
        if (tag != 0x30)
        {
            break;
        }

        /* read length of SEQUENCE */
        size_t length;
        err = der_get_length(fp, &length);
        if (err != NO_ERROR)
        {
            ret = ERROR_FAILURE;
            break;
        }

        /* now get type of content */
        err = fsReadFile(fp, &tag, 1, &len);
        if (err != NO_ERROR || len != 1)
        {
            ret = ERROR_FAILURE;
            break;
        }

        if (tag == 0x30)
        {
            /* when it's a SEQUENCE, it's probably a certificate */
            *type = eDerTypeCertificate;
        }
        else if (tag == 0x02)
        {
            /* read the INTEGER length */
            size_t intLen;
            err = der_get_length(fp, &intLen);
            if (err != NO_ERROR || intLen == 0)
            {
                *type = eDerTypeKey; /* fallback: assume RSA */
                break;
            }
            /* read the first byte of the INTEGER value (version) */
            uint8_t version;
            err = fsReadFile(fp, &version, 1, &len);
            if (err != NO_ERROR || len != 1)
            {
                *type = eDerTypeKey; /* fallback: assume RSA */
                break;
            }
            if (version == 0x01)
            {
                /* EC private key (RFC 5915): version = 1 */
                *type = eDerTypeEcKey;
            }
            else
            {
                /* RSA/other: version = 0 */
                *type = eDerTypeKey;
            }
        }
    } while (0);

    fsCloseFile(fp);

    return ret;
}

/**
 * @brief Load the specified PEM file
 * @param[in] filename Name of the PEM file to load
 * @param[out] buffer Memory buffer that holds the contents of the file
 * @param[out] length Length of the file in bytes
 **/
error_t read_certificate(const char_t *filename, char_t **buffer, size_t *length)
{
    error_t error;

    // Initialize output parameters
    *buffer = NULL;
    *length = 0;

    if (!filename)
    {
        TRACE_ERROR("Filename NULL\r\n");
        return ERROR_READ_FAILED;
    }

    const char_t *type = NULL;
    eDerType derType;

    error = der_detect(filename, &derType);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Failed to open '%s' for cert type detection\r\n", filename);
        return ERROR_READ_FAILED;
    }

    switch (derType)
    {
    case eDerTypeCertificate:
        type = "CERTIFICATE";
        TRACE_INFO("File '%s' detected as DER style %s\r\n", filename, type);
        break;
    case eDerTypeKey:
        type = "RSA PRIVATE KEY";
        TRACE_INFO("File '%s' detected as DER style %s\r\n", filename, type);
        break;
    case eDerTypeEcKey:
        type = "EC PRIVATE KEY";
        TRACE_INFO("File '%s' detected as DER style %s\r\n", filename, type);
        break;
    default:
        TRACE_INFO("File '%s' assumed PEM style\r\n", filename);
        type = NULL;
        break;
    }

    FsFile *fp = NULL;
    do
    {
        uint32_t fileLength = 0;
        error = fsGetFileSize(filename, &fileLength);
        if (error != NO_ERROR)
        {
            break;
        }

        /* allocate file content buffer */
        *length = fileLength;
        *buffer = osAllocMem(fileLength + 1);

        if (*buffer == NULL)
        {
            error = ERROR_OUT_OF_MEMORY;
            break;
        }
        osMemset(*buffer, 0x00, fileLength + 1);

        // Open the specified file
        fp = fsOpenFile(filename, FS_FILE_MODE_READ);

        // Failed to open the file?
        if (fp == NULL)
        {
            error = ERROR_OPEN_FAILED;
            break;
        }

        // Read file contents
        size_t read = 0;
        error = fsReadFile(fp, *buffer, *length, &read);

        // Failed to read data?
        if (error != NO_ERROR)
        {
            break;
        }

        // Failed to read data?
        if (read != *length)
        {
            error = ERROR_READ_FAILED;
            break;
        }

        // Successful processing
        error = NO_ERROR;
    } while (0);

    // Close file
    if (fp != NULL)
        fsCloseFile(fp);

    // Any error to report?
    if (error)
    {
        TRACE_ERROR("Error: Cannot load file %s\r\n", filename);
        // Clean up side effects
        osFreeMem(*buffer);
        *buffer = NULL;
        *length = 0;
    }

    /* convert .der to .pem by encoding it into ascii format */
    if (type && *buffer)
    {
        char *inBuf = *buffer;
        size_t inBufLen = *length;

        char *outBuf = NULL;
        size_t outBufLen = 0;

        /* get size of output string */
        error = pemEncodeFile(inBuf, inBufLen, type, NULL, &outBufLen);

        if (error != NO_ERROR)
        {
            TRACE_ERROR("Error: pemEncodeFile failed for %s with error %s\r\n", filename, error2text(error));
            return error;
        }

        outBuf = osAllocMem(outBufLen + 1);
        osMemset(outBuf, 0x00, outBufLen + 1);
        error = pemEncodeFile(inBuf, inBufLen, type, outBuf, &outBufLen);

        osFreeMem(inBuf);

        /* replace output data with generated ascii string */
        *buffer = outBuf;
        *length = outBufLen;
    }

    // Return status code
    return error;
}

static void keylog_write(TlsContext *context, const char_t *key)
{
    static bool failed = false;
    const char *logfile = settings_get_string("core.sslkeylogfile");
    if (!logfile || !osStrlen(logfile))
        return;

    char buf[256]; // key is at most 194 chars. see tlsDumpSecret
    size_t len = osStrlen(key);
    if (len > sizeof(buf) - 2)
        return;

    FsFile *keyLogFile = fsOpenFileEx(logfile, "a");
    if (keyLogFile == NULL)
    {
        if (!failed)
        {
            TRACE_ERROR("Failed to open ssl key log file \"%s\"\r\n", logfile);
            failed = true;
        }
        return;
    }
    osMemcpy(buf, key, len);
    buf[len++] = '\n';
    buf[len] = '\0';
    fsWriteFile(keyLogFile, buf, len);
    fsCloseFile(keyLogFile);
    failed = false;
}

void tls_context_key_log_init(TlsContext *context)
{
    (void)tlsSetKeyLogCallback(context, keylog_write);
}

error_t tls_adapter_deinit()
{
    return NO_ERROR;
}

error_t load_cert(const char *dest_var, const char *src_file, const char *src_var, uint8_t settingsId)
{
    /* check if the source setting contains a cert */
    const char *src_var_val = settings_get_string_id(src_var, settingsId);

    if (src_var_val && strlen(src_var_val))
    {
        settings_set_string_id(dest_var, src_var_val, settingsId);
    }
    else
    {
        const char *src_filename = settings_get_string_id(src_file, settingsId);

        char *src_filename_full = osAllocMem(256);
        settings_resolve_dir(&src_filename_full, (char *)src_filename, get_settings()->internal.basedirfull);

        if (!src_filename)
        {
            TRACE_ERROR("Failed to look up '%s'\r\n", src_file);
            osFreeMem(src_filename_full);
            return ERROR_FAILURE;
        }
        char_t *serverCert = NULL;
        size_t serverCertLen = 0;
        error_t error = read_certificate(src_filename_full, &serverCert, &serverCertLen);

        if (error)
        {
            TRACE_ERROR("Loading cert '%s' failed\r\n", src_filename_full);
            osFreeMem(src_filename_full);
            return error;
        }
        osFreeMem(src_filename_full);
        settings_set_string_id(dest_var, serverCert, settingsId);
        free(serverCert);
    }

    return NO_ERROR;
}

error_t tls_adapter_init()
{
    TRACE_INFO("Loading certificates...\r\n");
    error_t error = settings_load_certs_id(0);
    if (error)
    {
        TRACE_ERROR("Error: Failed to load certs (%s)\r\n", error2text(error));
        return error;
    }

    // TLS session cache initialization
    tlsCache = tlsInitCache(8);

    // Any error to report?
    if (tlsCache == NULL)
    {
        // Debug message
        TRACE_ERROR("Failed to initialize TLS session cache!\r\n");
    }

    return NO_ERROR;
}

static void copyAsString(char *dst, size_t dstLen, size_t srcLen, const char_t *srcData)
{
    if (srcLen == 0 || dstLen == 0)
    {
        return;
    }

    size_t len = srcLen < dstLen ? srcLen : dstLen - 1;
    memcpy(dst, srcData, len);
    dst[len] = '\0';
}

/* Box certificates of TeddyCloud are issued directly by one of its CAs. */
static bool issued_by(const X509CertInfo *cert, const char_t *caPem)
{
    size_t pemLength = caPem ? osStrlen(caPem) : 0;
    size_t derLength = 0;

    if (pemLength == 0 || pemImportCertificate(caPem, pemLength, NULL, &derLength, NULL) != NO_ERROR)
    {
        return false;
    }

    uint8_t *der = osAllocMem(derLength);
    X509CertInfo *ca = osAllocMem(sizeof(X509CertInfo));
    bool issued = der != NULL && ca != NULL &&
                  pemImportCertificate(caPem, pemLength, der, &derLength, NULL) == NO_ERROR &&
                  x509ParseCertificate(der, derLength, ca) == NO_ERROR &&
                  x509ValidateCertificate(cert, ca, 0) == NO_ERROR;

    osFreeMem(ca);
    osFreeMem(der);
    return issued;
}

static void copyAsHex(char *dst, size_t dstLen, size_t payloadLen, const uint8_t *payloadData)
{
    if (payloadLen == 0 || dstLen == 0)
    {
        return;
    }

    // Prepare to write as many full hex bytes as will fit into dst.
    size_t maxHexBytes = (dstLen - 1) / 2;
    if (maxHexBytes > payloadLen)
    {
        maxHexBytes = payloadLen;
    }

    for (size_t pos = 0; pos < maxHexBytes; pos++)
    {
        sprintf(dst + pos * 2, "%02X", payloadData[pos]);
    }

    // Null-terminate the output string.
    dst[maxHexBytes * 2] = '\0';
}

bool tls_cert_fingerprint(const char_t *pem, char_t sha256[65], char_t *subject, size_t subjectSize)
{
    size_t pemLength = pem ? osStrlen(pem) : 0;
    size_t derLength = 0;

    if (pemLength == 0 || pemImportCertificate(pem, pemLength, NULL, &derLength, NULL) != NO_ERROR)
    {
        return false;
    }

    uint8_t *der = osAllocMem(derLength);
    X509CertInfo *cert = osAllocMem(sizeof(X509CertInfo));
    bool parsed = der != NULL && cert != NULL &&
                  pemImportCertificate(pem, pemLength, der, &derLength, NULL) == NO_ERROR &&
                  x509ParseCertificate(der, derLength, cert) == NO_ERROR;
    if (parsed)
    {
        uint8_t digest[SHA256_DIGEST_SIZE];
        sha256Compute(der, derLength, digest);
        copyAsHex(sha256, 65, sizeof(digest), digest);
        copyAsString(subject, subjectSize, cert->tbsCert.subject.commonName.length, cert->tbsCert.subject.commonName.value);
    }

    osFreeMem(cert);
    osFreeMem(der);
    return parsed;
}

/**
 * @brief Parse certificate chain
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the certificate chain
 * @param[in] length Number of bytes available in the input stream
 * @return Error code
 **/

/*
 * Cyclone's own tlsParseCertificateList() is compiled under the name tlsParseCertificateList_override (see
 * the Makefile). It validates the certificate list; afterwards, when we are the server, the client's
 * certificate is copied into the TLS context for the box certificate check (box_cert_check.c).
 */
error_t tlsParseCertificateList_override(TlsContext *context, const uint8_t *p, size_t length);

error_t tlsParseCertificateList(TlsContext *context, const uint8_t *p, size_t length)
{
    error_t error = tlsParseCertificateList_override(context, p, length);
    if (error || context->entity != TLS_CONNECTION_END_SERVER)
    {
        return error;
    }

    /* the list was parsed and is well-formed: the first entry is the client's certificate (3 byte length + DER) */
    size_t n = LOAD24BE(p);
    const uint8_t *der = p + 3;

    X509CertInfo *certInfo = tlsAllocMem(sizeof(X509CertInfo));
    if (certInfo == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }

    error = x509ParseCertificate(der, n, certInfo);
    if (!error)
    {
        copyAsString(context->client_cert_issuer, sizeof(context->client_cert_issuer), certInfo->tbsCert.issuer.commonName.length, certInfo->tbsCert.issuer.commonName.value);
        copyAsString(context->client_cert_subject, sizeof(context->client_cert_subject), certInfo->tbsCert.subject.commonName.length, certInfo->tbsCert.subject.commonName.value);
        copyAsHex(context->client_cert_serial, sizeof(context->client_cert_serial), certInfo->tbsCert.serialNumber.length, certInfo->tbsCert.serialNumber.value);
        uint8_t sha256[SHA256_DIGEST_SIZE];
        sha256Compute(der, n, sha256);
        copyAsHex(context->client_cert_sha256, sizeof(context->client_cert_sha256), sizeof(sha256), sha256);
        context->client_cert_trusted = issued_by(certInfo, settings_get_string("internal.server.ca")) ||
                                       issued_by(certInfo, settings_get_string("internal.server_tb2.ca"));
    }

    tlsFreeMem(certInfo);
    return error;
}
