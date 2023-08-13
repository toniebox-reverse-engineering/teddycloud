#include <errno.h>
#ifdef WIN32
#else
#include <sys/random.h>
#endif

#include "pem_export.h"
#include "rng/yarrow.h"
#include "tls_adapter.h"
#include "error.h"
#include "debug.h"
#include "settings.h"
#include "fs_port.h"
#include "fs_ext.h"

// tsl_certificate.c function Dependencies
#include <string.h>
#include <ctype.h>
#include "tls.h"
#include "tls_certificate.h"
#include "tls_misc.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "pkix/pem_import.h"
#include "pkix/x509_cert_parse.h"
#include "pkix/x509_cert_validate.h"
#include "pkix/x509_key_parse.h"
#include "debug.h"

TlsCache *tlsCache;

YarrowContext yarrowContext;

/**
 * @enum eDerType
 * @brief Enumeration for the types of DER data
 */
typedef enum
{
    eDerTypeUnknown,
    eDerTypeKey,
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
            error_t err = fsReadFile(fp, &derLen, 1, &len);
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
            /* when it's an SEQUENCE, its probably a certificate */
            *type = eDerTypeCertificate;
        }
        else if (tag == 0x02)
        {
            /* when it's an INTEGER, its probably the RSA key */
            *type = eDerTypeKey;
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
            TRACE_ERROR("Error: pemEncodeFile failed for %s with code %d\r\n", filename, error);
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

    char buf[256]; // key is at most 194 chars. see tlsDumpSecret
    size_t len = osStrlen(key);
    if (len > sizeof(buf) - 2)
        return;
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
    // Release PRNG context
    yarrowRelease(&yarrowContext);

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
        if (!src_filename)
        {
            TRACE_ERROR("Failed to look up '%s'\r\n", src_file);
            return ERROR_FAILURE;
        }
        char_t *serverCert = NULL;
        size_t serverCertLen = 0;
        error_t error = read_certificate(src_filename, &serverCert, &serverCertLen);

        if (error)
        {
            TRACE_ERROR("Loading cert '%s' failed\r\n", src_filename);
            return error;
        }
        settings_set_string_id(dest_var, serverCert, settingsId);
        free(serverCert);
    }

    return NO_ERROR;
}

error_t tls_adapter_init()
{
    uint8_t seed[32];

    int ret = getrandom(seed, sizeof(seed), 0);
    if (ret < 0)
    {
        TRACE_ERROR("Error: Failed to generate random data (%d)\r\n", errno);
        return ERROR_FAILURE;
    }

    error_t error = yarrowInit(&yarrowContext);
    if (error)
    {
        TRACE_ERROR("Error: PRNG initialization failed (%d)\r\n", error);
        return ERROR_FAILURE;
    }

    error = yarrowSeed(&yarrowContext, seed, sizeof(seed));
    if (error)
    {
        TRACE_ERROR("Error: Failed to seed PRNG (%d)\r\n", error);
        return error;
    }

    TRACE_INFO("Loading certificates...\r\n");
    settings_load_certs_id(0);

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

static void copyAsHex(char *dst, size_t dstLen, size_t payloadLen, const uint8_t *payloadData)
{
    if (payloadLen <= 0 || dstLen <= 0)
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

/**
 * @brief Parse certificate chain
 * @param[in] context Pointer to the TLS context
 * @param[in] p Input stream where to read the certificate chain
 * @param[in] length Number of bytes available in the input stream
 * @return Error code
 **/

error_t tlsParseCertificateList(TlsContext *context,
                                const uint8_t *p, size_t length)
{
    error_t error;
    error_t certValidResult;
    uint_t i;
    size_t n;
    const char_t *subjectName;
    X509CertInfo *certInfo;
    X509CertInfo *issuerCertInfo;

    // Initialize X.509 certificates
    certInfo = NULL;
    issuerCertInfo = NULL;

    // Start of exception handling block
    do
    {
        // Allocate a memory buffer to store X.509 certificate info
        certInfo = tlsAllocMem(sizeof(X509CertInfo));
        // Failed to allocate memory?
        if (certInfo == NULL)
        {
            // Report an error
            error = ERROR_OUT_OF_MEMORY;
            break;
        }

        // Allocate a memory buffer to store the parent certificate
        issuerCertInfo = tlsAllocMem(sizeof(X509CertInfo));
        // Failed to allocate memory?
        if (issuerCertInfo == NULL)
        {
            // Report an error
            error = ERROR_OUT_OF_MEMORY;
            break;
        }

        // The end-user certificate is preceded by a 3-byte length field
        if (length < 3)
        {
            // Report an error
            error = ERROR_DECODING_FAILED;
            break;
        }

        // Get the size occupied by the certificate
        n = LOAD24BE(p);
        // Jump to the beginning of the DER-encoded certificate
        p += 3;
        length -= 3;

        // Malformed Certificate message?
        if (n == 0 || n > length)
        {
            // Report an error
            error = ERROR_DECODING_FAILED;
            break;
        }

        // Display ASN.1 structure
        error = asn1DumpObject(p, n, 0);
        // Any error to report?
        if (error)
            break;

        // Parse end-user certificate
        error = x509ParseCertificate(p, n, certInfo);
        // Failed to parse the X.509 certificate?
        if (error)
        {
            // Report an error
            error = ERROR_BAD_CERTIFICATE;
            break;
        }

        // Check certificate key usage
        error = tlsCheckKeyUsage(certInfo, context->entity,
                                 context->keyExchMethod);
        // Any error to report?
        if (error)
            break;

        // Extract the public key from the end-user certificate
        error = tlsReadSubjectPublicKey(context,
                                        &certInfo->tbsCert.subjectPublicKeyInfo);
        // Any error to report?
        if (error)
            break;

#if (TLS_CLIENT_SUPPORT == ENABLED)
        // Client mode?
        if (context->entity == TLS_CONNECTION_END_CLIENT)
        {
            TlsCertificateType certType;
            TlsNamedGroup namedCurve;

            // Retrieve the type of the X.509 certificate
            error = tlsGetCertificateType(certInfo, &certType, &namedCurve);
            // Unsupported certificate?
            if (error)
                break;

            // Version of TLS prior to TLS 1.3?
            if (context->version <= TLS_VERSION_1_2)
            {
                // ECDSA certificate?
                if (certType == TLS_CERT_ECDSA_SIGN)
                {
                    // Make sure the elliptic curve is supported
                    if (tlsGetCurveInfo(context, namedCurve) == NULL)
                    {
                        error = ERROR_BAD_CERTIFICATE;
                        break;
                    }
                }
            }

            // Point to the subject name
            subjectName = context->serverName;

            // Check the subject name in the server certificate against the actual
            // FQDN name that is being requested
            error = x509CheckSubjectName(certInfo, subjectName);
            // Any error to report?
            if (error)
            {
                // Debug message
                TRACE_WARNING("Server name mismatch!\r\n");

                // Report an error
                error = ERROR_BAD_CERTIFICATE;
                break;
            }
        }
        else
#endif
        // Server mode?
        {
            // Do not check name constraints
            subjectName = NULL;

            /* TeddyCloud customizations - copy certificate into TLS context */
            copyAsString(context->client_cert_issuer, sizeof(context->client_cert_issuer), certInfo->tbsCert.issuer.commonName.length, certInfo->tbsCert.issuer.commonName.value);
            copyAsString(context->client_cert_subject, sizeof(context->client_cert_subject), certInfo->tbsCert.subject.commonName.length, certInfo->tbsCert.subject.commonName.value);
            copyAsHex(context->client_cert_serial, sizeof(context->client_cert_serial), certInfo->tbsCert.serialNumber.length, certInfo->tbsCert.serialNumber.value);
        }

        // Check if the end-user certificate can be matched with a trusted CA
        certValidResult = tlsValidateCertificate(context, certInfo, 0,
                                                 subjectName);

        // Check validation result
        if (certValidResult != NO_ERROR && certValidResult != ERROR_UNKNOWN_CA)
        {
            // The certificate is not valid
            error = certValidResult;
            break;
        }

        // Next certificate
        p += n;
        length -= n;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
        // TLS 1.3 currently selected?
        if (context->version == TLS_VERSION_1_3)
        {
            // Parse the list of extensions for the current CertificateEntry
            error = tls13ParseCertExtensions(p, length, &n);
            // Any error to report?
            if (error)
                break;

            // Point to the next field
            p += n;
            // Remaining bytes to process
            length -= n;
        }
#endif

        // PKIX path validation
        for (i = 0; length > 0; i++)
        {
            // Each intermediate certificate is preceded by a 3-byte length field
            if (length < 3)
            {
                // Report an error
                error = ERROR_DECODING_FAILED;
                break;
            }

            // Get the size occupied by the certificate
            n = LOAD24BE(p);
            // Jump to the beginning of the DER-encoded certificate
            p += 3;
            // Remaining bytes to process
            length -= 3;

            // Malformed Certificate message?
            if (n == 0 || n > length)
            {
                // Report an error
                error = ERROR_DECODING_FAILED;
                break;
            }

            // Display ASN.1 structure
            error = asn1DumpObject(p, n, 0);
            // Any error to report?
            if (error)
                break;

            // Parse intermediate certificate
            error = x509ParseCertificate(p, n, issuerCertInfo);
            // Failed to parse the X.509 certificate?
            if (error)
            {
                // Report an error
                error = ERROR_BAD_CERTIFICATE;
                break;
            }

            // Certificate chain validation in progress?
            if (certValidResult == ERROR_UNKNOWN_CA)
            {
                // Validate current certificate
                error = x509ValidateCertificate(certInfo, issuerCertInfo, i);
                // Certificate validation failed?
                if (error)
                    break;

                // Check name constraints
                error = x509CheckNameConstraints(subjectName, issuerCertInfo);
                // Should the application reject the certificate?
                if (error)
                    return ERROR_BAD_CERTIFICATE;

                // Check the version of the certificate
                if (issuerCertInfo->tbsCert.version < X509_VERSION_3)
                {
                    // Conforming implementations may choose to reject all version 1
                    // and version 2 intermediate certificates (refer to RFC 5280,
                    // section 6.1.4)
                    error = ERROR_BAD_CERTIFICATE;
                    break;
                }

                // Check if the intermediate certificate can be matched with a
                // trusted CA
                certValidResult = tlsValidateCertificate(context, issuerCertInfo,
                                                         i, subjectName);

                // Check validation result
                if (certValidResult != NO_ERROR && certValidResult != ERROR_UNKNOWN_CA)
                {
                    // The certificate is not valid
                    error = certValidResult;
                    break;
                }
            }

            // Keep track of the issuer certificate
            *certInfo = *issuerCertInfo;

            // Next certificate
            p += n;
            length -= n;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
            // TLS 1.3 currently selected?
            if (context->version == TLS_VERSION_1_3)
            {
                // Parse the list of extensions for the current CertificateEntry
                error = tls13ParseCertExtensions(p, length, &n);
                // Any error to report?
                if (error)
                    break;

                // Point to the next field
                p += n;
                // Remaining bytes to process
                length -= n;
            }
#endif
        }

        // Certificate chain validation failed?
        if (error == NO_ERROR && certValidResult != NO_ERROR)
        {
            // A valid certificate chain or partial chain was received, but the
            // certificate was not accepted because the CA certificate could not
            // be matched with a known, trusted CA
            error = ERROR_UNKNOWN_CA;
        }

        // End of exception handling block
    } while (0);

    // Free previously allocated memory
    tlsFreeMem(certInfo);
    tlsFreeMem(issuerCertInfo);

    // Return status code
    return error;
}
