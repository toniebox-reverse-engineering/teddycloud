#include <errno.h>
#include <sys/random.h>

#include "pem_export.h"
#include "rng/yarrow.h"
#include "tls_adapter.h"
#include "error.h"
#include "debug.h"
#include "settings.h"

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
 * @brief Load the specified PEM file
 * @param[in] filename Name of the PEM file to load
 * @param[out] buffer Memory buffer that holds the contents of the file
 * @param[out] length Length of the file in bytes
 **/
error_t readPemFile(const char_t *filename, char_t **buffer, size_t *length, const char_t *type)
{
    int_t ret;
    error_t error;
    FILE *fp;

    // Initialize output parameters
    *buffer = NULL;
    *length = 0;

    if (!filename)
    {
        TRACE_ERROR("readPemFile() Filename NULL\r\n");
        return ERROR_READ_FAILED;
    }

    // Start of exception handling block
    do
    {
        // Open the specified file
        fp = fopen(filename, "rb");

        // Failed to open the file?
        if (fp == NULL)
        {
            error = ERROR_OPEN_FAILED;
            break;
        }

        // Jump to the end of the file
        ret = fseek(fp, 0, SEEK_END);

        // Any error to report?
        if (ret != 0)
        {
            error = ERROR_FAILURE;
            break;
        }

        // Retrieve the length of the file
        *length = ftell(fp);
        // Allocate a buffer to hold the contents of the file
        *buffer = malloc(*length + 1);
        memset(*buffer, 0x00, *length + 1);

        // Failed to allocate memory?
        if (*buffer == NULL)
        {
            error = ERROR_OUT_OF_MEMORY;
            break;
        }

        // Rewind to the beginning of the file
        rewind(fp);
        // Read file contents
        ret = fread(*buffer, 1, *length, fp);

        // Failed to read data?
        if (ret != *length)
        {
            error = ERROR_READ_FAILED;
            break;
        }

        // Successful processing
        error = NO_ERROR;

        // End of exception handling block
    } while (0);

    // Close file
    if (fp != NULL)
        fclose(fp);

    // Any error to report?
    if (error)
    {
        // Debug message
        TRACE_ERROR("Error: Cannot load file %s\r\n", filename);
        // Clean up side effects
        free(*buffer);
    }

    /* convert .der to .pem by encoding it into ascii format */
    if (type)
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

        outBuf = malloc(outBufLen + 1);
        memset(outBuf, 0x00, outBufLen + 1);
        error = pemEncodeFile(inBuf, inBufLen, type, outBuf, &outBufLen);

        free(inBuf);

        *buffer = outBuf;
        *length = outBufLen;
    }

    // Return status code
    return error;
}

error_t tls_adapter_deinit()
{
    // Release PRNG context
    yarrowRelease(&yarrowContext);

    return NO_ERROR;
}

error_t load_cert(const char *dest_var, const char *src_file, const char *src_var)
{
    /* check if the source setting contains a cert */
    const char *src_var_val = settings_get_string(src_var);

    if (strlen(src_var_val))
    {
        settings_set_string(dest_var, src_var_val);
    }
    else
    {
        char_t *serverCert = NULL;
        size_t serverCertLen = 0;
        error_t error = readPemFile(settings_get_string(src_file), &serverCert, &serverCertLen, NULL);
        if (error)
        {
            TRACE_ERROR("Loading cert '%s' failed\r\n", settings_get_string(src_file));
            return error;
        }
        settings_set_string(dest_var, serverCert);
        free(serverCert);
    }

    return NO_ERROR;
}

error_t tls_adapter_init()
{
    uint8_t seed[32];

    int ret = getrandom(seed, sizeof(seed), GRND_RANDOM);
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

    load_cert("internal.server.ca", "core.server_cert.file.ca", "core.server_cert.data.ca");
    load_cert("internal.server.crt", "core.server_cert.file.crt", "core.server_cert.data.crt");
    load_cert("internal.server.key", "core.server_cert.file.key", "core.server_cert.data.key");
    load_cert("internal.client.ca", "core.client_cert.file.ca", "core.client_cert.data.ca");
    load_cert("internal.client.crt", "core.client_cert.file.crt", "core.client_cert.data.crt");
    load_cert("internal.client.key", "core.client_cert.file.key", "core.client_cert.data.key");

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
    X509CertificateInfo *certInfo;
    X509CertificateInfo *issuerCertInfo;

    // Initialize X.509 certificates
    certInfo = NULL;
    issuerCertInfo = NULL;

    // Start of exception handling block
    do
    {
        // Allocate a memory buffer to store X.509 certificate info
        certInfo = tlsAllocMem(sizeof(X509CertificateInfo));
        // Failed to allocate memory?
        if (certInfo == NULL)
        {
            // Report an error
            error = ERROR_OUT_OF_MEMORY;
            break;
        }

        // Allocate a memory buffer to store the parent certificate
        issuerCertInfo = tlsAllocMem(sizeof(X509CertificateInfo));
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
            TlsSignatureAlgo certSignAlgo;
            TlsHashAlgo certHashAlgo;
            TlsNamedGroup namedCurve;

            // Retrieve the type of the X.509 certificate
            error = tlsGetCertificateType(certInfo, &certType, &certSignAlgo,
                                          &certHashAlgo, &namedCurve);
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
            copyAsString(context->client_cert_issuer, sizeof(context->client_cert_issuer), certInfo->tbsCert.issuer.commonNameLen, certInfo->tbsCert.issuer.commonName);
            copyAsString(context->client_cert_subject, sizeof(context->client_cert_subject), certInfo->tbsCert.subject.commonNameLen, certInfo->tbsCert.subject.commonName);
            copyAsHex(context->client_cert_serial, sizeof(context->client_cert_serial), certInfo->tbsCert.serialNumber.length, certInfo->tbsCert.serialNumber.data);
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
