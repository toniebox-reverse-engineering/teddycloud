/**
 * @file main.c
 * @brief TLS client demo
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

// Platform-specific dependencies
#ifdef _WIN32
#include "platform_win32.h"
#else
#include <sys/random.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#endif

// Dependencies
#include <stdlib.h>
#include "pem_export.h"
#include "tls_cipher_suites.h"
#include "rng/yarrow.h"
#include "debug.h"

// Trusted CA bundle
#define APP_CA_CERT_BUNDLE "certs/ca.der"
#define APP_CLIENT_CERT "certs/client.der"
#define APP_CLIENT_PRIVATE_KEY "certs/private.der"

char_t *clientCert = NULL;
size_t clientCertLen = 0;
char_t *clientPrivateKey = NULL;
size_t clientPrivateKeyLen = 0;
char_t *trustedCaList = NULL;
size_t trustedCaListLen = 0;
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
        *buffer = malloc(*length);

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

        error = pemEncodeFile(inBuf, inBufLen, type, NULL, &outBufLen);

        if (error != NO_ERROR)
        {
            TRACE_ERROR("Error: pemEncodeFile failed for %s with code %d\r\n", filename, error);
            return error;
        }

        outBuf = malloc(outBufLen + 1);
        error = pemEncodeFile(inBuf, inBufLen, type, outBuf, &outBufLen);

        free(inBuf);

        *buffer = outBuf;
        *length = outBufLen;
    }

    // Return status code
    return error;
}

int_t main(int argc, char *argv[])
{
    error_t error;
    int_t ret;
    uint8_t seed[32];

    // Credentials
    // Start-up message
    TRACE_INFO("**********************************\r\n");
    TRACE_INFO("***       Cloud API test       ***\r\n");
    TRACE_INFO("**********************************\r\n");
    TRACE_INFO("\r\n");

    char *request = NULL;
    char *hash = NULL;

    if (argc < 2)
    {
        TRACE_ERROR("Usage: %s <request> [hash]\r\n", argv[0]);
        return -1;
    }
    if (argc > 1)
    {
        request = argv[1];
        TRACE_ERROR("Request URL: %s\r\n", request);
    }
    if (argc > 2)
    {
        hash = argv[2];
        TRACE_ERROR("Hash: %s\r\n", hash);
    }

    TRACE_ERROR("\r\n");

    // Generate a random seed
    ret = getrandom(seed, sizeof(seed), GRND_RANDOM);
    // Any error to report?
    if (ret < 0)
    {
        // Debug message
        TRACE_ERROR("Error: Failed to generate random data (%d)\r\n", errno);
        // Exit immediately
        return ERROR_FAILURE;
    }

    // PRNG initialization
    error = yarrowInit(&yarrowContext);
    // Any error to report?
    if (error)
    {
        // Debug message
        TRACE_ERROR("Error: PRNG initialization failed (%d)\r\n", error);
        // Exit immediately
        return ERROR_FAILURE;
    }

    // Properly seed the PRNG
    error = yarrowSeed(&yarrowContext, seed, sizeof(seed));
    // Any error to report?
    if (error)
    {
        // Debug message
        TRACE_ERROR("Error: Failed to seed PRNG (%d)\r\n", error);
        // Exit immediately
        return error;
    }

    // Start of exception handling block
    do
    {
        // Debug message
        TRACE_INFO("Loading certificates...\r\n");

        // Load trusted CA certificates
        error = readPemFile(APP_CA_CERT_BUNDLE, &trustedCaList,
                            &trustedCaListLen, "CERTIFICATE");
        // Any error to report?
        if (error)
            break;

        // Load client's certificate
        error = readPemFile(APP_CLIENT_CERT, &clientCert, &clientCertLen, "CERTIFICATE");
        // Any error to report?
        if (error)
            break;

        // Load client's private key
        error = readPemFile(APP_CLIENT_PRIVATE_KEY, &clientPrivateKey,
                            &clientPrivateKeyLen, "RSA PRIVATE KEY");
        // Any error to report?
        if (error)
            break;

        error = cloud_request_get(NULL, 0, request, hash);

    } while (0);

    // Free previously allocated resources
    free(trustedCaList);
    free(clientCert);
    free(clientPrivateKey);

    // Release PRNG context
    yarrowRelease(&yarrowContext);

    // Return status code
    return error;
}