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
#define _CRTDBG_MAP_ALLOC
#define _WINERROR_
#include <crtdbg.h>
#include <winsock2.h>
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
#include "tls.h"
#include "pem_export.h"
#include "tls_cipher_suites.h"
#include "rng/yarrow.h"
#include "debug.h"

// Libraries
#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

// Platform-specific dependencies
#ifndef _WIN32
#define SOCKET intptr_t
#define SOCKET_ERROR -1
#define SOCKADDR_IN struct sockaddr_in
#define PSOCKADDR struct sockaddr *
#define HOSTENT struct hostent
#define closesocket close
#endif

// Server hostname and port
#define APP_SERVER_NAME "prod.de.tbs.toys"
#define APP_SERVER_PORT 443
#define APP_REQUEST_URI "/v2/content/aa760e1a500304e0"

// Compilation options
#define APP_SET_CIPHER_SUITES DISABLED
#define APP_SET_SERVER_NAME ENABLED
#define APP_SET_TRUSTED_CA_LIST ENABLED
#define APP_SET_CLIENT_CERT ENABLED
#define APP_SET_PSK DISABLED

// Trusted CA bundle
#define APP_CA_CERT_BUNDLE "certs/ca.der"

// Client's certificate and private key
#define APP_CLIENT_CERT "certs/client.der"
#define APP_CLIENT_PRIVATE_KEY "certs/private.der"

// Client's PSK identity
#define APP_CLIENT_PSK_IDENTITY "Client1"

// Client's PSK
const uint8_t clientPsk[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

// List of preferred ciphersuites
const uint16_t cipherSuites[] =
    {
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};

// Forward declaration of functions
error_t readPemFile(const char_t *filename, char_t **buffer, size_t *length, const char_t *type);

error_t tlsSendCallback(TlsSocketHandle socket, const void *data,
                        size_t length, size_t *written, uint_t flags);

error_t tlsReceiveCallback(TlsSocketHandle socket, void *data,
                           size_t size, size_t *received, uint_t flags);

/**
 * @brief Main entry point
 * @return Status code
 **/

int_t main(int argc, char *argv[])
{
    error_t error;
    size_t length;
    int_t ret;
#ifdef _WIN32
    WSADATA wsaData;
    HCRYPTPROV hProvider;
#endif
    HOSTENT *host;
    SOCKADDR_IN addr;
    YarrowContext yarrowContext;
    char_t buffer[512];
    uint8_t seed[32];

    // Socket descriptor
    SOCKET sock = SOCKET_ERROR;

    // TLS context
    TlsContext *tlsContext = NULL;

    // Credentials
    char_t *clientCert = NULL;
    size_t clientCertLen = 0;
    char_t *clientPrivateKey = NULL;
    size_t clientPrivateKeyLen = 0;
    char_t *trustedCaList = NULL;
    size_t trustedCaListLen = 0;

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

#ifdef _WIN32
    // Acquire cryptographic context
    ret = CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    // Any error to report?
    if (!ret)
    {
        // Debug message
        TRACE_ERROR("Error: Cannot acquire cryptographic context (%d)\r\n", GetLastError());
        // Exit immediately
        return ERROR_FAILURE;
    }

    // Generate a random seed
    ret = CryptGenRandom(hProvider, sizeof(seed), seed);
    // Any error to report?
    if (!ret)
    {
        // Debug message
        TRACE_ERROR("Error: Failed to generate random data (%d)\r\n", GetLastError());
        // Exit immediately
        return ERROR_FAILURE;
    }

    // Release cryptographic context
    CryptReleaseContext(hProvider, 0);
#else
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
#endif

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

#ifdef _WIN32
    // Winsock initialization
    ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    // Any error to report?
    if (ret)
    {
        // Debug message
        TRACE_ERROR("Error: Winsock initialization failed (%d)\r\n", ret);
        // Exit immediately
        return ERROR_FAILURE;
    }
#endif

    // Start of exception handling block
    do
    {
        // Debug message
        TRACE_INFO("Loading credentials...\r\n");

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

        // Debug message
        TRACE_INFO("Trying to resolve %s...\r\n", APP_SERVER_NAME);

        // Resolve server name
        host = gethostbyname(APP_SERVER_NAME);
        // Failed to resolve server name?
        if (!host)
        {
            // Debug message
            TRACE_ERROR("Error: Cannot resolve server name\r\n");
            // Report an error
            error = ERROR_FAILURE;
            // Exit immediately
            break;
        }

        // Open a socket
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        // Failed to open socket?
        if (sock < 0)
        {
            // Debug message
            TRACE_ERROR("Error: Cannot open socket\r\n");
            // Report an error
            error = ERROR_FAILURE;
            // Exit immediately
            break;
        }

        // Destination address
        addr.sin_family = host->h_addrtype;
        memcpy(&addr.sin_addr, host->h_addr, host->h_length);
        addr.sin_port = htons(APP_SERVER_PORT);

        TRACE_INFO("Connecting...\r\n");
        // Connect to the SSL server
        ret = connect(sock, (PSOCKADDR)&addr, sizeof(addr));
        // Connection with server failed?
        if (ret < 0)
        {
            // Debug message
            TRACE_ERROR("Error: Failed to connect\r\n");
            // Report an error
            error = ERROR_FAILURE;
            // Exit immediately
            break;
        }

        TRACE_INFO("Initializing TLS...\r\n");
        // Initialize TLS context
        tlsContext = tlsInit();
        // Initialization failed?
        if (!tlsContext)
        {
            // Report an error
            error = ERROR_OUT_OF_MEMORY;
            // Exit immediately
            break;
        }

        // Set send and receive callbacks (I/O abstraction layer)
        error = tlsSetSocketCallbacks(tlsContext, tlsSendCallback,
                                      tlsReceiveCallback, (TlsSocketHandle)sock);
        // Any error to report?
        if (error)
            break;

        // Select client operation mode
        error = tlsSetConnectionEnd(tlsContext, TLS_CONNECTION_END_CLIENT);
        // Any error to report?
        if (error)
            break;

        // Set the PRNG algorithm to be used
        error = tlsSetPrng(tlsContext, YARROW_PRNG_ALGO, &yarrowContext);
        // Any error to report?
        if (error)
            break;

#if (APP_SET_CIPHER_SUITES == ENABLED)
        // Preferred cipher suite list
        error = tlsSetCipherSuites(tlsContext, cipherSuites,
                                   arraysize(cipherSuites));
        // Any error to report?
        if (error)
            break;
#endif

#if (APP_SET_SERVER_NAME == ENABLED)
        // Set the fully qualified domain name of the server
        error = tlsSetServerName(tlsContext, APP_SERVER_NAME);
        // Any error to report?
        if (error)
            break;
#endif

#if (APP_SET_TRUSTED_CA_LIST == ENABLED)
        // Import the list of trusted CA certificates
        error = tlsSetTrustedCaList(tlsContext, trustedCaList, trustedCaListLen);
        // Any error to report?
        if (error)
            break;
#endif

#if (APP_SET_CLIENT_CERT == ENABLED)
        // Import the client's certificate
        error = tlsAddCertificate(tlsContext, clientCert, clientCertLen,
                                  clientPrivateKey, clientPrivateKeyLen);
        // Any error to report?
        if (error)
            break;
#endif

#if (APP_SET_PSK == ENABLED)
        // Set the PSK identity to be used by the client
        error = tlsSetPskIdentity(tlsContext, APP_CLIENT_PSK_IDENTITY);
        // Any error to report?
        if (error)
            break;

        // Set the pre-shared key to be used
        error = tlsSetPsk(tlsContext, clientPsk, sizeof(clientPsk));
        // Any error to report?
        if (error)
            break;
#endif

        // Establish a secure session
        error = tlsConnect(tlsContext);
        // TLS handshake failure?
        if (error)
            break;

        char auth[128];

        if(hash)
        {
            sprintf(auth, "Authorization: BD %s\r\n", hash);
        }

        // Format HTTP request
        sprintf(buffer, "GET %s HTTP/1.0\r\nHost: %s:%u\r\n%s\r\n",
                request, APP_SERVER_NAME, APP_SERVER_PORT, auth);

        // Debug message
        printf("\r\n");
        printf("HTTP request:\r\n");
        printf("---------------------------------------------\r\n");
        printf("%s", buffer);
        printf("---------------------------------------------\r\n");

        // Send the request
        error = tlsWrite(tlsContext, buffer, strlen(buffer), NULL, 0);
        // Any error to report?
        if (error)
            break;

        // Debug message
        printf("\r\n");
        printf("HTTP response:\r\n");
        printf("---------------------------------------------\r\n");

        // Read the whole response
        while (1)
        {
            // Read data
            error = tlsRead(tlsContext, buffer, sizeof(buffer) - 1, &length, 0);
            // End of stream?
            if (error)
                break;

            // Properly terminate the string with a NULL character
            buffer[length] = '\0';
            // Debug message
            printf("%s", buffer);
        }
        printf("---------------------------------------------\r\n");

        // Terminate TLS session
        error = tlsShutdown(tlsContext);
        // Any error to report?
        if (error)
            break;

        // End of exception handling block
    } while (0);

    // Release TLS context
    tlsFree(tlsContext);

    // Close socket if necessary
    if (sock >= 0)
        closesocket(sock);

    // Free previously allocated resources
    free(trustedCaList);
    free(clientCert);
    free(clientPrivateKey);

    // Release PRNG context
    yarrowRelease(&yarrowContext);

    // Return status code
    return error;
}

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

/**
 * @brief TLS send callback (I/O abstraction layer)
 * @param[in] socket Handle that identifies a socket
 * @param[in] data Pointer to a buffer containing the data to be transmitted
 * @param[in] length Number of data bytes to send
 * @param[out] written Number of bytes that have been transmitted
 * @param[in] flags Unused parameter
 * @return Error code
 **/

error_t tlsSendCallback(TlsSocketHandle socket, const void *data,
                        size_t length, size_t *written, uint_t flags)
{
    int_t n;
    error_t error;

    // Send data
    n = send((SOCKET)socket, data, length, 0);

    // Check return value
    if (n > 0)
    {
        // Total number of data that have been written
        *written = n;
        // Successful write operation
        error = NO_ERROR;
    }
    else
    {
#if defined(_WIN32)
        // Timeout error?
        if (WSAGetLastError() == WSAEWOULDBLOCK)
            error = ERROR_TIMEOUT;
        else
            error = ERROR_WRITE_FAILED;
#else
        // Timeout error?
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            error = ERROR_TIMEOUT;
        else
            error = ERROR_WRITE_FAILED;
#endif
    }

    // Return status code
    return error;
}

/**
 * @brief TLS receive callback (I/O abstraction layer)
 * @param[in] socket Handle that identifies a socket
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be received
 * @param[out] received Number of bytes that have been received
 * @param[in] flags Unused parameter
 * @return Error code
 **/

error_t tlsReceiveCallback(TlsSocketHandle socket, void *data,
                           size_t size, size_t *received, uint_t flags)
{
    int_t n;
    error_t error;

    // Receive data
    n = recv((SOCKET)socket, data, size, 0);

    // Check return value
    if (n > 0)
    {
        // Total number of data that have been received
        *received = n;
        // Successful write operation
        error = NO_ERROR;
    }
    else
    {
#if defined(_WIN32)
        // Timeout error?
        if (WSAGetLastError() == WSAEWOULDBLOCK)
            error = ERROR_TIMEOUT;
        else
            error = ERROR_READ_FAILED;
#else
        // Timeout error?
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            error = ERROR_TIMEOUT;
        else
            error = ERROR_READ_FAILED;
#endif
    }

    // Return status code
    return error;
}
