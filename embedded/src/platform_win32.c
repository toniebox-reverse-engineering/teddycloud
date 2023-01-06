
#ifdef _WIN32

#include <stdlib.h>
#include "tls.h"
#include "pem_export.h"
#include "tls_cipher_suites.h"
#include "rng/yarrow.h"
#include "debug.h"

#pragma comment(lib, "ws2_32.lib")

int main_win32()
{
    WSADATA wsaData;
    HCRYPTPROV hProvider;

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
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
    int_t ret;

    // Acquire cryptographic context
    ret = CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    // Any error to report?
    if (!ret)
    {
        // Debug message
        TRACE_ERROR("Error: Cannot acquire cryptographic context (%d)\r\n", GetLastError());
        // Exit immediately
        return -1;
    }

    // Generate a random seed
    ret = CryptGenRandom(hProvider, sizeof(seed), seed);
    // Any error to report?
    if (!ret)
    {
        // Debug message
        TRACE_ERROR("Error: Failed to generate random data (%d)\r\n", GetLastError());
        // Exit immediately
        return -1;
    }

    // Release cryptographic context
    CryptReleaseContext(hProvider, 0);

    return 0;
}
#endif
