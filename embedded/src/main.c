
// Platform-specific dependencies
#include <sys/types.h>
#include <stdlib.h>

#include "error.h"
#include "debug.h"

#include "tls_adapter.h"
#include "cloud_request.h"

void platform_init(void);
void platform_deinit(void);

int_t main(int argc, char *argv[])
{
    error_t error;

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

    TRACE_INFO("\r\n");

    /* platform specific init */
    platform_init();

    /* load certificates and TLS RNG */
    if (tls_adapter_init() != NO_ERROR)
    {
        return -1;
    }

    error = cloud_request_get(NULL, 0, request, hash);

    tls_adapter_deinit();
    platform_deinit();

    // Return status code
    return error;
}
