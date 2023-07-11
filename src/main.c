
// Platform-specific dependencies
#include <sys/types.h>
#include <stdlib.h>

#include "error.h"
#include "debug.h"

#include "tls_adapter.h"
#include "cloud_request.h"

#include "settings.h"

void platform_init(void);
void platform_deinit(void);
void server_init(void);

int_t main(int argc, char *argv[])
{
    error_t error = 0;

    /* platform specific init */
    settings_init();
    platform_init();

    /* load certificates and TLS RNG */
    if (tls_adapter_init() != NO_ERROR)
    {
        TRACE_ERROR("tls_adapter_init() failed\r\n");
        return -1;
    }

    if (argc > 1)
    {
        TRACE_INFO("**********************************\r\n");
        TRACE_INFO("***       Cloud API test       ***\r\n");
        TRACE_INFO("**********************************\r\n");
        TRACE_INFO("\r\n");

        char *request = NULL;
        uint8_t *hash = NULL;

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
            hash = (uint8_t *)argv[2];
            TRACE_ERROR("Hash: %s\r\n", hash);
        }

        TRACE_INFO("\r\n");

        error = cloud_request_get(NULL, 0, request, hash, NULL);
    }
    else
    {
        server_init();
    }

    tls_adapter_deinit();
    platform_deinit();
    // Return status code
    return error;
}
