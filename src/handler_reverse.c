
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "handler.h"
#include "handler_reverse.h"
#include "settings.h"
#include "stats.h"
#include "cloud_request.h"
#include "os_port.h"
#include "http/http_client.h"

error_t handleReverseCloudGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    cbr_ctx_t cbr_ctx;
    req_cbr_t cbr = getCloudCbr(connection, uri, queryString, API_NONE, &cbr_ctx, client_ctx);

    stats_update("reverse_requests", 1);

    /* here call cloud request, which has to get extended for cbr for header fields and content packets */
    uint8_t *token = connection->private.authentication_token;

    // TODO POST
    error_t error = cloud_request_get(NULL, 0, &uri[8], queryString, token, &cbr);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("cloud_request_get() failed\r\n");
        return error;
    }

    TRACE_DEBUG("httpServerRequestCallback: (waiting)\r\n");
    while (cbr_ctx.status != PROX_STATUS_DONE)
    {
        osDelayTask(50);
    }
    error = httpFlushStream(connection);

    TRACE_DEBUG("httpServerRequestCallback: (done)\r\n");
    return error;
}
