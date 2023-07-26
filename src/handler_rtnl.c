
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "handler_rtnl.h"
#include "settings.h"
#include "stats.h"
#include "cloud_request.h"

#include "proto/toniebox.pb.rtnl.pb-c.h"

error_t handleRtnl(HttpConnection *connection, const char_t *uri, const char_t *queryString)
{
    char_t *data = connection->buffer;
    size_t size = connection->response.contentLength;
    /*
    char filename[32] = "";
    sprintf(filename, "tmp/%ld", time(NULL));

    FsFile *file = fsOpenFile(filename, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE);
    fsWriteFile(file, data, size);
    fsCloseFile(file);
    */

    size_t pos = 0;
    // TODO Split messages multiple
    while (size > 4 && pos < (size - 4))
    {
        data = &connection->buffer[pos];
        uint32_t protoLength = (uint32_t)((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
        char_t *protoData = &data[4];
        if (protoLength == 0 || protoLength > 256) // find apropiate size
        {
            pos++;
            continue;
        }
        TonieRtnlRPC *rpc = tonie_rtnl_rpc__unpack(NULL, protoLength, (const uint8_t *)protoData);
        pos += protoLength;
        if (rpc && (rpc->log2 || rpc->log3))
        {
            TRACE_INFO("RTNL: \r\n");
            if (rpc->log2)
            {
                TRACE_INFO(" LOG2:\r\n");
                TRACE_INFO("  1=%lu\r\n", rpc->log2->field1);
                TRACE_INFO("  2=%u\r\n", rpc->log2->field2);
                TRACE_INFO("  3=%u\r\n", rpc->log2->field3);
                TRACE_INFO("  4=%u\r\n", rpc->log2->field4);
                TRACE_INFO("  5=%u\r\n", rpc->log2->field5);
                TRACE_INFO("  6=len(data)=%lu, %s\r\n", rpc->log2->field6.len, rpc->log2->field6.data);
                if (rpc->log2->has_field8)
                    TRACE_INFO("  8=%u\r\n", rpc->log2->field8);
                if (rpc->log2->has_field9)
                    TRACE_INFO("  9=len(data)=%lu, %s\r\n", rpc->log2->field9.len, rpc->log2->field9.data);
            }
            if (rpc->log3)
            {
                TRACE_INFO(" LOG3:\r\n");
                TRACE_INFO("  1=%u\r\n", rpc->log3->field1);
                TRACE_INFO("  2=%u\r\n", rpc->log3->field2);
            }
        }
        tonie_rtnl_rpc__free_unpacked(rpc, NULL);
    }

    return NO_ERROR;
}