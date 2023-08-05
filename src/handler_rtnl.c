#ifdef WIN32
#else
#include <unistd.h>
#endif

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "mutex_manager.h"
#include "handler_sse.h"
#include "handler_rtnl.h"
#include "settings.h"
#include "stats.h"
#include "mqtt.h"
#include "fs_ext.h"
#include "cloud_request.h"

#include "proto/toniebox.pb.rtnl.pb-c.h"

static void escapeString(const char_t *input, size_t size, char_t *output);
static void escapeString(const char_t *input, size_t size, char_t *output)
{
    // Replacement sequences for special characters
    const char_t *replacements[] = {
        "\"", "\"\"", // Double quote (")
        "\n", "\\n",  // Newline
        "\r", "\\r"   // Carriage return
    };
    const size_t num_replacements = sizeof(replacements) / sizeof(replacements[0]);

    size_t input_length = size;
    size_t escaped_length = 0;

    // First pass to count the number of additional characters required for escaping
    for (size_t i = 0; i < input_length; i++)
    {
        for (size_t j = 0; j < num_replacements; j++)
        {
            if (input[i] == replacements[j][0])
            {
                escaped_length += osStrlen(replacements[j]) - 1;
                break;
            }
        }
    }

    size_t j = 0;
    // Second pass to actually escape the characters
    for (size_t i = 0; i < input_length; i++)
    {
        bool_t replaced = false;
        for (size_t k = 0; k < num_replacements; k++)
        {
            if (input[i] == replacements[k][0])
            {
                size_t len = osStrlen(replacements[k]);
                osStrcpy(&output[j], replacements[k]);
                j += len;
                replaced = true;
                break;
            }
        }

        if (!replaced)
        {
            if (isalnum(input[i]))
            {
                output[j++] = input[i];
            }
            else
            {
                output[j++] = '.';
            }
        }
    }

    // Null-terminate the escaped string
    output[j] = '\0';
}

error_t handleRtnl(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char_t *buffer = connection->buffer;
    size_t size = connection->response.contentLength;

    size_t pos = 0;
    do
    {
        /* check for enough data for the length header */
        if (pos + 4 > size)
        {
            break;
        }
        uint32_t protoLength = (uint32_t)((buffer[pos] << 24) | (buffer[pos + 1] << 16) | (buffer[pos + 2] << 8) | buffer[pos + 3]);

        if (pos + 4 + protoLength > size)
        {
            break;
        }

        /* check if we have enough data but not too much for the packet we seem to have there.
           do some safety checks */
        if (protoLength == 0 || buffer[pos] != 0 || buffer[pos + 1] != 0)
        {
            TRACE_WARNING("Invalid protoLen=%" PRIu32 ", pos=%" PRIuSIZE "\r\n", protoLength, pos);
            return ERROR_FAILURE;
        }

        /* there is enough bytes for that packet */
        if (client_ctx->settings->rtnl.logRaw)
        {
            mutex_lock(MUTEX_RTNL_FILE);
            FsFile *file = fsOpenFileEx(client_ctx->settings->rtnl.logRawFile, "ab");
            if (file)
            {
                fsWriteFile(file, &buffer[pos], 4 + protoLength);
                fsCloseFile(file);
            }
            mutex_unlock(MUTEX_RTNL_FILE);
        }

        pos += 4;
        TonieRtnlRPC *rpc = tonie_rtnl_rpc__unpack(NULL, protoLength, (const uint8_t *)&buffer[pos]);

        pos += protoLength;
        if (rpc && (rpc->log2 || rpc->log3))
        {
            rtnlEvent(rpc);
            rtnlEventLog(rpc);
            rtnlEventDump(rpc, client_ctx->settings);
        }
        tonie_rtnl_rpc__free_unpacked(rpc, NULL);
    } while (true);

    /* move left-over data to the start of the buffer */
    connection->response.byteCount = size - pos;
    osMemmove(buffer, &buffer[pos], connection->response.byteCount);

    return NO_ERROR;
}

int32_t read_little_endian(const uint8_t *buf)
{
    return (int32_t)(buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24);
}

void rtnlEvent(TonieRtnlRPC *rpc)
{
    char_t buffer[4096];
    if (rpc->log2)
    {
        sse_startEventRaw("rtnl-raw-log2");
        osSprintf(buffer, "{\"uptime\": %" PRIu64 ", "
                          "\"sequence\": %" PRIu32 ", "
                          "\"field3\": %" PRIu32 ", "
                          "\"function_group\": %" PRIu32 ", "
                          "\"function\": %" PRIu32 ", "
                          "\"field6\": \"",
                  rpc->log2->uptime,
                  rpc->log2->sequence,
                  rpc->log2->field3,
                  rpc->log2->function_group,
                  rpc->log2->function);
        sse_rawData(buffer);

        if (rpc->log2->field6.len > 0)
        {
            for (size_t i = 0; i < rpc->log2->field6.len; i++)
            {
                osSprintf(&buffer[i * 2], "%02X", rpc->log2->field6.data[i]);
            }
            sse_rawData(buffer);
        }

        osSprintf(buffer, "\","
                          "\"field8\": %" PRIu32 ", "
                          "\"field9\": \"",
                  rpc->log2->field8);
        sse_rawData(buffer);

        if (rpc->log2->field9.len > 0)
        {
            for (size_t i = 0; i < rpc->log2->field9.len; i++)
            {
                osSprintf(&buffer[i * 2], "%02X", rpc->log2->field9.data[i]);
            }
            sse_rawData(buffer);
        }
        sse_rawData("\"}");

        sse_endEventRaw();
    }

    if (rpc->log3)
    {
        sse_startEventRaw("rtnl-raw-log3");
        osSprintf(buffer, "{\"datetime\": %" PRIu32 ", "
                          "\"field2\": %" PRIu32 "}",
                  rpc->log3->datetime,
                  rpc->log3->field2);
        sse_rawData(buffer);
        sse_endEventRaw();
    }

    if (rpc->log3)
    {
        switch (rpc->log3->field2)
        {
        case 1:
            sse_sendEvent("pressed", "ear-big", true);
            mqtt_sendEvent("VolUp", "ON");
            mqtt_sendEvent("VolUp", "OFF");
            break;
        case 2:
            sse_sendEvent("pressed", "ear-small", true);
            mqtt_sendEvent("VolDown", "ON");
            mqtt_sendEvent("VolDown", "OFF");
            break;
        case 3:
            sse_sendEvent("knock", "forward", true);
            mqtt_sendEvent("KnockForward", "ON");
            mqtt_sendEvent("KnockForward", "OFF");
            break;
        case 4:
            sse_sendEvent("knock", "backward", true);
            mqtt_sendEvent("KnockBackward", "ON");
            mqtt_sendEvent("KnockBackward", "OFF");
            break;
        case 5:
            sse_sendEvent("tilt", "forward", true);
            mqtt_sendEvent("TiltForward", "ON");
            mqtt_sendEvent("TiltForward", "OFF");
            break;
        case 6:
            sse_sendEvent("tilt", "backward", true);
            mqtt_sendEvent("TiltBackward", "ON");
            mqtt_sendEvent("TiltBackward", "OFF");
            break;
        case 11:
            sse_sendEvent("playback", "starting", true);
            mqtt_sendEvent("Playback", "ON");
            mqtt_sendEvent("TagInvalid", "");
            break;
        case 12:
            sse_sendEvent("playback", "started", true);
            mqtt_sendEvent("Playback", "ON");
            mqtt_sendEvent("TagInvalid", "");
            break;
        case 13:
            sse_sendEvent("playback", "stopped", true);
            mqtt_sendEvent("Playback", "OFF");
            mqtt_sendEvent("TagValid", "");
            mqtt_sendEvent("TagInvalid", "");
            break;
        default:
            TRACE_WARNING("Not-yet-known log3 type: %d\r\n", rpc->log3->field2);
            break;
        }
    }

    if (rpc->log2)
    {
        char buffer[33];

        /* ESP32 sends tag IDs, even if unknown */
        if (rpc->log2->function_group == 15 && rpc->log2->function == 15452)
        {
            if (rpc->log2->field6.len == 8)
            {
                for (size_t i = 0; i < rpc->log2->field6.len; i++)
                {
                    osSprintf(&buffer[i * 2], "%02X", rpc->log2->field6.data[(i + 4) % 8]);
                }
            }
            sse_sendEvent("TagInvalid", buffer, true);
            mqtt_sendEvent("TagInvalid", buffer);
            mqtt_sendEvent("TagValid", "");
        }
        else if (rpc->log2->function_group == 15 && rpc->log2->function == 16065)
        {
            if (rpc->log2->field6.len == 8)
            {
                for (size_t i = 0; i < rpc->log2->field6.len; i++)
                {
                    osSprintf(&buffer[i * 2], "%02X", rpc->log2->field6.data[(i + 4) % 8]);
                }
            }
            sse_sendEvent("TagValid", buffer, true);
            mqtt_sendEvent("TagValid", buffer);
            mqtt_sendEvent("TagInvalid", "");
        }
        /* CC also sends messages */
        else if (rpc->log2->function_group == 15 && rpc->log2->function == 8646)
        {
            if (rpc->log2->field6.len == 8)
            {
                for (size_t i = 0; i < rpc->log2->field6.len; i++)
                {
                    osSprintf(&buffer[i * 2], "%02X", rpc->log2->field6.data[(i + 4) % 8]);
                }
            }
            sse_sendEvent("TagInvalid", buffer, true);
            mqtt_sendEvent("TagInvalid", buffer);
            mqtt_sendEvent("TagValid", "");
        }
        else if (rpc->log2->function_group == 15 && rpc->log2->function == 8627)
        {
            if (rpc->log2->field6.len == 8)
            {
                for (size_t i = 0; i < rpc->log2->field6.len; i++)
                {
                    osSprintf(&buffer[i * 2], "%02X", rpc->log2->field6.data[(i + 4) % 8]);
                }
            }
            sse_sendEvent("TagValid", buffer, true);
            mqtt_sendEvent("TagValid", buffer);
            mqtt_sendEvent("TagInvalid", "");
        }
        else if (rpc->log2->function_group == 12 && rpc->log2->function == 15427)
        {
            int32_t angle = read_little_endian(rpc->log2->field6.data);
            osSprintf(buffer, "%d", angle);
            sse_sendEvent("BoxTilt", buffer, true);
            mqtt_sendEvent("BoxTilt", buffer);
        }
        else if (rpc->log2->function_group == 12 && rpc->log2->function == 15426)
        {
            int32_t angle = read_little_endian(rpc->log2->field6.data);
            osSprintf(buffer, "%d", angle);
            sse_sendEvent("BoxTilt", buffer, true);
            mqtt_sendEvent("BoxTilt", buffer);
        }
    }
}

void rtnlEventLog(TonieRtnlRPC *rpc)
{
    TRACE_DEBUG("RTNL: \r\n");
    if (rpc->log2)
    {
        TRACE_DEBUG(" LOG2:\r\n");
        TRACE_DEBUG("  uptime=%" PRIu64 "\r\n", rpc->log2->uptime);
        TRACE_DEBUG("  sequence=%" PRIu32 "\r\n", rpc->log2->sequence);
        TRACE_DEBUG("  3=%" PRIu32 "\r\n", rpc->log2->field3);
        TRACE_DEBUG("  group=%" PRIu32 "\r\n", rpc->log2->function_group);
        TRACE_DEBUG("  function=%" PRIu32 "\r\n", rpc->log2->function);
        TRACE_DEBUG("  6=len(data)=%" PRIuSIZE ", data=", rpc->log2->field6.len);
        for (size_t i = 0; i < rpc->log2->field6.len; i++)
        {
            TRACE_DEBUG_RESUME("%02X", rpc->log2->field6.data[i]);
        }
        TRACE_DEBUG_RESUME(", txt=%s\r\n", rpc->log2->field6.data);
        if (rpc->log2->has_field8)
            TRACE_DEBUG("  8=%" PRIu32 "\r\n", rpc->log2->field8);
        if (rpc->log2->has_field9)
        {
            TRACE_DEBUG("  9=len(data)=%" PRIuSIZE ", data=", rpc->log2->field9.len);
            for (size_t i = 0; i < rpc->log2->field9.len; i++)
            {
                TRACE_DEBUG_RESUME("%02X", rpc->log2->field9.data[i]);
            }
            TRACE_DEBUG_RESUME(", txt=%s\r\n", rpc->log2->field9.data);
        }
    }
    if (rpc->log3)
    {
        TRACE_DEBUG(" LOG3:\r\n");
        TRACE_DEBUG("  datetime=%" PRIu32 "\r\n", rpc->log3->datetime);
        TRACE_DEBUG("  2=%" PRIu32 "\r\n", rpc->log3->field2);
    }
}

void rtnlEventDump(TonieRtnlRPC *rpc, settings_t *settings)
{
    if (settings->rtnl.logHuman)
    {
        bool_t addHeader = !fsFileExists(settings->rtnl.logHumanFile);
        FsFile *file = fsOpenFileEx(settings->rtnl.logHumanFile, "ab");
        if (addHeader)
        {
            char_t *header = "timestamp;log2;uptime;sequence;3;group;function;6(len);6(bytes);6(string);8;9(len);9(bytes);9(string);log3;datetime;2\r\n";
            fsWriteFile(file, header, osStrlen(header));
        }
        char_t buffer[4096];
        osSprintf(buffer, "%" PRIuTIME ";", time(NULL));
        fsWriteFile(file, buffer, osStrlen(buffer));

        if (rpc->log2)
        {
            osSprintf(buffer, "x;%" PRIu64 ";%" PRIu32 ";%" PRIu32 ";%" PRIu32 ";%" PRIu32 ";%" PRIuSIZE ";",
                      rpc->log2->uptime,
                      rpc->log2->sequence,
                      rpc->log2->field3,
                      rpc->log2->function_group,
                      rpc->log2->function,
                      rpc->log2->field6.len);
            fsWriteFile(file, buffer, osStrlen(buffer));

            if (rpc->log2->field6.len > 0)
            {
                for (size_t i = 0; i < rpc->log2->field6.len; i++)
                {
                    osSprintf(&buffer[i * 2], "%02X", rpc->log2->field6.data[i]);
                }
                fsWriteFile(file, buffer, osStrlen(buffer));
            }

            osSprintf(buffer, ";\"");
            escapeString((char_t *)rpc->log2->field6.data, rpc->log2->field6.len, &buffer[2]);
            fsWriteFile(file, buffer, osStrlen(buffer));

            osSprintf(buffer, "\";%" PRIu32 ";%" PRIuSIZE ";",
                      rpc->log2->field8, // TODO hasfield
                      rpc->log2->field9.len);
            fsWriteFile(file, buffer, osStrlen(buffer));

            if (rpc->log2->has_field9)
            {
                if (rpc->log2->field9.len > 0)
                {
                    for (size_t i = 0; i < rpc->log2->field9.len; i++)
                    {
                        osSprintf(&buffer[i * 2], "%02X", rpc->log2->field9.data[i]);
                    }
                    fsWriteFile(file, buffer, osStrlen(buffer));
                }
                osSprintf(buffer, ";\"");
                escapeString((char_t *)rpc->log2->field9.data, rpc->log2->field9.len, &buffer[2]);
                fsWriteFile(file, buffer, osStrlen(buffer));
                char_t *output = "\";";
                fsWriteFile(file, output, osStrlen(output));
            }
            else
            {
                char_t *output = ";;";
                fsWriteFile(file, output, osStrlen(output));
            }
        }
        else
        {
            char_t *output = ";;;;;;;;;;;;;";
            fsWriteFile(file, output, osStrlen(output));
        }

        if (rpc->log3)
        {
            osSprintf(buffer, "x;%" PRIu32 ";%" PRIu32 "\r\n",
                      rpc->log3->datetime,
                      rpc->log3->field2);
            fsWriteFile(file, buffer, osStrlen(buffer));
        }
        else
        {
            char_t *output = ";;\r\n";
            fsWriteFile(file, output, osStrlen(output));
        }
        fsCloseFile(file);
    }
}