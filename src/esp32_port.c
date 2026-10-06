#include "esp32_port.h"

#include <string.h>

/* The connect function of the box firmware (v5.231.0 to v5.237.0) passes the
 * port to esp_tls_conn_new_sync() and uses TLS only for port 443. */

#define ANY -1
#define CODE_SIZE 3

static const int16_t function_start[] = {
    0x36, 0x21, 0x01, 0x72, 0x61, 0x19, 0x62, 0x61, 0x18, ANY, ANY, ANY,
    0x20, 0x72, 0x20, 0x61, ANY, ANY, ANY, ANY, ANY, 0xa0, 0x2a, 0x20};

#define TAIL_OFFSET 0xd2
static const int16_t function_tail[] = {
    ANY, ANY, ANY, 0x0c, 0x15, 0x8a, 0x84, 0x99, 0x21, 0x52, 0x41, 0x34,
    0x92, 0x21, 0x16, 0x0c, 0x15, ANY, ANY, ANY, 0xa9, 0x11, 0xad, 0x03};

#define FUNCTION_LENGTH (TAIL_OFFSET + sizeof(function_tail) / sizeof(function_tail[0]))

typedef struct
{
    size_t offset;
    uint8_t original[CODE_SIZE];
    uint8_t patched_prefix[2];
} site_t;

static const site_t sites[] = {
    {0x12, {0x40, 0x40, 0xf4}, {0x42, 0xa0}}, /* extui a4, a4, 0, 16  ->  movi a4, port & 0xff */
    {0xd2, {0x82, 0xae, 0x45}, {0x42, 0xd4}}, /* movi a8, -443        ->  addmi a4, a4, port & 0xff00 */
    {0xe3, {0x80, 0x57, 0x83}, {0x52, 0xa0}}, /* moveqz a5, a7, a8    ->  movi a5, 0 (TLS on) */
};
#define SITE_COUNT (sizeof(sites) / sizeof(sites[0]))

bool esp32_port_supported(uint32_t port)
{
    return port >= 1 && port <= 0x7fff;
}

static bool matches(const uint8_t *data, const int16_t *pattern, size_t length)
{
    for (size_t pos = 0; pos < length; pos++)
    {
        if (pattern[pos] != ANY && data[pos] != pattern[pos])
        {
            return false;
        }
    }
    return true;
}

static bool is_connect_function(const uint8_t *function)
{
    if (!matches(function, function_start, sizeof(function_start) / sizeof(function_start[0])) ||
        !matches(&function[TAIL_OFFSET], function_tail, sizeof(function_tail) / sizeof(function_tail[0])))
    {
        return false;
    }
    for (size_t i = 0; i < SITE_COUNT; i++)
    {
        const uint8_t *code = &function[sites[i].offset];
        if (memcmp(code, sites[i].original, CODE_SIZE) != 0 && memcmp(code, sites[i].patched_prefix, 2) != 0)
        {
            return false;
        }
    }
    return true;
}

int esp32_port_patch(uint8_t *image, size_t length, uint16_t port)
{
    const uint8_t patched[SITE_COUNT][CODE_SIZE] = {
        {0x42, 0xa0, port & 0xff},
        {0x42, 0xd4, port >> 8},
        {0x52, 0xa0, 0x00},
    };
    int count = 0;

    for (size_t pos = 0; pos + FUNCTION_LENGTH <= length; pos++)
    {
        uint8_t *function = &image[pos];
        if (!is_connect_function(function))
        {
            continue;
        }
        for (size_t i = 0; i < SITE_COUNT; i++)
        {
            memcpy(&function[sites[i].offset], port == 443 ? sites[i].original : patched[i], CODE_SIZE);
        }
        count++;
    }
    return count;
}
