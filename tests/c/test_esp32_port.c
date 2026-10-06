#include <assert.h>
#include <string.h>

#include "esp32_port.h"
#include "tests.h"

/* the connect function of v5.237.0, with the bytes outside the patterns zeroed */
static const uint8_t function_start[] = {
    0x36, 0x21, 0x01, 0x72, 0x61, 0x19, 0x62, 0x61, 0x18, 0x25, 0xe1, 0x3c,
    0x20, 0x72, 0x20, 0x61, 0xe6, 0xac, 0x40, 0x40, 0xf4, 0xa0, 0x2a, 0x20};
static const uint8_t function_tail[] = {
    0x82, 0xae, 0x45, 0x0c, 0x15, 0x8a, 0x84, 0x99, 0x21, 0x52, 0x41, 0x34,
    0x92, 0x21, 0x16, 0x0c, 0x15, 0x80, 0x57, 0x83, 0xa9, 0x11, 0xad, 0x03};

#define FUNCTION_AT 0x100

static void place_function(uint8_t *image, size_t size)
{
    memset(image, 0, size);
    memcpy(&image[FUNCTION_AT], function_start, sizeof(function_start));
    memcpy(&image[FUNCTION_AT + 0xd2], function_tail, sizeof(function_tail));
}

static void assert_code(const uint8_t *image, size_t offset, uint8_t b0, uint8_t b1, uint8_t b2)
{
    const uint8_t *code = &image[FUNCTION_AT + offset];
    assert(code[0] == b0 && code[1] == b1 && code[2] == b2);
}

void test_esp32_port_patch(void)
{
    uint8_t image[0x400], original[sizeof(image)];
    place_function(image, sizeof(image));
    memcpy(original, image, sizeof(image));

    assert(esp32_port_patch(image, sizeof(image), 8443) == 1);
    assert_code(image, 0x12, 0x42, 0xa0, 0xfb); /* movi a4, 0xfb */
    assert_code(image, 0xd2, 0x42, 0xd4, 0x20); /* addmi a4, a4, 0x2000 */
    assert_code(image, 0xe3, 0x52, 0xa0, 0x00); /* movi a5, 0 */

    assert(esp32_port_patch(image, sizeof(image), 1443) == 1);
    assert_code(image, 0x12, 0x42, 0xa0, 0xa3);
    assert_code(image, 0xd2, 0x42, 0xd4, 0x05);

    assert(esp32_port_patch(image, sizeof(image), 443) == 1);
    assert(memcmp(image, original, sizeof(image)) == 0);

    image[FUNCTION_AT + 0xd2 + 4] ^= 0xff;
    assert(esp32_port_patch(image, sizeof(image), 8443) == 0);

    assert(!esp32_port_supported(0));
    assert(esp32_port_supported(1));
    assert(esp32_port_supported(32767));
    assert(!esp32_port_supported(32768));
}
