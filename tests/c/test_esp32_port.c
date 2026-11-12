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

/* the reachability check of v5.237.0 */
static const uint8_t check_function[] = {
    0x36, 0x41, 0x00, 0x65, 0x86, 0x21, 0xc2, 0xa7, 0x53, 0xe0, 0xcc, 0x11,
    0xb2, 0xa1, 0xbb, 0x16, 0x1a, 0x01, 0xa1, 0xde, 0xd4, 0xa5, 0x41, 0x21,
    0x22, 0xa0, 0x00, 0xcc, 0x3a, 0x65, 0x09, 0x0d, 0x0c, 0x12, 0x1d, 0xf0};

#define CHECK_AT 0x80

/* the port and timeout the patched code computes: movi a11, addmi a11, addmi a12 */
static void assert_check_args(const uint8_t *image, int port)
{
    const uint8_t *args = &image[CHECK_AT + 6];
    assert(args[0] == 0xb2 && args[1] == 0xa0 && args[3] == 0xb2 && args[4] == 0xdb && args[6] == 0xc2 && args[7] == 0xdb);
    int a11 = args[2] + (int8_t)args[5] * 0x100;
    int a12 = a11 + (int8_t)args[8] * 0x100;
    assert(a11 == port);
    assert(a12 >= 7500 - 128 && a12 <= 7500 + 128);
}

void test_esp32_port_patch_check(void)
{
    uint8_t image[0x100], original[sizeof(image)];
    memset(image, 0, sizeof(image));
    memcpy(&image[CHECK_AT], check_function, sizeof(check_function));
    memcpy(original, image, sizeof(image));

    assert(esp32_port_patch_check(image, sizeof(image), 10443) == 1);
    assert_check_args(image, 10443);
    assert(memcmp(&image[CHECK_AT + 15], &original[CHECK_AT + 15], sizeof(check_function) - 15) == 0);

    assert(esp32_port_patch_check(image, sizeof(image), 1) == 1);
    assert_check_args(image, 1);
    assert(esp32_port_patch_check(image, sizeof(image), 32767) == 1);
    assert_check_args(image, 32767);

    assert(esp32_port_patch_check(image, sizeof(image), 443) == 1);
    assert(memcmp(image, original, sizeof(image)) == 0);

    image[CHECK_AT + 0x20] ^= 0xff;
    assert(esp32_port_patch_check(image, sizeof(image), 10443) == 0);
}
