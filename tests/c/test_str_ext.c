#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "str_ext.h"
#include "tests.h"

/* buffers get CANARY_LEN guard bytes behind them to catch writes past the end */
#define CANARY_LEN 8

static void assert_canary(const char *area, size_t size)
{
    for (size_t i = size; i < size + CANARY_LEN; i++)
    {
        assert(area[i] == '#');
    }
}

void test_hex_encode(void)
{
    uint8_t data[1000];
    for (size_t i = 0; i < sizeof(data); i++)
    {
        data[i] = (uint8_t)(i * 7);
    }

    char expected[2 * sizeof(data) + 1];
    for (size_t i = 0; i < sizeof(data); i++)
    {
        snprintf(&expected[2 * i], 3, "%02X", data[i]);
    }

    /* 17 bytes fit 8 encoded bytes and the NUL; larger input comes out in chunks */
    char area[17 + CANARY_LEN];
    char joined[sizeof(expected)] = "";
    size_t pos = 0;
    while (pos < sizeof(data))
    {
        memset(area, '#', sizeof(area));
        size_t n = hexEncode(&data[pos], sizeof(data) - pos, area, 17);
        assert(n > 0 && n <= 8);
        assert(strlen(area) == 2 * n);
        assert_canary(area, 17);
        strcat(joined, area);
        pos += n;
    }
    assert(strcmp(joined, expected) == 0);

    /* an odd size leaves the last byte unused instead of writing half a pair */
    memset(area, '#', sizeof(area));
    assert(hexEncode(data, sizeof(data), area, 4) == 1);
    assert_canary(area, 4);
}

void test_escape_string(void)
{
    char out[64];
    const char input[] = "a\"b\nc\rd\\e f";
    assert(escapeString(input, sizeof(input) - 1, out, sizeof(out)) == sizeof(input) - 1);
    assert(strcmp(out, "a\"\"b\\nc\\rd.e.f") == 0);

    /* every '"' doubles; with 7 bytes, 3 of them fit per chunk, never a half pair */
    char quotes[50];
    memset(quotes, '"', sizeof(quotes));
    char area[7 + CANARY_LEN];
    size_t total = 0;
    size_t pos = 0;
    while (pos < sizeof(quotes))
    {
        memset(area, '#', sizeof(area));
        size_t n = escapeString(&quotes[pos], sizeof(quotes) - pos, area, 7);
        assert(n > 0);
        assert(strlen(area) == 2 * n);
        assert(strspn(area, "\"") == 2 * n);
        assert_canary(area, 7);
        total += strlen(area);
        pos += n;
    }
    assert(total == 2 * sizeof(quotes));
}

static void check_split(const char *url, const char *base, const char *path, const char *query)
{
    char b[32], p[32], q[32];
    assert(split_url(url, b, p, q, sizeof(b)));
    assert(strcmp(b, base) == 0);
    assert(strcmp(p, path) == 0);
    assert(strcmp(q, query) == 0);
}

void test_split_url(void)
{
    check_split("https://host.example/a/b?x=1&y=2", "host.example", "/a/b", "x=1&y=2");
    check_split("https://host/path", "host", "/path", "");
    check_split("http://h/?", "h", "/", "");

    char b[32], p[32], q[32];
    assert(!split_url("host/path", b, p, q, sizeof(b)));    /* no scheme */
    assert(!split_url("https://host", b, p, q, sizeof(b))); /* no path */
    assert(!split_url("https://h/p", b, p, q, 0));

    /* each part may use buf_size - 1 bytes, one more is rejected */
    char area[8 + CANARY_LEN];
    memset(area, '#', sizeof(area));
    assert(split_url("https://1234567/x", area, p, q, 8));
    assert(strcmp(area, "1234567") == 0);
    assert_canary(area, 8);
    assert(!split_url("https://12345678/x", b, p, q, 8));
    assert(!split_url("https://h/1234567?q", b, p, q, 8));
    assert(!split_url("https://h/p?12345678", b, p, q, 8));
}

static bool is_public(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    const uint8_t ip[4] = {a, b, c, d};
    return ipv4_is_public(ip);
}

void test_ipv4_is_public(void)
{
    /* public */
    assert(is_public(8, 8, 8, 8));
    assert(is_public(1, 1, 1, 1));
    assert(is_public(172, 15, 255, 255)); /* just below 172.16/12 */
    assert(is_public(172, 32, 0, 1));     /* just above */
    assert(is_public(100, 63, 255, 255)); /* just below 100.64/10 */
    assert(is_public(100, 128, 0, 1));    /* just above */
    assert(is_public(198, 17, 0, 1));
    assert(is_public(198, 20, 0, 1));
    assert(is_public(223, 255, 255, 255));

    /* not public */
    assert(!is_public(0, 0, 0, 0));
    assert(!is_public(10, 1, 2, 3));
    assert(!is_public(100, 64, 0, 1));
    assert(!is_public(100, 127, 255, 255));
    assert(!is_public(127, 0, 0, 1));
    assert(!is_public(127, 255, 255, 254));
    assert(!is_public(169, 254, 169, 254)); /* cloud metadata */
    assert(!is_public(172, 16, 0, 1));
    assert(!is_public(172, 31, 255, 255));
    assert(!is_public(192, 0, 0, 1));
    assert(!is_public(192, 0, 2, 1));
    assert(!is_public(192, 168, 1, 1));
    assert(!is_public(198, 18, 0, 1));
    assert(!is_public(198, 19, 255, 255));
    assert(!is_public(198, 51, 100, 7));
    assert(!is_public(203, 0, 113, 9));
    assert(!is_public(224, 0, 0, 1));
    assert(!is_public(240, 0, 0, 1));
    assert(!is_public(255, 255, 255, 255));
}
