#include <assert.h>

#include "http_ext.h"
#include "tests.h"

static HttpRangeResult resolve(bool valid, uint32_t start, bool has_end, uint32_t end, uint32_t size, uint32_t *first, uint32_t *last)
{
    HttpRangeHeader range = {.start = start, .end = end, .valid = valid, .has_end = has_end};
    return httpExtResolveRange(&range, size, first, last);
}

void test_range_ext(void)
{
    uint32_t first = 7, last = 7;

    assert(resolve(false, 0, false, 0, 100, &first, &last) == HTTP_RANGE_FULL);

    assert(resolve(true, 10, true, 19, 100, &first, &last) == HTTP_RANGE_PARTIAL);
    assert(first == 10 && last == 19);
    assert(resolve(true, 0, true, 9, 100, &first, &last) == HTTP_RANGE_PARTIAL);
    assert(first == 0 && last == 9);
    assert(resolve(true, 0, true, 0, 100, &first, &last) == HTTP_RANGE_PARTIAL); /* the first byte */
    assert(first == 0 && last == 0);
    assert(resolve(true, 10, false, 0, 100, &first, &last) == HTTP_RANGE_PARTIAL);
    assert(first == 10 && last == 99);
    assert(resolve(true, 90, true, 200, 100, &first, &last) == HTTP_RANGE_PARTIAL); /* end is clamped */
    assert(first == 90 && last == 99);
    assert(resolve(true, 99, false, 0, 100, &first, &last) == HTTP_RANGE_PARTIAL);
    assert(first == 99 && last == 99);

    assert(resolve(true, 100, false, 0, 100, &first, &last) == HTTP_RANGE_UNSATISFIABLE);
    assert(resolve(true, 500, true, 600, 100, &first, &last) == HTTP_RANGE_UNSATISFIABLE);
    assert(resolve(true, 0, false, 0, 0, &first, &last) == HTTP_RANGE_UNSATISFIABLE); /* empty resource */

    assert(resolve(true, 50, true, 10, 100, &first, &last) == HTTP_RANGE_FULL); /* reversed: ignored */
    assert(resolve(true, 500, true, 10, 100, &first, &last) == HTTP_RANGE_FULL);
}
