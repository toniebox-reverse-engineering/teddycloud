#include "http_ext.h"

HttpRangeResult httpExtResolveRange(const HttpRangeHeader *range, uint32_t size, uint32_t *first, uint32_t *last)
{
    if (!range->valid)
    {
        return HTTP_RANGE_FULL;
    }
    /* a range whose end lies before its start is invalid and ignored */
    if (range->has_end && range->end < range->start)
    {
        return HTTP_RANGE_FULL;
    }
    if (range->start >= size)
    {
        return HTTP_RANGE_UNSATISFIABLE;
    }
    *first = range->start;
    *last = (range->has_end && range->end < size) ? range->end : size - 1;
    return HTTP_RANGE_PARTIAL;
}
