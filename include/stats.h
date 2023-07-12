#pragma once

#include "debug.h"

typedef struct
{
    const char *name;
    const char *description;
    uint32_t value;
} stat_t;

#define STATS_START() stat_t statistics[] = {
#define STATS_ENTRY(n, d) {.name = n, .description = d, .value = 0},
#define STATS_END()  \
    {                \
        .name = NULL \
    }                \
    }                \
    ;

void stats_update(const char *item, int count);
stat_t *stats_get(int index);
