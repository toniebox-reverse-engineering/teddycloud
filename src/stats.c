
#include "debug.h"
#include "stats.h"

STATS_START()
STATS_ENTRY("connections", "Connections made to this server")
STATS_ENTRY("reverse_requests", "Reverse proxy calls made by clients")
STATS_ENTRY("cloud_requests", "Cloud requests executed")
STATS_ENTRY("cloud_blocked", "Blocked cloud requests")
STATS_ENTRY("cloud_failed", "Failed cloud requests")
STATS_END()

void stats_update(const char *item, int count)
{
    int pos = 0;
    while (statistics[pos].name)
    {
        if (!osStrcmp(item, statistics[pos].name))
        {
            statistics[pos].value += count;
            return;
        }
        pos++;
    }
}

stat_t *stats_get(int index)
{
    int pos = 0;
    while (statistics[pos].name != NULL)
    {
        if (pos == index)
        {
            return &statistics[pos];
        }
        pos++;
    }
    return NULL;
}
