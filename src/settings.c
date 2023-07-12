
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "debug.h"
#include "settings.h"

settings_t Settings;

OPTION_START()
OPTION_BOOL("cloud.enabled", &Settings.cloud.enabled, FALSE, "Generally enable cloud operation")
OPTION_BOOL("cloud.enableV1Claim", &Settings.cloud.enableV1Claim, TRUE, "Pass 'claim' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1FreshnessCheck", &Settings.cloud.enableV1FreshnessCheck, TRUE, "Pass 'freshnessCheck' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Log", &Settings.cloud.enableV1Log, FALSE, "Pass 'log' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Time", &Settings.cloud.enableV1Time, FALSE, "Pass 'time' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Ota", &Settings.cloud.enableV1Ota, FALSE, "Pass 'ota' queries to boxine cloud")
OPTION_BOOL("cloud.enableV2Content", &Settings.cloud.enableV2Content, TRUE, "Pass 'content' queries to boxine cloud")

OPTION_BOOL("toniebox.overrideCloud", &Settings.toniebox.overrideCloud, TRUE, "Override toniebox settings from the boxine cloud")
OPTION_INT("toniebox.max_vol_spk", &Settings.toniebox.max_vol_spk, 3, "Limit speaker volume (0-3)")
OPTION_INT("toniebox.max_vol_hdp", &Settings.toniebox.max_vol_hdp, 3, "Limit headphone volume (0-3)")
OPTION_BOOL("toniebox.slap_enabled", &Settings.toniebox.slap_enabled, TRUE, "Enable slapping to skip a track")
OPTION_BOOL("toniebox.slap_back_left", &Settings.toniebox.slap_back_left, FALSE, "False=left-backwards - True=left-forward")
OPTION_INT("toniebox.led", &Settings.toniebox.led, 0, "0=on, 1=off, 2=dimmed")

OPTION_END()

void settings_init()
{
    TRACE_INFO("Init Settings\r\n");
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        switch (option_map[pos].type)
        {
        case TYPE_BOOL:
            TRACE_INFO("  %s = %s\r\n", option_map[pos].option_name, option_map[pos].defaults.bool_default ? "true" : "false");
            *((bool *)option_map[pos].ptr) = option_map[pos].defaults.bool_default;
            break;
        case TYPE_INTEGER:
        case TYPE_HEX:
            TRACE_INFO("  %s = %d\r\n", option_map[pos].option_name, option_map[pos].defaults.integer_default);
            *((uint32_t *)option_map[pos].ptr) = option_map[pos].defaults.integer_default;
            break;
        case TYPE_FLOAT:
            TRACE_INFO("  %s = %f\r\n", option_map[pos].option_name, option_map[pos].defaults.float_default);
            *((uint32_t *)option_map[pos].ptr) = option_map[pos].defaults.float_default;
            break;
        default:
            break;
        }
        pos++;
    }
}

option_map_t *settings_get(int index)
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        if (pos == index)
        {
            return &option_map[pos];
        }
        pos++;
    }
    return NULL;
}

void settings_set_bool(const char *item, bool value)
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        if (!strcmp(item, option_map[pos].option_name))
        {
            switch (option_map[pos].type)
            {
            case TYPE_BOOL:
                *((bool *)option_map[pos].ptr) = value;
                break;
            default:
                break;
            }
        }
        pos++;
    }
    TRACE_WARNING("Option '%s' not found\r\n", item);
}

void settings_set_int(const char *item, uint32_t value)
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        if (!strcmp(item, option_map[pos].option_name))
        {
            switch (option_map[pos].type)
            {
            case TYPE_INTEGER:
            case TYPE_HEX:
                *((uint32_t *)option_map[pos].ptr) = value;
                break;
            default:
                break;
            }
        }
        pos++;
    }
    TRACE_WARNING("Option '%s' not found\r\n", item);
}

bool settings_get_bool(const char *item)
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        if (!strcmp(item, option_map[pos].option_name))
        {
            switch (option_map[pos].type)
            {
            case TYPE_BOOL:
                return *((bool *)option_map[pos].ptr);
            default:
                return false;
            }
        }
        pos++;
    }
    TRACE_WARNING("Option '%s' not found\r\n", item);
    return false;
}

uint32_t settings_get_int(const char *item)
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        if (!strcmp(item, option_map[pos].option_name))
        {
            switch (option_map[pos].type)
            {
            case TYPE_INTEGER:
            case TYPE_HEX:
                return *((uint32_t *)option_map[pos].ptr);
            default:
                return INT32_MIN;
            }
        }
        pos++;
    }
    TRACE_WARNING("Option '%s' not found\r\n", item);
    return INT32_MIN;
}
