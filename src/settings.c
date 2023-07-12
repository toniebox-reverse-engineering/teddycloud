
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "debug.h"
#include "settings.h"

settings_t Settings;

OPTION_START()
OPTION_INTERNAL_BOOL("internal.exit", &Settings.internal.exit, FALSE, "Exit the server")
OPTION_INTERNAL_SIGNED("internal.returncode", &Settings.internal.returncode, 0, -128, 127, "Returncode when exiting")
OPTION_BOOL("cloud.enabled", &Settings.cloud.enabled, FALSE, "Generally enable cloud operation")
OPTION_BOOL("cloud.enableV1Claim", &Settings.cloud.enableV1Claim, TRUE, "Pass 'claim' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1FreshnessCheck", &Settings.cloud.enableV1FreshnessCheck, TRUE, "Pass 'freshnessCheck' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Log", &Settings.cloud.enableV1Log, FALSE, "Pass 'log' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Time", &Settings.cloud.enableV1Time, FALSE, "Pass 'time' queries to boxine cloud")
OPTION_BOOL("cloud.enableV1Ota", &Settings.cloud.enableV1Ota, FALSE, "Pass 'ota' queries to boxine cloud")
OPTION_BOOL("cloud.enableV2Content", &Settings.cloud.enableV2Content, TRUE, "Pass 'content' queries to boxine cloud")

OPTION_BOOL("toniebox.overrideCloud", &Settings.toniebox.overrideCloud, TRUE, "Override toniebox settings from the boxine cloud")
OPTION_UNSIGNED("toniebox.max_vol_spk", &Settings.toniebox.max_vol_spk, 3, 0, 3, "Limit speaker volume (0-3)")
OPTION_UNSIGNED("toniebox.max_vol_hdp", &Settings.toniebox.max_vol_hdp, 3, 0, 3, "Limit headphone volume (0-3)")
OPTION_BOOL("toniebox.slap_enabled", &Settings.toniebox.slap_enabled, TRUE, "Enable slapping to skip a track")
OPTION_BOOL("toniebox.slap_back_left", &Settings.toniebox.slap_back_left, FALSE, "False=left-backwards - True=left-forward")
OPTION_UNSIGNED("toniebox.led", &Settings.toniebox.led, 0, 0, 2, "0=on, 1=off, 2=dimmed")

OPTION_BOOL("mqtt.enabled", &Settings.mqtt.enabled, FALSE, "Enable MQTT service")
OPTION_STRING("mqtt.hostname", Settings.mqtt.hostname, sizeof(Settings.mqtt.hostname) - 1, "", "MQTT hostname")
OPTION_STRING("mqtt.username", Settings.mqtt.username, sizeof(Settings.mqtt.username) - 1, "", "Username")
OPTION_STRING("mqtt.password", Settings.mqtt.password, sizeof(Settings.mqtt.password) - 1, "", "Password")
OPTION_STRING("mqtt.identification", Settings.mqtt.identification, sizeof(Settings.mqtt.identification) - 1, "", "Client identification")

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
            TRACE_INFO("  %s = %s\r\n", option_map[pos].option_name, option_map[pos].init.bool_value ? "true" : "false");
            *((bool *)option_map[pos].ptr) = option_map[pos].init.bool_value;
            break;
        case TYPE_SIGNED:
            TRACE_INFO("  %s = %d\r\n", option_map[pos].option_name, option_map[pos].init.signed_value);
            *((uint32_t *)option_map[pos].ptr) = option_map[pos].init.signed_value;
            break;
        case TYPE_UNSIGNED:
        case TYPE_HEX:
            TRACE_INFO("  %s = %d\r\n", option_map[pos].option_name, option_map[pos].init.unsigned_value);
            *((uint32_t *)option_map[pos].ptr) = option_map[pos].init.unsigned_value;
            break;
        case TYPE_FLOAT:
            TRACE_INFO("  %s = %f\r\n", option_map[pos].option_name, option_map[pos].init.float_value);
            *((uint32_t *)option_map[pos].ptr) = option_map[pos].init.float_value;
            break;
        default:
            break;
        }
        pos++;
    }

    settings_load();
}

void settings_save()
{
    TRACE_ERROR("settings_save() not implemented yet\r\n");
}

void settings_load()
{
    TRACE_ERROR("settings_load() not implemented yet\r\n");
}

setting_item_t *settings_get(int index)
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
    TRACE_WARNING("Setting item #%d not found\r\n", index);
    return NULL;
}

setting_item_t *settings_get_by_name(const char *item)
{
    int pos = 0;
    while (option_map[pos].type != TYPE_END)
    {
        if (!strcmp(item, option_map[pos].option_name))
        {
            return &option_map[pos];
        }
        pos++;
    }
    TRACE_WARNING("Setting item '%s' not found\r\n", item);
    return NULL;
}

bool settings_get_bool(const char *item)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_BOOL)
    {
        return false;
    }

    return *((bool *)opt->ptr);
}

bool settings_set_bool(const char *item, bool value)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_BOOL)
    {
        return false;
    }

    *((bool *)opt->ptr) = value;
    return true;
}

int32_t settings_get_signed(const char *item)
{
    if (!item)
    {
        return 0;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_SIGNED)
    {
        return 0;
    }

    return *((int32_t *)opt->ptr);
}

bool settings_set_signed(const char *item, int32_t value)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_SIGNED)
    {
        return false;
    }

    if (value < opt->min.signed_value || value > opt->max.signed_value)
    {
        TRACE_ERROR("  %s = %d out of bounds\r\n", opt->option_name, value);
        return false;
    }

    *((int32_t *)opt->ptr) = value;
    return true;
}

uint32_t settings_get_unsigned(const char *item)
{
    if (!item)
    {
        return 0;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_UNSIGNED)
    {
        return 0;
    }

    return *((uint32_t *)opt->ptr);
}

bool settings_set_unsigned(const char *item, uint32_t value)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_UNSIGNED)
    {
        return false;
    }

    if (value < opt->min.unsigned_value || value > opt->max.unsigned_value)
    {
        TRACE_ERROR("  %s = %d out of bounds\r\n", opt->option_name, value);
        return false;
    }

    *((uint32_t *)opt->ptr) = value;
    return true;
}

float settings_get_float(const char *item)
{
    if (!item)
    {
        return 0;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_FLOAT)
    {
        return 0;
    }

    return *((float *)opt->ptr);
}

bool settings_set_float(const char *item, float value)
{
    if (!item)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_FLOAT)
    {
        return false;
    }

    if (value < opt->min.float_value || value > opt->max.float_value)
    {
        TRACE_ERROR("  %s = %f out of bounds\r\n", opt->option_name, value);
        return false;
    }

    *((float *)opt->ptr) = value;
    return true;
}

const char *settings_get_string(const char *item)
{
    if (!item)
    {
        return NULL;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_STRING)
    {
        return NULL;
    }

    return (const char *)opt->ptr;
}

bool settings_set_string(const char *item, const char *value)
{
    if (!item || !value)
    {
        return false;
    }

    setting_item_t *opt = settings_get_by_name(item);
    if (!opt || opt->type != TYPE_STRING)
    {
        return false;
    }

    if (osStrlen(value) > opt->max.unsigned_value)
    {
        TRACE_WARNING("Setting item '%s' is too small for the %lu bytes requested to store\r\n", item, osStrlen(value));
        return false;
    }

    osStrcpy((char *)opt->ptr, value);
    return true;
}
