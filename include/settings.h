#include <stdbool.h>
#include <stdint.h>

#ifndef SETTINGS_H
#define SETTINGS_H

typedef struct
{
    bool enabled;
    bool enableV1Claim;
    bool enableV1FreshnessCheck;
    bool enableV1Log;
    bool enableV1Time;
    bool enableV1Ota;
    bool enableV2Content;
} settings_cloud_t;

typedef struct
{
    bool overrideCloud;
    uint8_t max_vol_spk;
    uint8_t max_vol_hdp;
    bool slap_enabled;
    bool slap_back_left;
    uint8_t led;
} settings_toniebox_t;

typedef struct
{
    bool exit;
    int32_t returncode;
} settings_internal_t;

typedef struct
{
    settings_cloud_t cloud;
    settings_toniebox_t toniebox;
    settings_internal_t internal;
} settings_t;

typedef enum
{
    TYPE_BOOL,
    TYPE_INTEGER,
    TYPE_HEX,
    TYPE_STRING,
    TYPE_FLOAT,
    TYPE_END
} settings_type;

typedef union
{
    bool bool_default;
    int integer_default;
    int hex_default;
    float float_default;
} option_default_t;

typedef struct
{
    const char *option_name;
    const char *description;
    void *ptr;
    settings_type type;
    option_default_t defaults;
    bool internal;
} option_map_t;

#define OPTION_START() option_map_t option_map[] = {
#define OPTION_ADV_BOOL(o, p, d, desc, i) {.option_name = o, .ptr = p, .defaults = {.bool_default = d}, .type = TYPE_BOOL, .description = desc, .internal = i},
#define OPTION_ADV_INT(o, p, d, desc, i) {.option_name = o, .ptr = p, .defaults = {.integer_default = d}, .type = TYPE_INTEGER, .description = desc, .internal = i},

#define OPTION_BOOL(o, p, d, desc) OPTION_ADV_BOOL(o, p, d, desc, false)
#define OPTION_INT(o, p, d, desc) OPTION_ADV_INT(o, p, d, desc, false)

#define OPTION_INTERNAL_BOOL(o, p, d, desc) OPTION_ADV_BOOL(o, p, d, desc, true)
#define OPTION_INTERNAL_INT(o, p, d, desc) OPTION_ADV_INT(o, p, d, desc, true)

#define OPTION_END()     \
    {                    \
        .type = TYPE_END \
    }                    \
    }                    \
    ;

extern settings_t Settings;

void settings_set_bool(const char *item, bool value);
void settings_set_integer(const char *item, uint32_t value);
bool settings_get_bool(const char *item);
uint32_t settings_get_intger(const char *item);
option_map_t *settings_get(int index);
void settings_init();

#endif