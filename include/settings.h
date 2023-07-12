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
    settings_cloud_t cloud;
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
} option_map_t;

#define OPTION_START() option_map_t option_map[] = {
#define OPTION_BOOL(name, p, default, desc) {.option_name = name, .ptr = p, .defaults = {.bool_default = default}, .type = TYPE_BOOL, .description = desc},
#define OPTION_END()     \
    {                    \
        .type = TYPE_END \
    }                    \
    }                    \
    ;

extern settings_t Settings;

void settings_set_bool(const char *item, bool value);
void settings_set_int(const char *item, uint32_t value);
bool settings_get_bool(const char *item);
uint32_t settings_get_int(const char *item);
option_map_t *settings_get(int index);
void settings_init();

#endif