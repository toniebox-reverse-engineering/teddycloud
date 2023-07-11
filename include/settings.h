#include <stdbool.h>

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

extern settings_t Settings;
#endif