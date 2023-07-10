#include <stdbool.h>

#ifndef SETTINGS_H
#define SETTINGS_H

typedef struct
{
    bool cloud;
} settings_t;

extern settings_t Settings;
#endif