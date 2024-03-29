#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    const char *id;
    const char *name;
} toniebox_state_box_t;

typedef struct
{
    uint64_t uid;
    bool valid;
    uint32_t audio_id;
} toniebox_state_tag_t;

typedef struct
{
    toniebox_state_box_t box;
    toniebox_state_tag_t tag;
} toniebox_state_t;

void toniebox_state_init();
toniebox_state_t *get_toniebox_state();
toniebox_state_t *get_toniebox_state_id(uint8_t id);