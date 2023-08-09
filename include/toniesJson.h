#pragma once

#include <stdint.h>

typedef struct
{
    uint16_t no;
    char *model;
    uint32_t *audio_ids;
    uint8_t audio_ids_count;
    //* hashes;
    char *title;
    char *series;
    char *episodes;
    // *tracks;
    uint32_t release;
    char *language;
    char *category;
    char *picture;
} toniesJson_item_t;

void tonies_init();
void tonies_readJson();
toniesJson_item_t *tonies_byAudioId(uint32_t audio_id);
void tonies_deinit();