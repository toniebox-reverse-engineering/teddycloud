#pragma once

#include <stdint.h>
#include <stddef.h>

#define TEDDY_BENCH_AUDIO_ID_DEDUCT 0x50000000

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
void tonies_readJson(char *source, toniesJson_item_t **toniesCache, size_t *toniesCount);
toniesJson_item_t *tonies_byAudioId(uint32_t audio_id);
toniesJson_item_t *tonies_byModel(char *model);
toniesJson_item_t *tonies_byAudioIdModel(uint32_t audio_id, char *model);
void tonies_deinit();