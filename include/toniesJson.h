#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "error.h"

typedef struct
{
    uint16_t no;
    char *model;
    uint32_t *audio_ids;
    uint8_t audio_ids_count;
    uint8_t *hashes;
    uint8_t hashes_count;
    char *title;
    char *series;
    char *episodes;
    char **tracks;
    uint8_t tracks_count;
    uint32_t release;
    char *language;
    char *category;
    char *picture;
    bool custom;
} toniesJson_item_t;

typedef struct
{
    char *series;
    char *episode;
    uint32_t release;
    char *language;
    char *category;
    char *image;
    char *sample;
    char *web;
    char *shop_id;
    char **track_desc;
    uint8_t track_desc_count;
} toniesV2Json_data_t;

typedef struct
{
    uint32_t audio_id;
    char *hash;
    uint32_t size;
    uint8_t tracks;
    uint8_t confidence;
} toniesV2Json_ids_t;

typedef struct
{
    char *article;
    toniesV2Json_data_t *data;
    uint8_t data_count;
    toniesV2Json_ids_t *ids;
    uint8_t ids_count;
} toniesV2Json_item_t;

void tonies_init();
error_t tonies_update();
error_t toniesV2_update();
void tonies_readJson(char *source, toniesJson_item_t **retCache, size_t *retCount);
void toniesV2_readJson(char *source, toniesV2Json_item_t **toniesCache, size_t *toniesCount);
toniesJson_item_t *tonies_byAudioId(uint32_t audio_id);
toniesJson_item_t *tonies_byAudioIdHash(uint32_t audio_id, uint8_t *hash);
toniesJson_item_t *tonies_byModel(char *model);
toniesJson_item_t *tonies_byAudioIdHashModel(uint32_t audio_id, uint8_t *hash, char *model);
bool tonies_byModelSeriesEpisode(char *model, char *series, char *episode, toniesJson_item_t *result[18], size_t *result_size);
void tonies_deinit();