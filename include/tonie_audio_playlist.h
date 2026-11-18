#pragma once

#include "debug.h"
#include "error.h"
#include "settings.h"

#define TAP_TYPE_TAP "tap"
#define TAP_TYPE_RANDOM "random"
/* Bytes of a TAF's SHA1 that name a random pool's pick in its V3 chapter names. */
#define TAP_RANDOM_SHA1_PREFIX 4

typedef struct
{
    char *filepath;
    char *name;
    char *_filepath_resolved;
} tap_file_t;
typedef struct
{
    char *type;
    time_t audio_id;
    char *filepath;
    char *_filepath_resolved;
    char *name;
    tap_file_t *files;
    size_t filesCount;
    /* Random pools only, resolved: every TAF directly in this folder belongs to the pool. */
    char *directory;
    bool_t _random;
    bool_t _cached;
    bool_t _valid;
} tonie_audio_playlist_t;

typedef struct
{
    tonie_audio_playlist_t *tap;
    bool_t force;
} tap_generate_param_t;

bool_t is_valid_tap(char *filename);
error_t tap_load(char *filename, tonie_audio_playlist_t *tap);
error_t tap_save(char *filename, tonie_audio_playlist_t *tap);
void tap_free(tonie_audio_playlist_t *tap);
error_t tap_random_pick(const tonie_audio_playlist_t *tap, uint32_t audio_id, const uint8_t *sha1_prefix, settings_t *settings, char **picked);
error_t tap_generate_taf(tonie_audio_playlist_t *tap, size_t *current_source, bool_t *active, bool_t force);
void tap_generate_task(void *param);