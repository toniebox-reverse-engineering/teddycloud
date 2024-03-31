#pragma once

#include "debug.h"

#define TAP_TYPE_TAP "tap"

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
    bool_t _cached;
    bool_t _valid;
} tonie_audio_playlist_t;

typedef struct
{
    tonie_audio_playlist_t *tap;
    bool_t force;
    bool_t active;
    OsTaskId taskId;
    error_t error;
    bool_t quit;
} tap_generate_param_t;

bool_t is_valid_tap(char *filename);
error_t tap_load(char *filename, tonie_audio_playlist_t *tap);
error_t tap_save(char *filename, tonie_audio_playlist_t *tap);
void tap_free(tonie_audio_playlist_t *tap);
error_t tap_generate_taf(tonie_audio_playlist_t *tap, bool_t *active, bool_t force);
void tap_generate_task(void *param);