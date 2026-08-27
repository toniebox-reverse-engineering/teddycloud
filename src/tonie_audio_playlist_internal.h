#pragma once

#include "tonie_audio_playlist.h"

typedef struct
{
    tonie_audio_playlist_t *tap;
    void *stream_ctx;
    bool_t force;
    bool_t preserve_on_client_disconnect;
    toniefile_live_header_t live_header;
    uint32_t generation;
    size_t *runtime_indices;
    size_t runtime_files_count;
    size_t current_source;
    error_t error;
    bool_t generator_started;
    bool_t generator_active;
    bool_t generator_done;
} tap_generate_param_t;

void tap_generate_task(void *param);
