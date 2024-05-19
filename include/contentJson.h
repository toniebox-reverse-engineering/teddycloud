#pragma once

#include "fs_port.h"
#include "stdbool.h"
#include "error.h"
#include "settings.h"
#include "tonie_audio_playlist.h"
#include "proto/toniebox.pb.taf-header.pb-c.h"

typedef enum
{
    CT_SOURCE_NONE,
    CT_SOURCE_TAF,
    CT_SOURCE_TAF_INCOMPLETE,
    CT_SOURCE_TAP_STREAM,
    CT_SOURCE_TAP_CACHED,
    CT_SOURCE_STREAM,
} ct_source_t;

typedef struct
{
    bool_t live;
    bool_t nocloud;
    char *source;
    size_t skip_seconds;
    bool_t cache;
    char *cloud_ruid;
    uint8_t *cloud_auth;
    size_t cloud_auth_len;
    bool_t cloud_override;
    char *tonie_model;

    bool_t _has_cloud_auth;
    ct_source_t _source_type;
    char *_streamFile;
    tonie_audio_playlist_t _tap;
    char *_source_resolved;
    uint32_t _version;
    bool_t _updated;

    bool_t _valid;
    bool_t _create_if_missing;

} contentJson_t;

typedef struct
{
    char *contentPath;
    char *jsonPath;
    bool_t exists;
    bool_t valid;
    bool_t updated;
    bool_t locked;
    contentJson_t json;
    TonieboxAudioFileHeader *tafHeader;
} tonie_info_t;

#define CONTENT_JSON_VERSION 5

error_t load_content_json(const char *content_path, contentJson_t *content_json, bool create_if_missing, settings_t *settings);
error_t save_content_json(const char *json_path, contentJson_t *content_json);
void content_json_update_model(contentJson_t *content_json, uint32_t audio_id, uint8_t *hash);
void free_content_json(contentJson_t *content_json);