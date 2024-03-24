#pragma once

#include "fs_port.h"
#include "stdbool.h"
#include "error.h"
#include "settings.h"

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
    bool_t _source_is_taf;
    bool_t _stream;
    char *_streamFile;
    char *_source_resolved;
    uint32_t _version;
    bool_t _updated;

    bool_t _valid;

} contentJson_t;

#define CONTENT_JSON_VERSION 5

error_t load_content_json(const char *content_path, contentJson_t *content_json, bool create_if_missing);
error_t load_content_json_settings(const char *content_path, contentJson_t *content_json, bool create_if_missing, settings_t *settings);
error_t save_content_json(const char *content_path, contentJson_t *content_json);
void content_json_update_model(contentJson_t *content_json, uint32_t audio_id, uint8_t *hash);
void free_content_json(contentJson_t *content_json);