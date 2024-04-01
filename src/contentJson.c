#include "contentJson.h"

#include "settings.h"
#include "debug.h"
#include "cJSON.h"
#include "net_config.h"
#include "server_helpers.h"
#include "toniesJson.h"
#include "handler.h"
#include "json_helper.h"

error_t load_content_json(const char *content_path, contentJson_t *content_json, bool create_if_missing)
{
    return load_content_json_settings(content_path, content_json, create_if_missing, get_settings());
}
error_t load_content_json_settings(const char *content_path, contentJson_t *content_json, bool create_if_missing, settings_t *settings)
{
    char *jsonPath = custom_asprintf("%s.json", content_path);
    error_t error = NO_ERROR;
    osMemset(content_json, 0, sizeof(contentJson_t));
    content_json->live = false;
    content_json->nocloud = false;
    content_json->source = NULL;
    content_json->skip_seconds = 0;
    content_json->cache = false;
    content_json->_updated = false;
    content_json->_source_type = CT_SOURCE_NONE;
    content_json->_streamFile = custom_asprintf("%s.stream", content_path);
    content_json->cloud_ruid = NULL;
    content_json->cloud_auth = NULL;
    content_json->cloud_auth_len = 0;
    content_json->cloud_override = false;
    content_json->_has_cloud_auth = false;
    content_json->tonie_model = NULL;
    content_json->_valid = false;
    osMemset(&content_json->_tap, 0, sizeof(tonie_audio_playlist_t));

    if (fsFileExists(jsonPath))
    {
        size_t fileSize = 0;
        fsGetFileSize(jsonPath, (uint32_t *)(&fileSize));

        FsFile *fsFile = fsOpenFile(jsonPath, FS_FILE_MODE_READ);
        if (fsFile != NULL)
        {
            size_t sizeRead;
            char *data = osAllocMem(fileSize);
            size_t pos = 0;

            while (pos < fileSize)
            {
                fsReadFile(fsFile, &data[pos], fileSize - pos, &sizeRead);
                pos += sizeRead;
            }
            fsCloseFile(fsFile);

            cJSON *contentJson = cJSON_ParseWithLengthOpts(data, fileSize, 0, 0);
            osFreeMem(data);
            if (contentJson == NULL)
            {
                const char *error_ptr = cJSON_GetErrorPtr();
                TRACE_ERROR("Json parse error\r\n");
                if (error_ptr != NULL)
                {
                    // TRACE_ERROR(" before: %s\r\n", error_ptr); //==194402==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020000bd2d0 at pc 0x555555ac8ba9 bp 0x7ffff2ffb490 sp 0x7ffff2ffac08
                }
                error = ERROR_INVALID_FILE;
            }
            else
            {
                content_json->live = jsonGetBool(contentJson, "live");
                content_json->nocloud = jsonGetBool(contentJson, "nocloud");
                content_json->source = jsonGetString(contentJson, "source");
                content_json->_source_resolved = jsonGetString(contentJson, "source");
                content_json->skip_seconds = jsonGetUInt32(contentJson, "skip_seconds");
                content_json->cache = jsonGetBool(contentJson, "cache");
                content_json->cloud_ruid = jsonGetString(contentJson, "cloud_ruid");
                content_json->cloud_auth = jsonGetBytes(contentJson, "cloud_auth", &content_json->cloud_auth_len);
                content_json->cloud_override = jsonGetBool(contentJson, "cloud_override");
                content_json->tonie_model = jsonGetString(contentJson, "tonie_model");

                // TODO: use checkCustomTonie to validate
                // TODO validate rUID
                if (osStrlen(content_json->cloud_ruid) == 16 && content_json->cloud_auth_len == AUTH_TOKEN_LENGTH)
                {
                    content_json->_has_cloud_auth = true;
                }
                else
                {
                    content_json->cloud_override = false;
                }

                if (osStrlen(content_json->source) > 0)
                {
                    resolveSpecialPathPrefix(&content_json->_source_resolved, settings);
                    if (isValidTaf(content_json->_source_resolved))
                    {
                        content_json->_source_type = CT_SOURCE_TAF;
                    }
                    else
                    {
                        error_t error = tap_load(content_json->_source_resolved, &content_json->_tap);
                        if (error == NO_ERROR && content_json->_tap._valid)
                        {
                            if (content_json->_tap._cached)
                            {
                                content_json->_source_type = CT_SOURCE_TAP_CACHED;
                            }
                            else
                            {
                                content_json->_source_type = CT_SOURCE_TAP_STREAM;
                            }
                            osFreeMem(content_json->_source_resolved);
                            content_json->_source_resolved = strdup(content_json->_tap._filepath_resolved);
                        }
                        else if (fsFileExists(content_json->_source_resolved) || osStrstr(content_json->_source_resolved, "://"))
                        {
                            content_json->_source_type = CT_SOURCE_STREAM;
                            if (!content_json->live || !content_json->nocloud)
                            {
                                content_json->live = true;
                                content_json->nocloud = true;
                                content_json->_updated = true;
                            }
                        }
                    }
                }

                if (jsonGetUInt32(contentJson, "_version") != CONTENT_JSON_VERSION)
                {
                    error = ERROR_INVALID_FILE;
                }

                cJSON_Delete(contentJson);
            }
        }
    }
    else
    {
        error = ERROR_FILE_NOT_FOUND;
    }

    if (error == NO_ERROR)
    {
        content_json->_valid = true;
    }

    if (error != NO_ERROR && (error != ERROR_FILE_NOT_FOUND || create_if_missing))
    {
        error = save_content_json(content_path, content_json);
        if (error == NO_ERROR)
        {
            load_content_json_settings(content_path, content_json, true, settings);
        }
    }

    osFreeMem(jsonPath);

    return error;
}

error_t save_content_json(const char *content_path, contentJson_t *content_json)
{
    char *jsonPath = custom_asprintf("%s.json", content_path);
    error_t error = NO_ERROR;
    cJSON *contentJson = cJSON_CreateObject();

    cJSON_AddBoolToObject(contentJson, "live", content_json->live);
    cJSON_AddBoolToObject(contentJson, "nocloud", content_json->nocloud);
    jsonAddStringToObject(contentJson, "source", content_json->source);
    cJSON_AddNumberToObject(contentJson, "skip_seconds", content_json->skip_seconds);
    cJSON_AddBoolToObject(contentJson, "cache", content_json->cache);
    jsonAddStringToObject(contentJson, "cloud_ruid", content_json->cloud_ruid);
    jsonAddByteArrayToObject(contentJson, "cloud_auth", content_json->cloud_auth, content_json->cloud_auth_len);
    cJSON_AddBoolToObject(contentJson, "cloud_override", content_json->cloud_override);
    jsonAddStringToObject(contentJson, "tonie_model", content_json->tonie_model);
    cJSON_AddNumberToObject(contentJson, "_version", CONTENT_JSON_VERSION);

    char *jsonRaw = cJSON_Print(contentJson);

    char *dir = strdup(content_path);
    dir[osStrlen(dir) - 8] = '\0';
    if (!fsDirExists(dir))
    {
        fsCreateDir(dir);
    }
    osFreeMem(dir);

    FsFile *file = fsOpenFile(jsonPath, FS_FILE_MODE_WRITE);
    if (file != NULL)
    {
        error = fsWriteFile(file, jsonRaw, osStrlen(jsonRaw));
        fsCloseFile(file);
    }
    else
    {
        error = ERROR_FILE_OPENING_FAILED;
    }

    cJSON_Delete(contentJson);
    osFreeMem(jsonRaw);
    osFreeMem(jsonPath);

    if (error == NO_ERROR)
    {
        content_json->_updated = false;
        content_json->_version = CONTENT_JSON_VERSION;
    }

    return error;
}

void content_json_update_model(contentJson_t *content_json, uint32_t audio_id, uint8_t *hash)
{
    if (content_json->_valid)
    {
        toniesJson_item_t *toniesJson = tonies_byAudioIdHash(audio_id, hash);
        if (toniesJson != NULL && osStrcmp(content_json->tonie_model, toniesJson->model) != 0)
        {
            if (audio_id == SPECIAL_AUDIO_ID_ONE && hash == NULL)
            { // don't update special tonies without hash
            }
            else
            {
                osFreeMem(content_json->tonie_model);
                content_json->tonie_model = strdup(toniesJson->model);
                content_json->_updated = true;
            }
        }
        else
        {
            // TODO add to tonies.custom.json + report
            TRACE_DEBUG("Audio-id %08X unknown but previous content known by model %s.\r\n", audio_id, content_json->tonie_model);
        }
    }
}

void free_content_json(contentJson_t *content_json)
{
    content_json->_valid = false;
    if (content_json->source)
    {
        osFreeMem(content_json->source);
        content_json->source = NULL;
    }
    if (content_json->cloud_ruid)
    {
        osFreeMem(content_json->cloud_ruid);
        content_json->cloud_ruid = NULL;
    }
    if (content_json->cloud_auth)
    {
        osFreeMem(content_json->cloud_auth);
        content_json->cloud_auth = NULL;
    }
    if (content_json->tonie_model)
    {
        osFreeMem(content_json->tonie_model);
        content_json->tonie_model = NULL;
    }
    if (content_json->_streamFile)
    {
        osFreeMem(content_json->_streamFile);
        content_json->_streamFile = NULL;
    }
    if (content_json->_source_resolved)
    {
        osFreeMem(content_json->_source_resolved);
        content_json->_source_resolved = NULL;
    }
    tap_free(&content_json->_tap);
    content_json->cloud_auth_len = 0;
}