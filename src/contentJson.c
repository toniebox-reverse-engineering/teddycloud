#include "contentJson.h"

#include "settings.h"
#include "debug.h"
#include "cJSON.h"
#include "net_config.h"
#include "server_helpers.h"
#include "toniesJson.h"
#include "handler.h"

char *content_jsonGetString(cJSON *jsonElement, char *name)
{
    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsString(attr))
    {
        return strdup(attr->valuestring);
    }
    return strdup("");
}

cJSON *content_AddStringToObject(cJSON *const object, const char *const name, const char *const string)
{
    if (string != NULL)
    {
        return cJSON_AddStringToObject(object, name, string);
    }
    return cJSON_AddStringToObject(object, name, "");
}

uint8_t *content_jsonGetBytes(cJSON *jsonElement, char *name, size_t *length)
{
    char *text = content_jsonGetString(jsonElement, name);
    uint8_t *bytes = NULL;
    size_t textLen = osStrlen(text);
    size_t byteLen = textLen / 2;

    *length = 0;
    if (byteLen > 0)
    {
        bytes = osAllocMem(byteLen);
        for (size_t i = 0; i < byteLen; i++)
        {
            sscanf(&text[i * 2], "%02hhx", &bytes[i]);
        }
        *length = byteLen;
    }

    osFreeMem(text);

    return bytes;
}

cJSON *content_AddByteArrayToObject(cJSON *const object, const char *const name, uint8_t *bytes, size_t bytes_len)
{
    size_t string_len = bytes_len * 2 + 1;
    char *string = osAllocMem(string_len);
    string[string_len - 1] = '\0';

    for (size_t i = 0; i < bytes_len; i++)
    {
        sprintf(&string[i * 2], "%02hhx", bytes[i]);
    }

    return cJSON_AddStringToObject(object, name, string);
}

bool_t content_jsonGetBool(cJSON *jsonElement, char *name)
{
    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsBool(attr))
    {
        return attr->valueint;
    }
    return false;
}

uint32_t content_jsonGetUInt32(cJSON *jsonElement, char *name)
{
    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsNumber(attr))
    {
        return attr->valuedouble;
    }
    return 0;
}

error_t load_content_json(const char *content_path, contentJson_t *content_json, bool create_if_missing)
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
    content_json->_source_is_taf = false;
    content_json->_stream = false;
    content_json->_streamFile = custom_asprintf("%s.stream", content_path);
    content_json->cloud_ruid = NULL;
    content_json->cloud_auth = NULL;
    content_json->cloud_auth_len = 0;
    content_json->cloud_override = false;
    content_json->tonie_model = NULL;
    content_json->_valid = false;

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
                content_json->live = content_jsonGetBool(contentJson, "live");
                content_json->nocloud = content_jsonGetBool(contentJson, "nocloud");
                content_json->source = content_jsonGetString(contentJson, "source");
                content_json->skip_seconds = content_jsonGetUInt32(contentJson, "skip_seconds");
                content_json->cache = content_jsonGetBool(contentJson, "cache");
                content_json->cloud_ruid = content_jsonGetString(contentJson, "cloud_ruid");
                content_json->cloud_auth = content_jsonGetBytes(contentJson, "cloud_auth", &content_json->cloud_auth_len);
                content_json->cloud_override = content_jsonGetBool(contentJson, "cloud_override");
                content_json->tonie_model = content_jsonGetString(contentJson, "tonie_model");

                // TODO: use checkCustomTonie to validate
                if (osStrlen(content_json->cloud_ruid) != 16)
                {
                    // TODO validate rUID
                    content_json->cloud_override = false;
                }
                if (content_json->cloud_auth_len != AUTH_TOKEN_LENGTH)
                {
                    content_json->cloud_override = false;
                }

                if (osStrlen(content_json->source) > 0)
                {
                    if (isValidTaf(content_json->source))
                    {
                        content_json->_source_is_taf = true;
                    }
                    else
                    {
                        content_json->_stream = true;
                        if (!content_json->live || !content_json->nocloud)
                        {
                            content_json->live = true;
                            content_json->nocloud = true;
                            content_json->_updated = true;
                        }
                    }
                }

                if (content_jsonGetUInt32(contentJson, "_version") != CONTENT_JSON_VERSION)
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
            load_content_json(content_path, content_json, true);
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
    content_AddStringToObject(contentJson, "source", content_json->source);
    cJSON_AddNumberToObject(contentJson, "skip_seconds", content_json->skip_seconds);
    cJSON_AddBoolToObject(contentJson, "cache", content_json->cache);
    content_AddStringToObject(contentJson, "cloud_ruid", content_json->cloud_ruid);
    content_AddByteArrayToObject(contentJson, "cloud_auth", content_json->cloud_auth, content_json->cloud_auth_len);
    cJSON_AddBoolToObject(contentJson, "cloud_override", content_json->cloud_override);
    content_AddStringToObject(contentJson, "tonie_model", content_json->tonie_model);
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
            TRACE_WARNING("Audio-id %08X unknown but previous content known by model %s.\r\n", audio_id, content_json->tonie_model);
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
    content_json->cloud_auth_len = 0;
}