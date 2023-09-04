#include "contentJson.h"

#include "settings.h"
#include "debug.h"
#include "cJSON.h"

char *content_jsonGetString(cJSON *jsonElement, char *name)
{

    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsString(attr))
    {
        return strdup(attr->valuestring);
    }
    return strdup("");
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

error_t load_content_json(const char *content_path, contentJson_t *content_json)
{
    char *jsonPath = osAllocMem(osStrlen(content_path) + 5 + 1);
    osStrcpy(jsonPath, content_path);
    osStrcat(jsonPath, ".json");
    error_t error = NO_ERROR;

    content_json->live = false;
    content_json->nocloud = false;
    content_json->source = NULL;
    content_json->cache = false;
    content_json->_updated = false;
    content_json->_stream = false;

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
                content_json->cache = content_jsonGetBool(contentJson, "cache");

                if (osStrlen(content_json->source) > 0)
                {
                    content_json->_stream = true;
                    if (!content_json->live || !content_json->nocloud)
                    {
                        content_json->live = true;
                        content_json->nocloud = true;
                        content_json->_updated = true;
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

    if (error != NO_ERROR)
    {
        error = save_content_json(content_path, content_json);
    }

    osFreeMem(jsonPath);

    return error;
}
error_t save_content_json(const char *content_path, contentJson_t *content_json)
{
    char *jsonPath = osAllocMem(osStrlen(content_path) + 5 + 1);
    osStrcpy(jsonPath, content_path);
    osStrcat(jsonPath, ".json");
    error_t error = NO_ERROR;

    cJSON *contentJson = cJSON_CreateObject();

    cJSON_AddBoolToObject(contentJson, "live", content_json->live);
    cJSON_AddBoolToObject(contentJson, "nocloud", content_json->nocloud);
    if (content_json->source != NULL)
    {
        cJSON_AddStringToObject(contentJson, "source", content_json->source);
    }
    else
    {
        cJSON_AddStringToObject(contentJson, "source", "");
    }
    cJSON_AddBoolToObject(contentJson, "cache", content_json->cache);
    cJSON_AddNumberToObject(contentJson, "_version", CONTENT_JSON_VERSION);

    char *jsonRaw = cJSON_Print(contentJson);
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
void free_content_json(contentJson_t *content_json)
{
    osFreeMem(content_json->source);
}