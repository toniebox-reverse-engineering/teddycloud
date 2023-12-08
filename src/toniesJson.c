#include "toniesJson.h"
#include "fs_port.h"
#include "settings.h"
#include "debug.h"
#include "cJSON.h"

#define TONIES_JSON_CACHED 1
#if TONIES_JSON_CACHED == 1
static size_t toniesJsonCount;
static toniesJson_item_t *toniesJsonCache;
static size_t toniesCustomJsonCount;
static toniesJson_item_t *toniesCustomJsonCache;
#endif

void tonies_init()
{
    toniesJsonCount = 0;
    toniesCustomJsonCount = 0;
    tonies_readJson(TONIES_CUSTOM_JSON_PATH, &toniesCustomJsonCache, &toniesCustomJsonCount);
    tonies_readJson(TONIES_JSON_PATH, &toniesJsonCache, &toniesJsonCount);
}

char *tonies_jsonGetString(cJSON *jsonElement, char *name)
{

    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsString(attr))
    {
        return strdup(attr->valuestring);
    }
    return strdup("");
}
uint32_t tonies_jsonGetUInt32(cJSON *jsonElement, char *name)
{
    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsNumber(attr))
    {
        return attr->valuedouble;
    }
    return 0;
}
void tonies_readJson(char *source, toniesJson_item_t **toniesCache, size_t *toniesCount)
{
#if TONIES_JSON_CACHED == 1
    if (*toniesCount > 0)
    {
        *toniesCount = 0;
        osFreeMem(*toniesCache);
    }

    size_t fileSize = 0;
    fsGetFileSize(source, (uint32_t *)(&fileSize));
    TRACE_INFO("Trying to read %s with size %" PRIuSIZE "\r\n", source, fileSize);

    FsFile *fsFile = fsOpenFile(source, FS_FILE_MODE_READ);
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

        cJSON *toniesJson = cJSON_ParseWithLengthOpts(data, fileSize, 0, 0);
        cJSON *tonieJson;
        osFreeMem(data);
        if (toniesJson == NULL)
        {
            if (fileSize > 0)
            {
                const char *error_ptr = cJSON_GetErrorPtr();
                TRACE_ERROR("Json parse error\r\n");
                if (error_ptr != NULL)
                {
                    // TRACE_ERROR(" before: %s\r\n", error_ptr); //TODO is crashing
                }
            }
            cJSON_Delete(toniesJson);
        }
        else
        {
            size_t line = 0;
            *toniesCount = cJSON_GetArraySize(toniesJson);
            *toniesCache = osAllocMem(*toniesCount * sizeof(toniesJson_item_t));
            cJSON_ArrayForEach(tonieJson, toniesJson)
            {
                cJSON *arrayJson;
                toniesJson_item_t *item = &(*toniesCache)[line++];
                char *no_str = tonies_jsonGetString(tonieJson, "no");
                item->no = atoi(no_str);
                free(no_str);
                item->model = tonies_jsonGetString(tonieJson, "model");

                arrayJson = cJSON_GetObjectItem(tonieJson, "audio_id");
                item->audio_ids_count = (uint8_t)cJSON_GetArraySize(arrayJson);
                item->audio_ids = osAllocMem(item->audio_ids_count * sizeof(uint32_t));
                for (size_t i = 0; i < item->audio_ids_count; i++)
                {
                    cJSON *arrayItemJson = cJSON_GetArrayItem(arrayJson, i);
                    item->audio_ids[i] = atoi(arrayItemJson->valuestring);
                }
                arrayJson = cJSON_GetObjectItem(tonieJson, "hash");
                item->hashes_count = (uint8_t)cJSON_GetArraySize(arrayJson);
                item->hashes = osAllocMem(item->hashes_count * sizeof(uint8_t) * 20);
                for (size_t i = 0; i < item->hashes_count; i++)
                {
                    cJSON *arrayItemJson = cJSON_GetArrayItem(arrayJson, i);
                    if (arrayItemJson->valuestring == NULL || osStrlen(arrayItemJson->valuestring) != 40)
                    {
                        break;
                    }
                    for (size_t j = 0; j < 20; j++)
                    {
                        sscanf(&arrayItemJson->valuestring[j * 2], "%2hhx", &item->hashes[(i * 20) + j]);
                    }
                }
                item->title = tonies_jsonGetString(tonieJson, "title");
                item->episodes = tonies_jsonGetString(tonieJson, "episodes");
                item->series = tonies_jsonGetString(tonieJson, "series");
                // TODO Tracks
                char *releaseString = tonies_jsonGetString(tonieJson, "release");
                item->release = atoi(releaseString);
                osFreeMem(releaseString);
                item->language = tonies_jsonGetString(tonieJson, "language");
                item->category = tonies_jsonGetString(tonieJson, "category");
                item->picture = tonies_jsonGetString(tonieJson, "pic");
            }
            cJSON_Delete(toniesJson);
        }
    }
    else
    {
        TRACE_INFO("Create empty json file\r\n");
        FsFile *fsFile = fsOpenFile(source, FS_FILE_MODE_WRITE);
        if (fsFile != NULL)
        {
            fsWriteFile(fsFile, "[]", 2);
            fsCloseFile(fsFile);
        }
        else
        {
            TRACE_ERROR("...could not create file\r\n");
        }
    }
#endif
}
toniesJson_item_t *tonies_byAudioIdHash_base(uint32_t audio_id, uint8_t *hash, toniesJson_item_t *toniesCache, size_t toniesCount)
{
#if TONIES_JSON_CACHED == 1
    for (size_t i = 0; i < toniesCount; i++)
    {
        for (size_t j = 0; j < toniesCache[i].audio_ids_count; j++)
        {
            if (toniesCache[i].audio_ids[j] == audio_id || (audio_id < TEDDY_BENCH_AUDIO_ID_DEDUCT && toniesCache[i].audio_ids[j] == audio_id + TEDDY_BENCH_AUDIO_ID_DEDUCT))
            {
                for (size_t k = 0; k < toniesCache[i].hashes_count; k++)
                {
                    if (hash == NULL || osMemcmp(toniesCache[i].hashes + (k * 20), hash, 20) == 0)
                        return &toniesCache[i];
                }
            }
        }
    }
#else
    // cJSON_ParseWithLengthOpts
#endif
    return NULL;
}
toniesJson_item_t *tonies_byAudioId(uint32_t audio_id)
{
    toniesJson_item_t *item = tonies_byAudioIdHash_base(audio_id, NULL, toniesCustomJsonCache, toniesCustomJsonCount);
    if (item)
    {
        return item;
    }
    return tonies_byAudioIdHash_base(audio_id, NULL, toniesJsonCache, toniesJsonCount);
}
toniesJson_item_t *tonies_byAudioIdHash(uint32_t audio_id, uint8_t *hash)
{
    toniesJson_item_t *item = tonies_byAudioIdHash_base(audio_id, hash, toniesCustomJsonCache, toniesCustomJsonCount);
    if (item)
    {
        return item;
    }
    return tonies_byAudioIdHash_base(audio_id, hash, toniesJsonCache, toniesJsonCount);
}
toniesJson_item_t *tonies_byModel_base(char *model, toniesJson_item_t *toniesCache, size_t toniesCount)
{
    if (model == NULL || osStrcmp(model, "") == 0)
        return NULL;
#if TONIES_JSON_CACHED == 1
    for (size_t i = 0; i < toniesCount; i++)
    {
        if (osStrcmp(toniesCache[i].model, model) == 0)
            return &toniesCache[i];
    }
#else
        // cJSON_ParseWithLengthOpts
#endif
    return NULL;
}
toniesJson_item_t *tonies_byModel(char *model)
{
    toniesJson_item_t *item = tonies_byModel_base(model, toniesCustomJsonCache, toniesCustomJsonCount);
    if (item)
    {
        return item;
    }
    return tonies_byModel_base(model, toniesJsonCache, toniesJsonCount);
}
toniesJson_item_t *tonies_byAudioIdHashModel(uint32_t audio_id, uint8_t *hash, char *model)
{
    toniesJson_item_t *item = tonies_byAudioIdHash(audio_id, hash);
    if (item)
    {
        return item;
    }
    return tonies_byModel(model);
}
void tonies_deinit_base(toniesJson_item_t *toniesCache, size_t *toniesCount)
{
#if TONIES_JSON_CACHED == 1
    for (size_t i = 0; i < *toniesCount; i++)
    {
        toniesJson_item_t *item = &toniesCache[i];
        osFreeMem(item->model);
        osFreeMem(item->audio_ids);
        osFreeMem(item->hashes);
        osFreeMem(item->title);
        osFreeMem(item->episodes);
        osFreeMem(item->series);
        osFreeMem(item->language);
        osFreeMem(item->category);
        osFreeMem(item->picture);
    }
    *toniesCount = 0;
    osFreeMem(toniesCache);
#endif
}
void tonies_deinit()
{
    tonies_deinit_base(toniesJsonCache, &toniesJsonCount);
    tonies_deinit_base(toniesCustomJsonCache, &toniesCustomJsonCount);
}