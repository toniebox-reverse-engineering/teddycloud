#include "toniesJson.h"
#include "web.h"
#include "fs_port.h"
#include "os_port.h"
#include "settings.h"
#include "debug.h"
#include "cJSON.h"
#include "handler.h"
#include "cloud_request.h"
#include "server_helpers.h"
#include "mutex_manager.h"
#include "hash/sha256.h" // for sha256Update, sha256Final, sha256Init

#define TONIES_JSON_CACHED 1
#if TONIES_JSON_CACHED == 1
static bool toniesJsonInitialized = false;
static size_t toniesJsonCount = 0;
static toniesJson_item_t *toniesJsonCache = NULL;
static size_t toniesCustomJsonCount = 0;
static toniesJson_item_t *toniesCustomJsonCache = NULL;
static char *tonies_json_path = NULL;
static char *tonies_custom_json_path = NULL;
static char *tonies_json_tmp_path = NULL;

static bool toniesV2JsonInitialized = false;
static size_t toniesV2JsonCount = 0;
static toniesV2Json_item_t *toniesV2JsonCache = NULL;
static size_t toniesV2CustomJsonCount = 0;
static toniesV2Json_item_t *toniesV2CustomJsonCache = NULL;
static char *toniesV2_json_path = NULL;
static char *toniesV2_custom_json_path = NULL;
static char *toniesV2_json_tmp_path = NULL;
#endif

void tonies_init()
{
    /* lock tonies cache and update caches */
    mutex_lock(MUTEX_TONIES_JSON_CACHE);
    if (!toniesJsonInitialized)
    {
        toniesCustomJsonCount = 0;
        tonies_json_path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIES_JSON_FILE);
        tonies_custom_json_path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIES_CUSTOM_JSON_FILE);
        tonies_json_tmp_path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIES_JSON_TMP_FILE);

        tonies_readJson(tonies_custom_json_path, &toniesCustomJsonCache, &toniesCustomJsonCount);
        tonies_readJson(tonies_json_path, &toniesJsonCache, &toniesJsonCount);
        toniesJsonInitialized = true;
    }

    if (!toniesV2JsonInitialized)
    {
        toniesV2CustomJsonCount = 0;
        toniesV2_json_path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIESV2_JSON_FILE);
        toniesV2_custom_json_path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIESV2_CUSTOM_JSON_FILE);
        toniesV2_json_tmp_path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIES_JSON_TMP_FILE);

        toniesV2_readJson(toniesV2_custom_json_path, &toniesV2CustomJsonCache, &toniesV2CustomJsonCount);
        toniesV2_readJson(toniesV2_json_path, &toniesV2JsonCache, &toniesV2JsonCount);
        toniesV2JsonInitialized = true;
    }
    mutex_unlock(MUTEX_TONIES_JSON_CACHE);
}

void tonies_downloadBody(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    HttpClientContext *httpClientContext = (HttpClientContext *)cloud_ctx;

    if (httpClientContext->statusCode == 200)
    {
        if (ctx->file == NULL)
        {
            ctx->file = fsOpenFile(tonies_json_tmp_path, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
        }
        error_t errorWrite = NO_ERROR;
        if (length > 0)
        {
            errorWrite = fsWriteFile(ctx->file, (void *)payload, length);
        }

        if (error == ERROR_END_OF_STREAM)
        {
            fsCloseFile(ctx->file);
        }
        else if (error != NO_ERROR)
        {
            fsCloseFile(ctx->file);
            TRACE_ERROR("tonies.json download body error=%s\r\n", error2text(error));
        }
        if (errorWrite != NO_ERROR)
        {
            fsCloseFile(ctx->file);
            TRACE_ERROR("tonies.json (%s) write error=%s\r\n", tonies_json_tmp_path, error2text(error));
        }
    }
}

error_t tonies_update()
{
    TRACE_INFO("Updating tonies.json from api.revvox.de...\r\n");
    cbr_ctx_t ctx;
    client_ctx_t client_ctx = {
        .settings = get_settings(),
    };

    const char *uri_base = "api.revvox.de";
    const char *uri_path = "/tonies.json?source=teddyCloud&version=" BUILD_GIT_SHORT_SHA;
    const char *queryString = NULL;
    fillBaseCtx(NULL, uri_path, queryString, V1_LOG, &ctx, &client_ctx);
    req_cbr_t cbr = {
        .ctx = &ctx,
        .body = &tonies_downloadBody,
    };

    ctx.file = NULL;
    fsDeleteFile(tonies_json_tmp_path);
    // TODO: Be sure HTTPS CA is checked!
    error_t error = web_request(uri_base, 443, true, uri_path, queryString, "GET", NULL, 0, NULL, &cbr, false, false);

    if (error == NO_ERROR && fsFileExists(tonies_json_tmp_path))
    {
        fsDeleteFile(tonies_json_path);
        fsRenameFile(tonies_json_tmp_path, tonies_json_path);
        TRACE_INFO("... success updating tonies.json from api.revvox.de, reloading\r\n");
        tonies_deinit();
        tonies_init();
    }
    else
    {
        TRACE_ERROR("... failed updating tonies.json error=%s\r\n", error2text(error));
    }
    return error;
}

error_t toniesV2_update()
{
    TRACE_INFO("Updating tonies.json from api.revvox.de...\r\n");
    cbr_ctx_t ctx;
    client_ctx_t client_ctx = {
        .settings = get_settings(),
    };

    const char *uri_base = "api.revvox.de";
    const char *uri_path = "/toniesV2.json?source=teddyCloud&version=" BUILD_GIT_SHORT_SHA;
    const char *queryString = NULL;
    fillBaseCtx(NULL, uri_path, queryString, V1_LOG, &ctx, &client_ctx);
    req_cbr_t cbr = {
        .ctx = &ctx,
        .body = &tonies_downloadBody,
    };

    ctx.file = NULL;
    fsDeleteFile(tonies_json_tmp_path);
    // TODO: Be sure HTTPS CA is checked!
    error_t error = web_request(uri_base, 443, true, uri_path, queryString, "GET", NULL, 0, NULL, &cbr, false, false);

    if (error == NO_ERROR && fsFileExists(tonies_json_tmp_path))
    {
        fsDeleteFile(tonies_json_path);
        fsRenameFile(tonies_json_tmp_path, tonies_json_path);
        TRACE_INFO("... success updating tonies.json from api.revvox.de, reloading\r\n");
        tonies_deinit();
        tonies_init();
    }
    else
    {
        TRACE_ERROR("... failed updating tonies.json error=%s\r\n", error2text(error));
    }
    return error;
}

void tonieboxes_downloadBody(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cbr_ctx_t *ctx = (cbr_ctx_t *)src_ctx;
    HttpClientContext *httpClientContext = (HttpClientContext *)cloud_ctx;

    if (httpClientContext->statusCode == 200)
    {
        if (ctx->file == NULL)
        {
            char *target = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIEBOX_JSON_FILE);
            char *target_tmp = custom_asprintf("%s.tmp", target);
            ctx->file = fsOpenFile(target_tmp, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
            osFreeMem(target);
            osFreeMem(target_tmp);
        }
        error_t errorWrite = NO_ERROR;
        if (length > 0)
        {
            errorWrite = fsWriteFile(ctx->file, (void *)payload, length);
        }

        if (error == ERROR_END_OF_STREAM)
        {
            fsCloseFile(ctx->file);
        }
        else if (error != NO_ERROR)
        {
            fsCloseFile(ctx->file);
            TRACE_ERROR("tonieboxes.json download body error=%s\r\n", error2text(error));
        }
        if (errorWrite != NO_ERROR)
        {
            fsCloseFile(ctx->file);
            TRACE_ERROR("tonieboxes.json (%s) write error=%s\r\n", tonies_json_tmp_path, error2text(error));
        }
    }
}
error_t tonieboxes_update()
{
    TRACE_INFO("Updating tonies.json from api.revvox.de...\r\n");
    cbr_ctx_t ctx;
    client_ctx_t client_ctx = {
        .settings = get_settings(),
    };

    char *target = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIEBOX_JSON_FILE);
    char *target_tmp = custom_asprintf("%s.tmp", target);

    const char *uri_base = "api.revvox.de";
    const char *uri_path = "/tonieboxes.json?source=teddyCloud&version=" BUILD_GIT_SHORT_SHA;
    const char *queryString = NULL;
    fillBaseCtx(NULL, uri_path, queryString, V1_LOG, &ctx, &client_ctx);
    req_cbr_t cbr = {
        .ctx = &ctx,
        .body = &tonieboxes_downloadBody,
    };

    ctx.file = NULL;
    fsDeleteFile(target_tmp);
    // TODO: Be sure HTTPS CA is checked!
    error_t error = web_request(uri_base, 443, true, uri_path, queryString, "GET", NULL, 0, NULL, &cbr, false, false);

    if (error == NO_ERROR && fsFileExists(target_tmp))
    {
        fsDeleteFile(target);
        fsRenameFile(target_tmp, target);
        TRACE_INFO("... success updating tonieboxes.json from api.revvox.de, reloading\r\n");
        tonies_deinit();
        tonies_init();
    }
    else
    {
        TRACE_ERROR("... failed updating tonieboxes.json error=%s\r\n", error2text(error));
    }
    osFreeMem(target);
    osFreeMem(target_tmp);
    return error;
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

void tonies_readJson(char *source, toniesJson_item_t **retCache, size_t *retCount)
{
#if TONIES_JSON_CACHED == 1
    size_t toniesCount = 0;
    toniesJson_item_t *toniesCache = NULL;

    size_t fileSize = 0;
    fsGetFileSize(source, (uint32_t *)(&fileSize));
    TRACE_INFO("Trying to read %s with size %zu\r\n", source, fileSize);

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
            toniesCount = cJSON_GetArraySize(toniesJson);
            toniesCache = osAllocMem(toniesCount * sizeof(toniesJson_item_t));
            cJSON_ArrayForEach(tonieJson, toniesJson)
            {
                cJSON *arrayJson;
                toniesJson_item_t *item = &toniesCache[line++];
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

                const cJSON *tracks = cJSON_GetObjectItemCaseSensitive(tonieJson, "tracks");
                item->tracks_count = cJSON_GetArraySize(tracks);
                if (item->tracks_count > 0)
                {
                    item->tracks = osAllocMem(item->tracks_count * sizeof(char *));
                    uint8_t i = 0;
                    const cJSON *track;
                    cJSON_ArrayForEach(track, tracks)
                    {
                        item->tracks[i++] = strdup(track->valuestring);
                    }
                }

                char *releaseString = tonies_jsonGetString(tonieJson, "release");
                item->release = atoi(releaseString);
                osFreeMem(releaseString);
                item->language = tonies_jsonGetString(tonieJson, "language");
                item->category = tonies_jsonGetString(tonieJson, "category");

                char *pic_link = tonies_jsonGetString(tonieJson, "pic");

                if (osStrlen(pic_link) > 0 && settings_get_bool("tonie_json.cache_images"))
                {
                    const char *cachePath = get_settings()->internal.cachedirfull;
                    if (cachePath == NULL || !fsDirExists(cachePath))
                    {
                        char message[128];
                        osSnprintf(message, sizeof(message), "core.cachedirfull not set to a valid path: '%s'", cachePath);
                        TRACE_ERROR("%s\r\n", message);
                    }
                    else
                    {
                        uint8_t sha256_calc[32];
                        char sha256_calc_str[65];

                        /* hash the image URL */
                        Sha256Context ctx;
                        sha256Init(&ctx);
                        sha256Update(&ctx, pic_link, strlen(pic_link));
                        sha256Final(&ctx, sha256_calc);

                        for (int pos = 0; pos < 32; pos++)
                        {
                            osSprintf(&sha256_calc_str[2 * pos], "%02X", sha256_calc[pos]);
                        }

                        /* Find the file extension from the URL */
                        const char *ext_pos = strrchr(pic_link, '.');
                        char *extension = strdup("jpg");

                        if (ext_pos && !osStrchr(ext_pos, '/'))
                        {
                            osFreeMem(extension);
                            extension = strdup(&ext_pos[1]);

                            /* Remove optional HTTP GET parameters */
                            char *query_param = osStrchr(extension, '?');
                            if (query_param)
                            {
                                *query_param = '\0';
                            }
                        }
                        char *cached_filename = custom_asprintf("%s%c%s.%s", cachePath, PATH_SEPARATOR, sha256_calc_str, extension);
                        char *cached_url = custom_asprintf("%s%ccache%c%s.%s", settings_get_string("core.host_url"), PATH_SEPARATOR, PATH_SEPARATOR, sha256_calc_str, extension);

                        osFreeMem(extension);

                        // TRACE_INFO("Original URL: '%s'\r\n", pic_link);
                        // TRACE_INFO("Cache filename would be: '%s'\r\n", cached_filename);
                        TRACE_INFO("Cache URL would be: '%s'\r\n", cached_url);

                        /* check if it is already cached */
                        if (fsFileExists(cached_filename))
                        {
                            // TRACE_INFO("File exists, not downloading\r\n");
                            osFreeMem(pic_link);
                            pic_link = strdup(cached_url);
                        }
                        else
                        {
                            if (settings_get_bool("tonie_json.cache_preload"))
                            {
                                /* try to download and cache the file */
                                // TRACE_INFO("Download file from original URL\r\n");

                                error_t err = web_download(pic_link, cached_filename);
                                if (err == NO_ERROR)
                                {
                                    osFreeMem(pic_link);
                                    pic_link = strdup(cached_url);
                                }
                            }
                            else
                            {
                                // TRACE_INFO("Link to original URL\r\n");
                                char *url_filename = custom_asprintf("%s.url", cached_filename);
                                FsFile *url_file = fsOpenFile(url_filename, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
                                if (!url_file)
                                {
                                    TRACE_ERROR("Failed to open file for writing %s\r\n", url_filename);
                                }
                                else
                                {
                                    fsWriteFile(url_file, (void *)pic_link, osStrlen(pic_link));
                                    fsCloseFile(url_file);
                                }
                                osFreeMem(url_filename);
                            }
                        }
                        osFreeMem(cached_filename);
                        osFreeMem(cached_url);
                    }
                }
                item->picture = pic_link;
            }
            cJSON_Delete(toniesJson);
        }
    }
    else
    {
        TRACE_INFO("Create empty json file\r\n");
        fsFile = fsOpenFile(source, FS_FILE_MODE_WRITE);
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

    /* first save old pointer, then update return values */
    void *oldPtr = *retCache;

    *retCache = toniesCache;
    *retCount = toniesCount;

    if (oldPtr)
    {
        osFreeMem(oldPtr);
    }
#endif
}

void toniesV2_readJson(char *source, toniesV2Json_item_t **toniesCache, size_t *toniesCount)
{
#if TONIES_JSON_CACHED == 1

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
    mutex_lock(MUTEX_TONIES_JSON_CACHE);
    toniesJson_item_t *item = tonies_byAudioIdHash_base(audio_id, NULL, toniesCustomJsonCache, toniesCustomJsonCount);

    if (!item)
    {
        item = tonies_byAudioIdHash_base(audio_id, NULL, toniesJsonCache, toniesJsonCount);
    }

    mutex_unlock(MUTEX_TONIES_JSON_CACHE);
    return item;
}

toniesJson_item_t *tonies_byAudioIdHash(uint32_t audio_id, uint8_t *hash)
{
    mutex_lock(MUTEX_TONIES_JSON_CACHE);
    toniesJson_item_t *item = tonies_byAudioIdHash_base(audio_id, hash, toniesCustomJsonCache, toniesCustomJsonCount);
    if (!item)
    {
        item = tonies_byAudioIdHash_base(audio_id, hash, toniesJsonCache, toniesJsonCount);
    }

    mutex_unlock(MUTEX_TONIES_JSON_CACHE);
    return item;
}

toniesJson_item_t *tonies_byModel_base(char *model, toniesJson_item_t *toniesCache, size_t toniesCount)
{
    if (model == NULL || osStrcmp(model, "") == 0)
        return NULL;
#if TONIES_JSON_CACHED == 1
    for (size_t i = 0; i < toniesCount; i++)
    {
        if (osStrcasecmp(toniesCache[i].model, model) == 0)
            return &toniesCache[i];
    }
#else
        // cJSON_ParseWithLengthOpts
#endif
    return NULL;
}

toniesJson_item_t *tonies_byModel(char *model)
{
    mutex_lock(MUTEX_TONIES_JSON_CACHE);

    toniesJson_item_t *item = tonies_byModel_base(model, toniesCustomJsonCache, toniesCustomJsonCount);
    if (!item)
    {
        item = tonies_byModel_base(model, toniesJsonCache, toniesJsonCount);
    }

    mutex_unlock(MUTEX_TONIES_JSON_CACHE);
    return item;
}

toniesJson_item_t *tonies_byAudioIdHashModel(uint32_t audio_id, uint8_t *hash, char *model)
{
    toniesJson_item_t *item = tonies_byAudioIdHash(audio_id, hash);
    if (!item)
    {
        item = tonies_byModel(model);
    }

    return item;
}

const char *tonies_strcasestr(const char *haystack, const char *needle)
{
    while (*haystack)
    {
        const char *h = haystack;
        const char *n = needle;

        // Compare strings case-insensitively
        while (*h && *n && (tolower(*h) == tolower(*n)))
        {
            h++;
            n++;
        }

        // If the end of needle is reached, match found
        if (!*n)
        {
            return haystack;
        }

        haystack++;
    }

    return NULL;
}

bool tonies_byModelSeriesEpisode_base(char *model, char *series, char *episode, toniesJson_item_t *result[18], size_t *result_size, size_t max_slots, toniesJson_item_t *toniesCache, size_t toniesCount)
{
#if TONIES_JSON_CACHED == 1
    size_t count = *result_size;

    if (model != NULL && osStrlen(model) > 0)
    {
        size_t count_model = 0;
        for (size_t i = 0; i < toniesCount; i++)
        {
            if (count >= max_slots || count_model >= (max_slots - count) / 3)
            {
                break;
            }
            if (tonies_strcasestr(toniesCache[i].model, model) != NULL)
            {
                bool duplicate = false;
                for (size_t j = 0; j < count; j++)
                {
                    if (osStrcasecmp(result[j]->model, toniesCache[i].model) == 0)
                    {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate)
                {
                    result[count++] = &toniesCache[i];
                    count_model++;
                }
            }
        }
    }
    if (series != NULL && osStrlen(series) > 0)
    {
        size_t count_series = 0;
        for (size_t i = 0; i < toniesCount; i++)
        {
            if (count >= max_slots || count_series >= (max_slots - count) / 2)
            {
                break;
            }
            if (tonies_strcasestr(toniesCache[i].series, series) != NULL)
            {
                bool duplicate = false;
                for (size_t j = 0; j < count; j++)
                {
                    if (osStrcasecmp(result[j]->model, toniesCache[i].model) == 0)
                    {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate)
                {
                    result[count++] = &toniesCache[i];
                    count_series++;
                }
            }
        }
    }
    if (episode != NULL && osStrlen(episode) > 0)
    {
        size_t count_episode = 0;
        for (size_t i = 0; i < toniesCount; i++)
        {
            if (count >= max_slots || count_episode >= (max_slots - count) / 1)
            {
                break;
            }
            if (tonies_strcasestr(toniesCache[i].episodes, episode) != NULL)
            {
                bool duplicate = false;
                for (size_t j = 0; j < count; j++)
                {
                    if (osStrcasecmp(result[j]->model, toniesCache[i].model) == 0)
                    {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate)
                {
                    result[count++] = &toniesCache[i];
                    count_episode++;
                }
            }
        }
    }
    *result_size = count;
    return *result_size > 0;
#else
    return false;
#endif
}

bool tonies_byModelSeriesEpisode(char *model, char *series, char *episode, toniesJson_item_t *result[18], size_t *result_size)
{
    size_t count = 0;
    mutex_lock(MUTEX_TONIES_JSON_CACHE);
    tonies_byModelSeriesEpisode_base(model, series, episode, result, &count, 9, toniesCustomJsonCache, toniesCustomJsonCount);
    tonies_byModelSeriesEpisode_base(model, series, episode, result, &count, 18, toniesJsonCache, toniesJsonCount);
    mutex_unlock(MUTEX_TONIES_JSON_CACHE);
    *result_size = count;
    return *result_size > 0;
}

void tonies_deinit_base(toniesJson_item_t *toniesCache, size_t *toniesCount)
{
#if TONIES_JSON_CACHED == 1
    size_t count = *toniesCount;
    *toniesCount = 0;
    for (size_t i = 0; i < count; i++)
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
        if (item->tracks_count > 0)
        {
            for (size_t track = 0; track < item->tracks_count; track++)
            {
                osFreeMem(item->tracks[track]);
            }
            osFreeMem(item->tracks);
        }
    }
    osFreeMem(toniesCache);
#endif
}

void tonies_deinit()
{
    mutex_lock(MUTEX_TONIES_JSON_CACHE);
    tonies_deinit_base(toniesJsonCache, &toniesJsonCount);
    tonies_deinit_base(toniesCustomJsonCache, &toniesCustomJsonCount);

    toniesJsonCache = NULL;
    toniesCustomJsonCache = NULL;

    osFreeMem(tonies_json_path);
    osFreeMem(tonies_custom_json_path);
    osFreeMem(tonies_json_tmp_path);

    tonies_json_path = NULL;
    tonies_custom_json_path = NULL;
    tonies_json_tmp_path = NULL;

    toniesJsonInitialized = false;
    mutex_unlock(MUTEX_TONIES_JSON_CACHE);
}
