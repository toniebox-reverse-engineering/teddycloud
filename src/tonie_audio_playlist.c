#include "tonie_audio_playlist.h"

#include "fs_port.h"
#include "str.h"
#include "toniefile.h"
#include "server_helpers.h"
#include "cJSON.h"
#include "json_helper.h"
#include "handler.h"
#include "rand.h"

/* Upper bound on playlist entries, matching the fixed source array the
   ffmpeg encoder (ffmpeg_stream/ffmpeg_convert) operates on. */
#define TAP_MAX_FILES 99

bool_t is_valid_tap_file(char *filename)
{

    tonie_audio_playlist_t tap;
    osMemset(&tap, 0, sizeof(tap));
    tap_load(filename, &tap);
    if (tap._valid)
    {
        tap_free(&tap);
        return true;
    }
    return false;
}

error_t tap_load(char *filename, tonie_audio_playlist_t *tap)
{
    size_t fileSize = 0;
    error_t error = fsGetFileSize(filename, (uint32_t *)(&fileSize));
    tap->_cached = false;
    tap->_valid = false;

    if (error != NO_ERROR)
    {
        return error;
    }

    FsFile *fsFile = fsOpenFile(filename, FS_FILE_MODE_READ);
    if (fsFile == NULL)
    {
        return ERROR_FILE_OPENING_FAILED;
    }

    size_t sizeRead;
    char *data = osAllocMem(fileSize);
    size_t pos = 0;

    while (pos < fileSize)
    {
        if (fsReadFile(fsFile, &data[pos], fileSize - pos, &sizeRead) != NO_ERROR || sizeRead == 0)
        {
            break;
        }
        pos += sizeRead;
    }
    fsCloseFile(fsFile);

    cJSON *tapJson = cJSON_ParseWithLengthOpts(data, fileSize, 0, 0);
    osFreeMem(data);
    if (tapJson == NULL)
    {
        // const char *error_ptr = cJSON_GetErrorPtr();
        TRACE_ERROR("Json parse error\r\n");
        error = ERROR_INVALID_FILE;
    }
    else
    {
        tap->type = jsonGetString(tapJson, "type");
        tap->_random = (osStrcmp(tap->type, TAP_TYPE_RANDOM) == 0);
        if (osStrcmp(tap->type, TAP_TYPE_TAP) == 0 || tap->_random)
        {
            tap->audio_id = jsonGetUInt32(tapJson, "audio_id");
            tap->filepath = jsonGetString(tapJson, "filepath");

            tap->_filepath_resolved = strdup(tap->filepath);
            resolveSpecialPathPrefix(&tap->_filepath_resolved, get_settings());

            if (tap->_random)
            {
                tap->directory = jsonGetString(tapJson, "directory");
                resolveSpecialPathPrefix(&tap->directory, get_settings());
            }

            tap->name = jsonGetString(tapJson, "name");
            const cJSON *filesJson = cJSON_GetObjectItemCaseSensitive(tapJson, "files");
            tap->filesCount = cJSON_GetArraySize(filesJson);
            /* The downstream encoder works on a fixed char[TAP_MAX_FILES][PATH_LEN]
               array, so never load more entries than it can process. */
            if (tap->filesCount > TAP_MAX_FILES)
            {
                TRACE_WARNING("TAP has %" PRIuSIZE " files, truncating to %d\r\n", tap->filesCount, TAP_MAX_FILES);
                tap->filesCount = TAP_MAX_FILES;
            }
            if (tap->filesCount > 0)
            {
                tap->files = osAllocMem(tap->filesCount * sizeof(tap_file_t));
                size_t i = 0;
                cJSON *fileJson;
                cJSON_ArrayForEach(fileJson, filesJson)
                {
                    if (i >= tap->filesCount)
                    {
                        break;
                    }
                    tap->files[i].filepath = jsonGetString(fileJson, "filepath");
                    tap->files[i]._filepath_resolved = strdup(tap->files[i].filepath);
                    resolveSpecialPathPrefix(&tap->files[i]._filepath_resolved, get_settings());
                    tap->files[i].name = jsonGetString(fileJson, "name");
                    i++;
                }
            }
        }
        else
        {
            error = ERROR_INVALID_FILE;
        }
    }

    cJSON_Delete(tapJson);
    if (error == NO_ERROR)
    {
        if (isValidTaf(tap->_filepath_resolved, get_settings()->core.tap_taf_validation))
        {
            tap->_cached = true;
            // TODO check audio id if different and check settings.
        }
        tap->_valid = true;
    }
    return error;
}
error_t tap_save(char *filename, tonie_audio_playlist_t *tap)
{

    cJSON *tapJson = cJSON_CreateObject();
    error_t error = NO_ERROR;

    cJSON_AddStringToObject(tapJson, "type", TAP_TYPE_TAP);
    cJSON_AddNumberToObject(tapJson, "audio_id", tap->audio_id);
    cJSON_AddStringToObject(tapJson, "filepath", tap->filepath);
    cJSON_AddStringToObject(tapJson, "name", tap->name);
    if (tap->files != NULL)
    {
        cJSON *filesJson = cJSON_AddArrayToObject(tapJson, "files");
        for (size_t i = 0; i < tap->filesCount; i++)
        {
            cJSON *fileJson = cJSON_CreateObject();
            cJSON_AddStringToObject(fileJson, "filepath", tap->files[i].filepath);
            cJSON_AddStringToObject(fileJson, "name", tap->files[i].name);
            cJSON_AddItemToArray(filesJson, fileJson);
        }
    }
    char *jsonRaw = cJSON_Print(tapJson);

    FsFile *fsFile = fsOpenFile(filename, FS_FILE_MODE_WRITE);
    if (fsFile == NULL)
    {
        error = ERROR_FILE_OPENING_FAILED;
    }
    else
    {
        error = fsWriteFile(fsFile, jsonRaw, osStrlen(jsonRaw));
        fsCloseFile(fsFile);
    }

    cJSON_Delete(tapJson);
    osFreeMem(jsonRaw);
    return error;
}

void tap_free(tonie_audio_playlist_t *tap)
{
    for (size_t i = 0; i < tap->filesCount; i++)
    {
        osFreeMem(tap->files[i].filepath);
        osFreeMem(tap->files[i]._filepath_resolved);
        osFreeMem(tap->files[i].name);
    }
    if (tap->filesCount > 0)
    {
        tap->filesCount = 0;
        osFreeMem(tap->files);
    }
    if (tap->type != NULL)
    {
        osFreeMem(tap->type);
    }
    if (tap->filepath != NULL)
    {
        osFreeMem(tap->filepath);
    }
    if (tap->_filepath_resolved != NULL)
    {
        osFreeMem(tap->_filepath_resolved);
    }
    if (tap->name != NULL)
    {
        osFreeMem(tap->name);
    }
    if (tap->directory != NULL)
    {
        osFreeMem(tap->directory);
    }

    osMemset(tap, 0, sizeof(tonie_audio_playlist_t));
}

/* Reads the audio id and hash of a pool candidate that is a complete TAF: one still being encoded
   or uploaded already has a header, but its file is shorter than the header says. Small files
   (also pipes and devices, which report size 0) are never opened. Only files under the data
   directory can be served. */
static bool_t tap_random_header(const char *path, settings_t *settings, uint32_t *audio_id, uint8_t sha1[20])
{
    uint32_t fileSize = 0;
    if (osStrncmp(path, settings->internal.datadirfull, osStrlen(settings->internal.datadirfull)) != 0 ||
        fsGetFileSize(path, &fileSize) != NO_ERROR || fileSize <= 4096)
    {
        return false;
    }
    FsFile *file = fsOpenFile(path, FS_FILE_MODE_READ);
    if (file == NULL)
    {
        return false;
    }
    TonieboxAudioFileHeader *tafHeader = readTafHeader(file, path);
    fsCloseFile(file);
    bool_t complete = tafHeader != NULL && tafHeader->sha1_hash.len == 20 && (uint64_t)(fileSize - 4096) == tafHeader->num_bytes;
    if (complete)
    {
        *audio_id = tafHeader->audio_id;
        osMemcpy(sha1, tafHeader->sha1_hash.data, 20);
    }
    if (tafHeader != NULL)
    {
        toniebox_audio_file_header__free_unpacked(tafHeader, NULL);
    }
    return complete;
}

static void tap_random_add(char ***paths, size_t *count, size_t *capacity, char *path)
{
    if (*count == *capacity)
    {
        *capacity = (*capacity == 0) ? 64 : *capacity * 2;
        *paths = realloc(*paths, *capacity * sizeof(char *));
    }
    (*paths)[(*count)++] = path;
}

/* The candidates of a pool: the files directly in its directory (no subfolders) and its listed
   files; a listed file that is also in the directory is taken once. Nothing is opened yet. */
static size_t tap_random_candidates(const tonie_audio_playlist_t *tap, char ***paths)
{
    size_t count = 0;
    size_t capacity = 0;
    *paths = NULL;

    if (tap->directory[0] != '\0')
    {
        /* Without its trailing separator, so that a listed file in the folder compares equal. */
        char *dirPath = strdup(tap->directory);
        size_t dirLen = osStrlen(dirPath);
        while (dirLen > 1 && (dirPath[dirLen - 1] == '/' || dirPath[dirLen - 1] == '\\'))
        {
            dirPath[--dirLen] = '\0';
        }
        FsDir *dir = fsOpenDir(dirPath);
        if (dir != NULL)
        {
            FsDirEntry entry;
            while (fsReadDir(dir, &entry) == NO_ERROR)
            {
                if (!(entry.attributes & FS_FILE_ATTR_DIRECTORY))
                {
                    tap_random_add(paths, &count, &capacity, custom_asprintf("%s%c%s", dirPath, PATH_SEPARATOR, entry.name));
                }
            }
            fsCloseDir(dir);
        }
        else
        {
            TRACE_WARNING("Random TAP folder %s cannot be read\r\n", dirPath);
        }
        osFreeMem(dirPath);
    }
    size_t inDirectory = count;
    for (size_t i = 0; i < tap->filesCount; i++)
    {
        bool_t listedTwice = false;
        for (size_t j = 0; j < inDirectory && !listedTwice; j++)
        {
            listedTwice = (osStrcmp((*paths)[j], tap->files[i]._filepath_resolved) == 0);
        }
        if (!listedTwice)
        {
            tap_random_add(paths, &count, &capacity, strdup(tap->files[i]._filepath_resolved));
        }
    }
    return count;
}

/* The candidate a request that continues an earlier pick asks for: the one whose SHA1 starts with
   sha1_prefix (TAP_RANDOM_SHA1_PREFIX bytes) when that is given, else the one with audio_id. Two
   different TAFs that both match (audio ids are often encode times in seconds) make it ambiguous:
   then none is returned, as continuing the wrong one would splice two files. */
static char *tap_random_find(char **paths, size_t count, uint32_t audio_id, const uint8_t *sha1_prefix, settings_t *settings)
{
    char *found = NULL;
    uint8_t foundSha1[20];
    for (size_t i = 0; i < count; i++)
    {
        uint32_t id = 0;
        uint8_t sha1[20];
        if (!tap_random_header(paths[i], settings, &id, sha1) ||
            (sha1_prefix != NULL ? osMemcmp(sha1, sha1_prefix, TAP_RANDOM_SHA1_PREFIX) != 0 : id != audio_id))
        {
            continue;
        }
        if (found != NULL && osMemcmp(sha1, foundSha1, 20) != 0)
        {
            TRACE_WARNING("Random TAP: %s and %s both match the requested TAF\r\n", found, paths[i]);
            return NULL;
        }
        found = paths[i];
        osMemcpy(foundSha1, sha1, 20);
    }
    return found;
}

/* Picks one TAF of a random pool, each equally likely. Only the drawn candidate is opened; one that
   is no complete TAF (a cover, an unfinished encode) is dropped and another drawn, so a request
   costs a few opens, not one per file of the folder. With audio_id != 0 or a sha1_prefix the TAF
   an earlier pick served is picked instead (tap_random_find). Returns ERROR_NOT_FOUND when no TAF
   fits; the caller frees *picked otherwise. */
error_t tap_random_pick(const tonie_audio_playlist_t *tap, uint32_t audio_id, const uint8_t *sha1_prefix, settings_t *settings, char **picked)
{
    char **paths;
    size_t count = tap_random_candidates(tap, &paths);
    bool_t continuing = (audio_id != 0 || sha1_prefix != NULL);
    *picked = NULL;

    if (continuing)
    {
        char *found = tap_random_find(paths, count, audio_id, sha1_prefix, settings);
        if (found != NULL)
        {
            *picked = strdup(found);
        }
    }
    while (!continuing && count > 0 && *picked == NULL)
    {
        /* A failed draw leaves 0 and takes the first candidate. */
        uint32_t draw = 0;
        rand_get_algo()->generate(rand_get_context(), (uint8_t *)&draw, sizeof(draw));
        size_t index = draw % count;
        uint32_t id;
        uint8_t sha1[20];
        if (tap_random_header(paths[index], settings, &id, sha1))
        {
            *picked = paths[index];
        }
        else
        {
            osFreeMem(paths[index]);
        }
        paths[index] = paths[--count];
    }
    for (size_t i = 0; i < count; i++)
    {
        osFreeMem(paths[i]);
    }
    osFreeMem(paths);

    return (*picked != NULL) ? NO_ERROR : ERROR_NOT_FOUND;
}

error_t tap_generate_taf(tonie_audio_playlist_t *tap, size_t *current_source, bool_t *active, bool_t force)
{
    error_t error = NO_ERROR;
    bool_t sweep = false;
    tonie_info_t *tonieInfo = getTonieInfo(tap->_filepath_resolved, false, get_settings());

    // TODO custom audio id resolving
    if (force || !tonieInfo->valid || tonieInfo->tafHeader->audio_id != tap->audio_id)
    {
        char *tmp_taf = custom_asprintf("%s.tmp", tap->_filepath_resolved);
        char source[TAP_MAX_FILES][PATH_LEN];
        if (tap->filesCount == 0 || tap->filesCount > TAP_MAX_FILES)
        {
            osFreeMem(tmp_taf);
            freeTonieInfo(tonieInfo);
            return ERROR_INVALID_FILE;
        }

        for (size_t i = 0; i < tap->filesCount; i++)
        {
            strSafeCopy(source[i], tap->files[i]._filepath_resolved, PATH_LEN);
        }
        // toniefile_t *taf = toniefile_create(tmp_taf, tap->audio_id, false, 0);
        error = ffmpeg_stream(source, tap->filesCount, current_source, tmp_taf, 0, active, &sweep, false, false);
        // toniefile_close(taf);
        if (error != NO_ERROR)
        {
            fsDeleteFile(tmp_taf);
        }
        else
        {
            error = fsMoveFile(tmp_taf, tap->_filepath_resolved, true);
        }
        osFreeMem(tmp_taf);
        freeTonieInfo(tonieInfo);
    }
    return error;
}

void tap_generate_task(void *param)
{
    stream_ctx_t *stream_ctx = (stream_ctx_t *)param;
    tap_generate_param_t *tap_ctx = (tap_generate_param_t *)stream_ctx->ctx;

    stream_ctx->error = tap_generate_taf(tap_ctx->tap, &stream_ctx->current_source, &stream_ctx->active, tap_ctx->force);
    stream_ctx->quit = true;
    osDeleteTask((OsTaskId) OS_SELF_TASK_ID);
}
