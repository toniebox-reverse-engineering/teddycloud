
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "path.h"
#include "path_ext.h"
#include "server_helpers.h"
#include "fs_port.h"
#include "handler.h"
#include "handler_api.h"
#include "handler_cloud.h"
#include "settings.h"
#include "stats.h"
#include "returncodes.h"
#include "cJSON.h"
#include "toniefile.h"
#include "toniesJson.h"
#include "fs_ext.h"
#include "os_ext.h"
#include "cert.h"
#include "esp32.h"
#include "cache.h"

error_t parsePostData(HttpConnection *connection, char_t *post_data, size_t buffer_size)
{
    error_t error = NO_ERROR;
    osMemset(post_data, 0, buffer_size);
    size_t size;
    if (buffer_size > 0 && buffer_size <= connection->request.byteCount)
    {
        TRACE_ERROR("Body size %" PRIuSIZE " bigger than buffer size %" PRIuSIZE " bytes\r\n", connection->request.byteCount, buffer_size);
        return ERROR_BUFFER_OVERFLOW;
    }
    error = httpReceive(connection, post_data, buffer_size, &size, 0x00);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Could not read post data\r\n");
        return error;
    }
    return error;
}

/* sanitizes the path - needs two additional characters in worst case, so make sure 'path' has enough space */
void sanitizePath(char *path, bool isDir)
{
    size_t i, j;
    bool slash = false;

    pathCanonicalize(path);

    /* Merge all double (or more) slashes // */
    for (i = 0, j = 0; path[i]; ++i)
    {
        if (path[i] == PATH_SEPARATOR)
        {
            if (slash)
                continue;
            slash = true;
        }
        else
        {
            slash = false;
        }
        path[j++] = path[i];
    }

    /* Make sure the path doesn't end with a '/' unless it's the root directory. */
    if (j > 1 && path[j - 1] == PATH_SEPARATOR)
        j--;

    /* Null terminate the sanitized path */
    path[j] = '\0';

#ifndef WIN32
    /* If path doesn't start with '/', shift right and add '/' */
    if (path[0] != PATH_SEPARATOR)
    {
        memmove(&path[1], &path[0], j + 1); // Shift right
        path[0] = PATH_SEPARATOR;           // Add '/' at the beginning
        j++;
    }
#endif

    /* If path doesn't end with '/', add '/' at the end */
    if (isDir)
    {
        if (path[j - 1] != PATH_SEPARATOR)
        {
            path[j] = PATH_SEPARATOR; // Add '/' at the end
            path[j + 1] = '\0';       // Null terminate
        }
    }
}

error_t queryPrepare(const char *queryString, const char **rootPath, char *overlay, size_t overlay_size, settings_t **settings)
{
    char special[16];

    osStrcpy(special, "");

    if (overlay)
    {
        osStrcpy(overlay, "");
        if (queryGet(queryString, "overlay", overlay, overlay_size))
        {
            TRACE_DEBUG("got overlay '%s'\r\n", overlay);

            *settings = get_settings_ovl(overlay);
        }
    }

    *rootPath = settings_get_string_ovl("internal.contentdirfull", overlay);

    if (*rootPath == NULL || !fsDirExists(*rootPath))
    {
        TRACE_ERROR("internal.contentdirfull not set to a valid path: '%s'\r\n", *rootPath);
        return ERROR_FAILURE;
    }

    if (queryGet(queryString, "special", special, sizeof(special)))
    {
        TRACE_DEBUG("requested index for '%s'\r\n", special);
        if (!osStrcmp(special, "library"))
        {
            *rootPath = settings_get_string_ovl("internal.librarydirfull", overlay);

            if (*rootPath == NULL || !fsDirExists(*rootPath))
            {
                TRACE_ERROR("internal.librarydirfull not set to a valid path: '%s'\r\n", *rootPath);
                return ERROR_FAILURE;
            }
        }
        else if (!osStrcmp(special, "custom_img"))
        {
            const char *wwwDir = settings_get_string_ovl("internal.wwwdirfull", overlay);
            if (wwwDir == NULL || osStrlen(wwwDir) == 0)
            {
                TRACE_ERROR("internal.wwwdirfull not set to a valid path: '%s'\r\n", wwwDir);
                return ERROR_FAILURE;
            }

            static char customImgDir[1024];
            osSnprintf(customImgDir, sizeof(customImgDir), "%s%c%s", wwwDir, PATH_SEPARATOR, "custom_img");

            if (!fsDirExists(customImgDir))
            {
                error_t createErr = fsCreateDirEx(customImgDir, true);
                if (createErr != NO_ERROR || !fsDirExists(customImgDir))
                {
                    TRACE_ERROR("custom_img dir '%s' does not exist and could not be created. Error: %s\r\n", customImgDir, error2text(createErr));
                    return ERROR_FAILURE;
                }
            }

            *rootPath = customImgDir;
        }
    }

    return NO_ERROR;
}

void addToniesJsonInfoJson(toniesJson_item_t *item, char *fallbackModel, cJSON *parent)
{
    cJSON *tracksJson = cJSON_CreateArray();
    cJSON *tonieInfoJson;
    if (parent->type == cJSON_Object)
    {
        tonieInfoJson = cJSON_AddObjectToObject(parent, "tonieInfo");
    }
    else if (parent->type == cJSON_Array)
    {
        tonieInfoJson = cJSON_CreateObject();
        cJSON_AddItemToArray(parent, tonieInfoJson);
    }
    else
    {
        return;
    }

    cJSON_AddItemToObject(tonieInfoJson, "tracks", tracksJson);
    if (item != NULL)
    {
        cJSON_AddStringToObject(tonieInfoJson, "model", item->model);
        cJSON_AddStringToObject(tonieInfoJson, "series", item->series);
        cJSON_AddStringToObject(tonieInfoJson, "episode", item->episodes);
        cJSON_AddStringToObject(tonieInfoJson, "picture", item->picture);
        cJSON_AddStringToObject(tonieInfoJson, "language", item->language);
        for (size_t i = 0; i < item->tracks_count; i++)
        {
            cJSON_AddItemToArray(tracksJson, cJSON_CreateString(item->tracks[i]));
        }
    }
    else
    {
        if (fallbackModel != NULL)
        {
            cJSON_AddStringToObject(tonieInfoJson, "model", fallbackModel);
        }
        else
        {
            cJSON_AddStringToObject(tonieInfoJson, "model", "");
        }
        cJSON_AddStringToObject(tonieInfoJson, "series", "");
        cJSON_AddStringToObject(tonieInfoJson, "episode", "");

        cJSON_AddStringToObject(tonieInfoJson, "picture", "/img_unknown.png");
    }
}

error_t handleApiAssignUnknown(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    const char *rootPath = NULL;

    TRACE_INFO("Query: '%s'\r\n", queryString);

    char path[256];
    char overlay[16];

    osStrcpy(path, "");

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    if (queryGet(queryString, "path", path, sizeof(path)))
    {
        TRACE_INFO("got path '%s'\r\n", path);
    }

    /* important: first canonicalize path, then merge to prevent directory traversal attacks */
    pathSafeCanonicalize(path);
    char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);
    pathSafeCanonicalize(pathAbsolute);

    TRACE_INFO("Set '%s' for next unknown request\r\n", pathAbsolute);

    settings_set_string("internal.assign_unknown", pathAbsolute);
    osFreeMem(pathAbsolute);

    return httpOkResponse(connection);
}

error_t handleApiGetIndex(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *jsonArray = cJSON_AddArrayToObject(json, "options");

    char overlay[16];
    osStrcpy(overlay, "");
    char internal[6];
    osStrcpy(internal, "");
    char noLevel[6];
    osStrcpy(noLevel, "");

    bool showInternal = false;
    bool isNoLevel = false;

    if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
    {
        TRACE_DEBUG("got overlay '%s'\r\n", overlay);
    }
    if (queryGet(queryString, "internal", internal, sizeof(internal)))
    {
        if (internal[0] == 't')
        {
            showInternal = true;
        }
    }
    if (queryGet(queryString, "nolevel", noLevel, sizeof(internal)))
    {
        if (noLevel[0] == 't')
        {
            isNoLevel = true;
        }
    }
    for (size_t pos = 0; pos < settings_get_size(); pos++)
    {
        setting_item_t *opt = settings_get_ovl(pos, overlay);

        if (opt->type == TYPE_TREE_DESC)
        {
            continue;
        }

        if (opt->internal && !showInternal)
        {
            continue;
        }

        settings_level user_level = get_settings_ovl(overlay)->core.settings_level;
        if (!isNoLevel && opt->level > user_level)
        {
            continue;
        }

        cJSON *jsonEntry = cJSON_CreateObject();
        cJSON_AddStringToObject(jsonEntry, "ID", opt->option_name);
        cJSON_AddStringToObject(jsonEntry, "shortname", opt->option_name);
        cJSON_AddStringToObject(jsonEntry, "description", opt->description);
        cJSON_AddStringToObject(jsonEntry, "label", opt->label);
        cJSON_AddBoolToObject(jsonEntry, "overlayed", opt->overlayed);
        cJSON_AddBoolToObject(jsonEntry, "internal", opt->internal);
        cJSON_AddNumberToObject(jsonEntry, "level", opt->level);

        switch (opt->type)
        {
        case TYPE_BOOL:
            cJSON_AddStringToObject(jsonEntry, "type", "bool");
            cJSON_AddBoolToObject(jsonEntry, "value", settings_get_bool_ovl(opt->option_name, overlay));
            cJSON_AddBoolToObject(jsonEntry, "valueInit", opt->init.bool_value);
            break;
        case TYPE_UNSIGNED:
            cJSON_AddStringToObject(jsonEntry, "type", "uint");
            cJSON_AddNumberToObject(jsonEntry, "value", settings_get_unsigned_ovl(opt->option_name, overlay));
            cJSON_AddNumberToObject(jsonEntry, "valueInit", opt->init.unsigned_value);
            cJSON_AddNumberToObject(jsonEntry, "min", opt->min.unsigned_value);
            cJSON_AddNumberToObject(jsonEntry, "max", opt->max.unsigned_value);
            break;
        case TYPE_SIGNED:
            cJSON_AddStringToObject(jsonEntry, "type", "int");
            cJSON_AddNumberToObject(jsonEntry, "value", settings_get_signed_ovl(opt->option_name, overlay));
            cJSON_AddNumberToObject(jsonEntry, "valueInit", opt->init.signed_value);
            cJSON_AddNumberToObject(jsonEntry, "min", opt->min.signed_value);
            cJSON_AddNumberToObject(jsonEntry, "max", opt->max.signed_value);
            break;
        case TYPE_HEX:
            cJSON_AddStringToObject(jsonEntry, "type", "hex");
            cJSON_AddNumberToObject(jsonEntry, "value", settings_get_unsigned_ovl(opt->option_name, overlay));
            cJSON_AddNumberToObject(jsonEntry, "valueInit", opt->init.unsigned_value);
            cJSON_AddNumberToObject(jsonEntry, "min", opt->min.unsigned_value);
            cJSON_AddNumberToObject(jsonEntry, "max", opt->max.unsigned_value);
            break;
        case TYPE_STRING:
            cJSON_AddStringToObject(jsonEntry, "type", "string");
            cJSON_AddStringToObject(jsonEntry, "value", settings_get_string_ovl(opt->option_name, overlay));
            cJSON_AddStringToObject(jsonEntry, "valueInit", opt->init.string_value);
            break;
        case TYPE_FLOAT:
            cJSON_AddStringToObject(jsonEntry, "type", "float");
            cJSON_AddNumberToObject(jsonEntry, "value", settings_get_float_ovl(opt->option_name, overlay));
            cJSON_AddNumberToObject(jsonEntry, "valueInit", opt->init.float_value);
            cJSON_AddNumberToObject(jsonEntry, "min", opt->min.float_value);
            cJSON_AddNumberToObject(jsonEntry, "max", opt->max.float_value);
            break;
        case TYPE_TREE_DESC:
            cJSON_AddStringToObject(jsonEntry, "type", "desc");
            break;
        default:
            break;
        }

        cJSON_AddItemToArray(jsonArray, jsonEntry);
    }

    char *jsonString = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(jsonString);

    return httpWriteResponse(connection, jsonString, connection->response.contentLength, true);
}

error_t handleApiGetBoxes(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *jsonArray = cJSON_AddArrayToObject(json, "boxes");

    for (size_t i = 1; i < MAX_OVERLAYS; i++)
    {
        settings_t *settings = get_settings_id(i);
        if (!settings->internal.config_used)
        {
            continue;
        }

        cJSON *jsonEntry = cJSON_CreateObject();
        cJSON_AddStringToObject(jsonEntry, "ID", settings->internal.overlayUniqueId);
        cJSON_AddStringToObject(jsonEntry, "commonName", settings->commonName);
        cJSON_AddStringToObject(jsonEntry, "boxName", settings->boxName);
        cJSON_AddStringToObject(jsonEntry, "boxModel", settings->boxModel); // TODO add color name + url

        cJSON_AddItemToArray(jsonArray, jsonEntry);
    }

    char *jsonString = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(jsonString);

    return httpWriteResponse(connection, jsonString, connection->response.contentLength, true);
}

error_t handleApiTrigger(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    const char *item = &uri[5];
    char response[256];

    osSprintf(response, "FAILED");

    if (!strcmp(item, "triggerExit"))
    {
        TRACE_INFO("Triggered Exit\r\n");
        settings_set_bool("internal.exit", TRUE);
        settings_set_signed("internal.returncode", RETURNCODE_USER_QUIT);
        osSprintf(response, "OK");
    }
    else if (!strcmp(item, "triggerRestart"))
    {
        TRACE_INFO("Triggered Restart\r\n");
        settings_set_bool("internal.exit", TRUE);
        settings_set_signed("internal.returncode", RETURNCODE_USER_RESTART);
        osSprintf(response, "OK");
    }
    else if (!strcmp(item, "triggerReloadConfig"))
    {
        TRACE_INFO("Triggered ReloadConfig\r\n");
        osSprintf(response, "OK");
        settings_load();
    }
    else if (!strcmp(item, "triggerWriteConfig"))
    {
        TRACE_INFO("Triggered WriteConfig\r\n");
        osSprintf(response, "OK");
        settings_save();
    }

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/plain";
    connection->response.contentLength = osStrlen(response);

    return httpWriteResponse(connection, response, connection->response.contentLength, false);
}

error_t handleApiSettingsGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    const char *item = &uri[18];

    char response[32];
    osStrcpy(response, "ERROR");
    const char *response_ptr = response;

    char overlay[16];
    osStrcpy(overlay, "");
    if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
    {
        TRACE_DEBUG("got overlay '%s'\r\n", overlay);
    }
    setting_item_t *opt = settings_get_by_name_ovl(item, overlay);

    if (opt == NULL)
    {
        return ERROR_NOT_FOUND;
    }

    if (opt->level != LEVEL_SECRET)
    {
        switch (opt->type)
        {
        case TYPE_BOOL:
            osSprintf(response, "%s", settings_get_bool_ovl(item, overlay) ? "true" : "false");
            break;
        case TYPE_HEX:
        case TYPE_UNSIGNED:
            osSprintf(response, "%u", settings_get_unsigned_ovl(item, overlay));
            break;
        case TYPE_SIGNED:
            osSprintf(response, "%d", settings_get_signed_ovl(item, overlay));
            break;
        case TYPE_STRING:
            response_ptr = settings_get_string_ovl(item, overlay);
            break;
        case TYPE_FLOAT:
            osSprintf(response, "%f", settings_get_float_ovl(item, overlay));
            break;
        default:
            break;
        }
    }

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/plain";
    connection->response.contentLength = osStrlen(response_ptr);

    return httpWriteResponse(connection, (char_t *)response_ptr, connection->response.contentLength, false);
}

error_t handleApiSettingsSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char response[256];
    osSprintf(response, "ERROR");
    const char *item = &uri[18];

    char_t data[BODY_BUFFER_SIZE];
    size_t size;
    if (BODY_BUFFER_SIZE <= connection->request.byteCount)
    {
        TRACE_ERROR("Body size for setting '%s' %" PRIuSIZE " bigger than buffer size %i bytes\r\n", item, connection->request.byteCount, BODY_BUFFER_SIZE);
    }
    else
    {
        if (connection->request.byteCount > 0)
        {
            error_t error = httpReceive(connection, &data, BODY_BUFFER_SIZE, &size, 0x00);
            if (error != NO_ERROR)
            {
                TRACE_ERROR("httpReceive failed!\r\n");
                return error;
            }
        }
        else
        {
            size = 0;
        }
        data[size] = '\0';

        TRACE_INFO("Setting: '%s' to '%s'\r\n", item, data);

        char overlay[16];
        osStrcpy(overlay, "");
        if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
        {
            TRACE_DEBUG("got overlay '%s'\r\n", overlay);
        }

        bool success = false;
        if (size > 0)
        {
            success = settings_set_by_string_ovl(item, data, overlay);
        }

        if (success)
        {
            osStrcpy(response, "OK");
        }
    }

    httpPrepareHeader(connection, "text/plain; charset=utf-8", 0);
    return httpWriteResponseString(connection, response, false);
}
error_t handleApiSettingsReset(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char response[256];
    osSprintf(response, "ERROR");
    const char *item = &uri[20];
    char overlay[16];
    osStrcpy(overlay, "");
    if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
    {
        TRACE_DEBUG("got overlay '%s'\r\n", overlay);
    }
    setting_item_t *opt = settings_get_by_name_ovl(item, overlay);
    setting_item_t *opt_src = settings_get_by_name(item);
    bool success = false;

    if (opt && opt_src)
    {
        if (opt->overlayed || opt == opt_src)
        {
            overlay_settings_init_opt(opt, opt_src);
            if (opt == opt_src)
            {
                TRACE_INFO("Setting: '%s' reset to default\r\n", item);
            }
            else
            {
                TRACE_INFO("Setting: '%s' overlay removed\r\n", item);
            }
            success = true;
        }
        else
        {
            TRACE_WARNING("Setting '%s' is not overlayed\r\n", item);
        }
    }
    else
    {
        TRACE_ERROR("Setting '%s' is unknown\r\n", item);
    }

    if (success)
    {
        osStrcpy(response, "OK");
    }

    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(response));
    return httpWriteResponseString(connection, response, false);
}

error_t handleApiFileIndexV2(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    char special[16];
    const char *rootPath = NULL;

    osStrcpy(special, "");
    queryGet(queryString, "special", special, sizeof(special));

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    char path[128];

    if (!queryGet(queryString, "path", path, sizeof(path)))
    {
        osStrcpy(path, "/");
    }

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    pathSafeCanonicalize(path);
    char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);
    pathSafeCanonicalize(pathAbsolute);

    FsDir *dir = fsOpenDir(pathAbsolute);
    if (dir == NULL)
    {
        TRACE_ERROR("Failed to open dir '%s'\r\n", pathAbsolute);
        osFreeMem(pathAbsolute);
        return ERROR_FAILURE;
    }

    cJSON *json = cJSON_CreateObject();
    cJSON *jsonArray = cJSON_AddArrayToObject(json, "files");

    /* Fast path for custom_img: skip TAF parsing and content.json - images need only name, date, size, isDir */
    bool_t isCustomImg = (osStrcmp(special, "custom_img") == 0);

    while (true)
    {
        FsDirEntry entry;

        if (fsReadDir(dir, &entry) != NO_ERROR)
        {
            fsCloseDir(dir);
            break;
        }

        if (!osStrcmp(entry.name, "."))
        {
            continue;
        }
        if (!osStrcmp(entry.name, "..") && path[0] == '\0')
        {
            continue;
        }
        bool isDir = (entry.attributes & FS_FILE_ATTR_DIRECTORY);
        char *filePathAbsolute = custom_asprintf("%s%c%s", pathAbsolute, PATH_SEPARATOR, entry.name);
        pathSafeCanonicalize(filePathAbsolute);

        cJSON *jsonEntry = cJSON_CreateObject();
        cJSON_AddStringToObject(jsonEntry, "name", entry.name);
        cJSON_AddNumberToObject(jsonEntry, "date", convertDateToUnixTime(&entry.modified));
        cJSON_AddNumberToObject(jsonEntry, "size", entry.size);
        cJSON_AddBoolToObject(jsonEntry, "isDir", isDir);

        if (isCustomImg)
        {
            /* custom_img: no TAF, no content.json - just basic file info */
            osFreeMem(filePathAbsolute);
            cJSON_AddItemToArray(jsonArray, jsonEntry);
            continue;
        }

        tonie_info_t *tafInfo = getTonieInfo(filePathAbsolute, false, client_ctx->settings);
        toniesJson_item_t *item = NULL;
        if (tafInfo->valid)
        {
            cJSON *tafHeaderEntry = cJSON_AddObjectToObject(jsonEntry, "tafHeader");
            cJSON_AddNumberToObject(tafHeaderEntry, "audioId", tafInfo->tafHeader->audio_id);
            char sha1Hash[41];
            sha1Hash[0] = '\0';
            for (int pos = 0; pos < tafInfo->tafHeader->sha1_hash.len; pos++)
            {
                char tmp[3];
                osSprintf(tmp, "%02x", tafInfo->tafHeader->sha1_hash.data[pos]);
                osStrcat(sha1Hash, tmp);
            }
            cJSON_AddStringToObject(tafHeaderEntry, "sha1Hash", sha1Hash);
            cJSON_AddNumberToObject(tafHeaderEntry, "size", tafInfo->tafHeader->num_bytes);
            cJSON_AddBoolToObject(tafHeaderEntry, "valid", tafInfo->valid);
            cJSON *tracksArray = cJSON_AddArrayToObject(tafHeaderEntry, "trackSeconds");
            for (size_t i = 0; i < tafInfo->additional.track_positions.count; i++)
            {
                cJSON_AddItemToArray(tracksArray, cJSON_CreateNumber(tafInfo->additional.track_positions.pos[i]));
            }

            item = tonies_byAudioIdHashModel(tafInfo->tafHeader->audio_id, tafInfo->tafHeader->sha1_hash.data, tafInfo->json.tonie_model);
        }
        else
        {
            char *json_extension = NULL;
            if (isDir)
            {
                char *filePathAbsoluteSub = NULL;
                FsDir *subdir = fsOpenDir(filePathAbsolute);
                FsDirEntry subentry;
                if (subdir != NULL)
                {
                    while (true)
                    {
                        if (fsReadDir(subdir, &subentry) != NO_ERROR || item != NULL)
                        {
                            fsCloseDir(subdir);
                            break;
                        }
                        filePathAbsoluteSub = custom_asprintf("%s%c%s", filePathAbsolute, PATH_SEPARATOR, subentry.name);

                        json_extension = osStrstr(filePathAbsoluteSub, ".json");
                        if (json_extension != NULL)
                        {
                            *json_extension = '\0';
                        }

                        contentJson_t contentJson = {0};
                        load_content_json(filePathAbsoluteSub, &contentJson, false, client_ctx->settings);
                        item = tonies_byModel(contentJson.tonie_model);
                        osFreeMem(filePathAbsoluteSub);
                        cJSON_AddBoolToObject(jsonEntry, "hide", contentJson.hide);
                        free_content_json(&contentJson);
                    }
                }
            }
            else
            {
                json_extension = osStrstr(filePathAbsolute, ".json");
                if (json_extension != NULL)
                {
                    *json_extension = '\0';
                }
                contentJson_t contentJson = {0};
                load_content_json(filePathAbsolute, &contentJson, false, client_ctx->settings);
                item = tonies_byModel(contentJson.tonie_model);

                cJSON_AddBoolToObject(jsonEntry, "hide", contentJson.hide);
                if (contentJson._has_cloud_auth)
                {
                    cJSON_AddBoolToObject(jsonEntry, "has_cloud_auth", true);
                }
                free_content_json(&contentJson);
            }
        }
        if (item != NULL)
        {
            addToniesJsonInfoJson(item, NULL, jsonEntry);
        }
        freeTonieInfo(tafInfo);

        osFreeMem(filePathAbsolute);
        cJSON_AddItemToArray(jsonArray, jsonEntry);
    }

    osFreeMem(pathAbsolute);
    char *jsonString = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(jsonString);

    return httpWriteResponse(connection, jsonString, connection->response.contentLength, true);
}
error_t handleApiFileIndex(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char *jsonString = strdup("{\"files\":[]}"); // Make warning go away

    do
    {
        char overlay[16];
        const char *rootPath = NULL;

        if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
        {
            osFreeMem(jsonString);
            return ERROR_FAILURE;
        }

        char path[128];

        if (!queryGet(queryString, "path", path, sizeof(path)))
        {
            osStrcpy(path, "/");
        }

        /* first canonicalize path, then merge to prevent directory traversal bugs */
        pathSafeCanonicalize(path);
        char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);
        pathSafeCanonicalize(pathAbsolute);

        int pos = 0;
        FsDir *dir = fsOpenDir(pathAbsolute);
        if (dir == NULL)
        {
            TRACE_ERROR("Failed to open dir '%s'\r\n", pathAbsolute);
            osFreeMem(pathAbsolute);
            break;
        }

        cJSON *json = cJSON_CreateObject();
        cJSON *jsonArray = cJSON_AddArrayToObject(json, "files");

        while (true)
        {
            FsDirEntry entry;

            if (fsReadDir(dir, &entry) != NO_ERROR)
            {
                fsCloseDir(dir);
                break;
            }

            if (!osStrcmp(entry.name, ".") || !osStrcmp(entry.name, ".."))
            {
                continue;
            }
            bool isDir = (entry.attributes & FS_FILE_ATTR_DIRECTORY);
            char dateString[64];

            osSnprintf(dateString, sizeof(dateString), " %04" PRIu16 "-%02" PRIu8 "-%02" PRIu8 ",  %02" PRIu8 ":%02" PRIu8 ":%02" PRIu8,
                       entry.modified.year, entry.modified.month, entry.modified.day,
                       entry.modified.hours, entry.modified.minutes, entry.modified.seconds);

            char *filePathAbsolute = custom_asprintf("%s%c%s", pathAbsolute, PATH_SEPARATOR, entry.name);
            pathSafeCanonicalize(filePathAbsolute);

            cJSON *jsonEntry = cJSON_CreateObject();
            cJSON_AddStringToObject(jsonEntry, "name", entry.name);
            cJSON_AddStringToObject(jsonEntry, "date", dateString);
            cJSON_AddNumberToObject(jsonEntry, "size", entry.size);
            cJSON_AddBoolToObject(jsonEntry, "isDirectory", isDir);

            char desc[3 + 1 + 8 + 1 + 40 + 1 + 64 + 1 + 64];
            desc[0] = 0;
            tonie_info_t *tafInfo = getTonieInfo(filePathAbsolute, false, client_ctx->settings);
            toniesJson_item_t *item = NULL;
            if (tafInfo->valid)
            {
                osSnprintf(desc, sizeof(desc), "TAF:%08X:", tafInfo->tafHeader->audio_id);
                for (int hash_pos = 0; hash_pos < tafInfo->tafHeader->sha1_hash.len; hash_pos++)
                {
                    char tmp[3];
                    osSprintf(tmp, "%02x", tafInfo->tafHeader->sha1_hash.data[hash_pos]);
                    osStrcat(desc, tmp);
                }
                char extraDesc[1 + 64 + 1 + 64];
                osSnprintf(extraDesc, sizeof(extraDesc), ":%" PRIu64 ":%" PRIuSIZE, tafInfo->tafHeader->num_bytes, tafInfo->tafHeader->n_track_page_nums);
                osStrcat(desc, extraDesc);

                item = tonies_byAudioIdHashModel(tafInfo->tafHeader->audio_id, tafInfo->tafHeader->sha1_hash.data, tafInfo->json.tonie_model);
            }
            else
            {
                char *json_extension = NULL;
                if (isDir)
                {
                    char *filePathAbsoluteSub = NULL;
                    FsDir *subdir = fsOpenDir(filePathAbsolute);
                    FsDirEntry subentry;
                    if (subdir != NULL)
                    {
                        while (true)
                        {
                            if (fsReadDir(subdir, &subentry) != NO_ERROR || item != NULL)
                            {
                                fsCloseDir(subdir);
                                break;
                            }
                            filePathAbsoluteSub = custom_asprintf("%s%c%s", filePathAbsolute, PATH_SEPARATOR, subentry.name);

                            json_extension = osStrstr(filePathAbsoluteSub, ".json");
                            if (json_extension != NULL)
                            {
                                *json_extension = '\0';
                            }

                            contentJson_t contentJson = {0};
                            load_content_json(filePathAbsoluteSub, &contentJson, false, client_ctx->settings);
                            item = tonies_byModel(contentJson.tonie_model);
                            osFreeMem(filePathAbsoluteSub);
                            free_content_json(&contentJson);
                        }
                    }
                }
                else
                {
                    json_extension = osStrstr(filePathAbsolute, ".json");
                    if (json_extension != NULL)
                    {
                        *json_extension = '\0';
                    }
                    contentJson_t contentJson = {0};
                    load_content_json(filePathAbsolute, &contentJson, false, client_ctx->settings);
                    item = tonies_byModel(contentJson.tonie_model);

                    if (contentJson._has_cloud_auth)
                    {
                        cJSON_AddBoolToObject(jsonEntry, "has_cloud_auth", true);
                    }
                    free_content_json(&contentJson);
                }
            }
            if (item != NULL)
            {
                addToniesJsonInfoJson(item, NULL, jsonEntry);
            }

            freeTonieInfo(tafInfo);
            osFreeMem(filePathAbsolute);
            cJSON_AddStringToObject(jsonEntry, "desc", desc);

            cJSON_AddItemToArray(jsonArray, jsonEntry);

            pos++;
        }

        osFreeMem(pathAbsolute);
        osFreeMem(jsonString);
        jsonString = cJSON_PrintUnformatted(json);
        cJSON_Delete(json);
    } while (0);

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(jsonString);

    return httpWriteResponse(connection, jsonString, connection->response.contentLength, true);
}

error_t handleApiStats(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *jsonArray = cJSON_AddArrayToObject(json, "stats");
    int pos = 0;

    while (true)
    {
        stat_t *stat = stats_get(pos);

        if (!stat)
        {
            break;
        }
        cJSON *jsonEntry = cJSON_CreateObject();
        cJSON_AddStringToObject(jsonEntry, "ID", stat->name);
        cJSON_AddStringToObject(jsonEntry, "description", stat->description);
        cJSON_AddNumberToObject(jsonEntry, "value", stat->value);
        cJSON_AddItemToArray(jsonArray, jsonEntry);

        pos++;
    }

    char *jsonString = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(jsonString);

    return httpWriteResponse(connection, jsonString, connection->response.contentLength, true);
}

error_t file_save_start(void *in_ctx, const char *name, const char *filename)
{
    file_save_ctx *ctx = (file_save_ctx *)in_ctx;

    if (strchr(filename, '\\') || strchr(filename, '/'))
    {
        TRACE_ERROR("Filename '%s' contains directory separators!\r\n", filename);
        return ERROR_DIRECTORY_NOT_FOUND;
    }

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    ctx->filename = custom_asprintf("%s%c%s", ctx->root_path, PATH_SEPARATOR, filename);
    sanitizePath(ctx->filename, false);

    if (fsFileExists(ctx->filename))
    {
        TRACE_INFO("Filename '%s' already exists, overwriting\r\n", ctx->filename);
    }
    else
    {
        TRACE_INFO("Writing to '%s'\r\n", ctx->filename);
    }

    ctx->file = fsOpenFile(ctx->filename, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);

    if (ctx->file == NULL)
    {
        return ERROR_FILE_OPENING_FAILED;
    }

    return NO_ERROR;
}

error_t file_save_add(void *in_ctx, void *data, size_t length)
{
    file_save_ctx *ctx = (file_save_ctx *)in_ctx;

    if (!ctx->file)
    {
        return ERROR_FAILURE;
    }

    if (fsWriteFile(ctx->file, data, length) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    return NO_ERROR;
}

error_t file_save_end(void *in_ctx)
{
    file_save_ctx *ctx = (file_save_ctx *)in_ctx;

    if (!ctx->file)
    {
        return ERROR_FAILURE;
    }
    fsCloseFile(ctx->file);
    osFreeMem(ctx->filename);
    ctx->file = NULL;

    return NO_ERROR;
}

error_t file_save_end_cert(void *in_ctx)
{
    file_save_ctx *ctx = (file_save_ctx *)in_ctx;

    if (!ctx->file)
    {
        return ERROR_FAILURE;
    }
    fsCloseFile(ctx->file);
    ctx->file = NULL;

    /* file was uploaded, this is the cert-specific handler */
    if (!osStrcasecmp(ctx->filename, "ca.der"))
    {
        TRACE_INFO("Set ca.der to %s\r\n", ctx->filename);
        settings_set_string_ovl("core.client_cert.file.ca", ctx->filename, ctx->overlay);
    }
    else if (!osStrcasecmp(ctx->filename, "client.der"))
    {
        TRACE_INFO("Set client.der to %s\r\n", ctx->filename);
        settings_set_string_ovl("core.client_cert.file.crt", ctx->filename, ctx->overlay);
    }
    else if (!osStrcasecmp(ctx->filename, "private.der"))
    {
        TRACE_INFO("Set private.der to %s\r\n", ctx->filename);
        settings_set_string_ovl("core.client_cert.file.key", ctx->filename, ctx->overlay);
    }
    else
    {
        TRACE_INFO("Unknown file type %s\r\n", ctx->filename);
    }

    return NO_ERROR;
}

error_t handleApiUploadCert(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    uint_t statusCode = 500;
    char message[128] = {0};
    char overlay[16] = {0};

    if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
    {
        TRACE_DEBUG("got overlay '%s'\r\n", overlay);
    }
    const char *rootPath = settings_get_string_ovl("internal.certdirfull", overlay);

    if (rootPath == NULL)
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "internal.certdirfull not set to a valid path");
        TRACE_ERROR("internal.certdirfull not set to a valid path\r\n");
    }
    else if (!fsDirExists(rootPath))
    {
        error_t error = fsCreateDirEx(rootPath, true);
        if (error != NO_ERROR || !fsDirExists(rootPath))
        {
            osSnprintf(message, sizeof(message), "internal.certdirfull '%s' does not exist and could not be created. Error: %s", rootPath, error2text(error));
            TRACE_ERROR("internal.certdirfull '%s' does not exist and could not be created. Error: %s\r\n", rootPath, error2text(error));
        }
    }
    else
    {
        multipart_cbr_t cbr;
        file_save_ctx ctx;

        osMemset(&cbr, 0x00, sizeof(cbr));
        osMemset(&ctx, 0x00, sizeof(ctx));

        cbr.multipart_start = &file_save_start;
        cbr.multipart_add = &file_save_add;
        cbr.multipart_end = &file_save_end_cert;

        ctx.root_path = rootPath;
        ctx.overlay = overlay;

        switch (multipart_handle(connection, &cbr, &ctx))
        {
        case NO_ERROR:
            statusCode = 200;
            osSnprintf(message, sizeof(message), "OK");
            break;
        default:
            statusCode = 500;
            break;
        }
    }

    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    return httpWriteResponseString(connection, message, false);
}

error_t file_save_start_suffix(void *in_ctx, const char *name, const char *filename)
{
    file_save_ctx *ctx = (file_save_ctx *)in_ctx;

    if (strchr(filename, '\\') || strchr(filename, '/'))
    {
        TRACE_ERROR("Filename '%s' contains directory separators!\r\n", filename);
        return ERROR_DIRECTORY_NOT_FOUND;
    }

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    for (int suffix = 0; suffix < 100; suffix++)
    {
        if (suffix)
        {
            ctx->filename = custom_asprintf("%s/%s_%d.bin", ctx->root_path, filename, suffix);
        }
        else
        {
            ctx->filename = custom_asprintf("%s/%s.bin", ctx->root_path, filename);
        }
        sanitizePath(ctx->filename, false);

        if (fsFileExists(ctx->filename))
        {
            osFreeMem(ctx->filename);
            continue;
        }
        else
        {
            TRACE_INFO("Writing to '%s'\r\n", ctx->filename);
            break;
        }
    }

    ctx->file = fsOpenFile(ctx->filename, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);

    if (ctx->file == NULL)
    {
        return ERROR_FILE_OPENING_FAILED;
    }

    return NO_ERROR;
}

error_t file_save_end_suffix(void *in_ctx)
{
    file_save_ctx *ctx = (file_save_ctx *)in_ctx;

    if (!ctx->file)
    {
        return ERROR_FAILURE;
    }
    fsCloseFile(ctx->file);
    ctx->file = NULL;

    return NO_ERROR;
}

error_t handleApiGetCaDer(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    settings_t *settings = get_settings();
    char *ca_path = custom_asprintf("%s%c%s", settings->internal.basedirfull, PATH_SEPARATOR, settings->core.server_cert.file.ca_der);

    error_t err = httpSendResponseUnsafe(connection, uri, ca_path);
    osFreeMem(ca_path);
    return err;
}

error_t handleApiESP32UploadFirmware(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    uint_t statusCode = 500;
    char message[128];
    char overlay[16];

    const char *rootPath = get_settings()->internal.firmwaredirfull;

    if (rootPath == NULL || !fsDirExists(rootPath))
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "core.firmwaredir not set to a valid path: '%s'", rootPath);
        TRACE_ERROR("%s\r\n", message);
    }
    else
    {
        multipart_cbr_t cbr;
        file_save_ctx ctx;

        osMemset(&cbr, 0x00, sizeof(cbr));
        osMemset(&ctx, 0x00, sizeof(ctx));

        cbr.multipart_start = &file_save_start_suffix;
        cbr.multipart_add = &file_save_add;
        cbr.multipart_end = &file_save_end_suffix;

        ctx.root_path = rootPath;
        ctx.overlay = overlay;
        ctx.filename = NULL;

        switch (multipart_handle(connection, &cbr, &ctx))
        {
        case NO_ERROR:
            statusCode = 200;
            TRACE_INFO("Received new file:\r\n");
            TRACE_INFO("  '%s'\r\n", ctx.filename);
            osSnprintf(message, sizeof(message), "%s", &ctx.filename[strlen(ctx.root_path) + 1]);
            break;
        default:
            statusCode = 500;
            break;
        }

        osFreeMem(ctx.filename);
    }

    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    return httpWriteResponseString(connection, message, false);
}

bool_t move_cert_file(const char *type, char *from, char *to, char message[1024], uint_t *statusCode, bool overwrite)
{
    size_t message_size = 1024;
    error_t error = fsCompareFiles(from, to, NULL);
    if (error == ERROR_FILE_NOT_FOUND || overwrite)
    {
        error = fsMoveFile(from, to, true);
        if (error != NO_ERROR)
        {
            osSnprintf(message, message_size, "Moving %s from %s to %s failed with error %s\r\n", type, from, to, error2text(error));
            return false;
        }
    }
    else if (error == ERROR_ABORTED)
    {
        *statusCode = 409; // Conflict
        osSnprintf(message, message_size, "Different %s already exists at %s\r\n", type, to);
        return false;
    }
    else if (error == NO_ERROR)
    {
        TRACE_INFO("Skipped identical %s", type);
    }
    return true;
}

error_t handleApiESP32ExtractCerts(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    uint_t statusCode = 500;
    char message[1024];

    error_t error = NO_ERROR;
    const char *firmwareRootPath = get_settings()->internal.firmwaredirfull;
    const char *certRootPath = get_settings()->internal.certdirfull;
    char filename[255] = {0};
    char overwrite_s[16] = {0};
    char mac[13] = {0};

    if (!queryGet(queryString, "filename", filename, sizeof(filename)))
    {
        return ERROR_FAILURE;
    }

    bool overwrite = false;
    bool overwriteBase = false;
    if (queryGet(queryString, "overwrite", overwrite_s, sizeof(overwrite_s)))
    {
        if (overwrite_s[0] == 't')
        {
            overwrite = true;
        }
    }

    const char *sep = osStrchr(filename, '_');
    if (!sep || strlen(&sep[1]) < 12)
    {
        TRACE_ERROR("Invalid file pattern '%s'\r\n", filename);
        return ERROR_NOT_FOUND;
    }
    osStrncpy(mac, &sep[1], 12);
    mac[12] = 0;
    osStringToLower(mac);

    char *file_path = custom_asprintf("%s%c%s", firmwareRootPath, PATH_SEPARATOR, filename);
    char *target_dir = custom_asprintf("%s%c%s", certRootPath, PATH_SEPARATOR, mac);

    char *ca_file = custom_asprintf("%s%c%s", target_dir, PATH_SEPARATOR, "CA.DER");
    char *client_file = custom_asprintf("%s%c%s", target_dir, PATH_SEPARATOR, "CLIENT.DER");
    char *private_file = custom_asprintf("%s%c%s", target_dir, PATH_SEPARATOR, "PRIVATE.DER");

    char *ca_target_file = custom_asprintf("%s%c%s", target_dir, PATH_SEPARATOR, "ca.der");
    char *client_target_file = custom_asprintf("%s%c%s", target_dir, PATH_SEPARATOR, "client.der");
    char *private_target_file = custom_asprintf("%s%c%s", target_dir, PATH_SEPARATOR, "private.der");

    char *ca_global_file = custom_asprintf("%s%c%s", certRootPath, PATH_SEPARATOR, "ca.der");
    char *client_global_file = custom_asprintf("%s%c%s", certRootPath, PATH_SEPARATOR, "client.der");
    char *private_global_file = custom_asprintf("%s%c%s", certRootPath, PATH_SEPARATOR, "private.der");

    do
    {
        if (!fsDirExists(target_dir))
        {
            error = fsCreateDir(target_dir);
            if (error != NO_ERROR)
            {
                osSnprintf(message, sizeof(message), "Failed to create directory '%s' with error %s\r\n", target_dir, error2text(error));
                break;
            }
        }
        error = esp32_fat_extract(file_path, "CERT", target_dir);
        if (error != NO_ERROR)
        {
            osSnprintf(message, sizeof(message), "esp32_fat_extract failed with error %s\r\n", error2text(error));
            break;
        }

        if (!move_cert_file("CA", ca_file, ca_target_file, message, &statusCode, overwrite))
        {
            break;
        }
        if (!move_cert_file("CLIENT", client_file, client_target_file, message, &statusCode, overwrite))
        {
            break;
        }
        if (!move_cert_file("PRIVATE", private_file, private_target_file, message, &statusCode, overwrite))
        {
            break;
        }

        if (!move_cert_file("CA", ca_target_file, ca_global_file, message, &statusCode, overwriteBase))
        {
        }
        if (!move_cert_file("CLIENT", client_target_file, client_global_file, message, &statusCode, overwriteBase))
        {
        }
        if (!move_cert_file("PRIVATE", private_target_file, private_global_file, message, &statusCode, overwriteBase))
        {
        }

        osSnprintf(message, sizeof(message), "OK");
        statusCode = 200;
    } while (false);

    if (statusCode != 200)
    {
        TRACE_ERROR("%s\r\n", message);
    }

    fsDeleteFile(ca_file);
    fsDeleteFile(client_file);
    fsDeleteFile(private_file);

    osFreeMem(file_path);
    osFreeMem(target_dir);

    osFreeMem(ca_file);
    osFreeMem(client_file);
    osFreeMem(private_file);

    osFreeMem(ca_target_file);
    osFreeMem(client_target_file);
    osFreeMem(private_target_file);

    osFreeMem(ca_global_file);
    osFreeMem(client_global_file);
    osFreeMem(private_global_file);

    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    return httpWriteResponseString(connection, message, false);
}
error_t handleApiESP32PatchFirmware(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    const char *rootPath = get_settings()->internal.firmwaredirfull;

    TRACE_INFO("Patch firmware\r\n");
    TRACE_DEBUG("Query: '%s'\r\n", queryString);

    bool generate_certs = false;
    bool inject_ca = true;
    char old_patch_host[32] = {0};
    char patch_host[32] = {0};
    char wifi_ssid[64] = {0};
    char wifi_pass[64] = {0};
    char filename[255] = {0};
    char mac[13] = {0};
    osStrcpy(old_patch_host, "");
    osStrcpy(patch_host, "");
    osStrcpy(filename, "");
    osStrcpy(mac, "");

    if (!queryGet(queryString, "filename", filename, sizeof(filename)))
    {
        return ERROR_FAILURE;
    }

    if (queryGet(queryString, "hostname", patch_host, sizeof(patch_host)))
    {
        TRACE_INFO("Patch hostnames '%s'\r\n", patch_host);
    }

    if (queryGet(queryString, "hostname_old", old_patch_host, sizeof(old_patch_host)))
    {
        TRACE_INFO("Patch hostnames with old hostname '%s'\r\n", old_patch_host);
    }

    if (queryGet(queryString, "wifi_ssid", wifi_ssid, sizeof(wifi_ssid)))
    {
        TRACE_INFO("wifi ssid '%s'\r\n", wifi_ssid);
    }

    if (queryGet(queryString, "wifi_pass", wifi_pass, sizeof(wifi_pass)))
    {
        TRACE_INFO("wifi pass '%s'\r\n", wifi_pass);
    }

    const char *sep = osStrchr(filename, '_');
    if (!sep || strlen(&sep[1]) < 12)
    {
        TRACE_ERROR("Invalid file pattern '%s'\r\n", filename);
        return ERROR_NOT_FOUND;
    }
    osStrncpy(mac, &sep[1], 12);
    mac[12] = 0;

    char *file_path = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, filename);
    char *patched_path = custom_asprintf("%s%cpatched_%s.bin", rootPath, PATH_SEPARATOR, mac);

    TRACE_INFO("Request for '%s'\r\n", file_path);

    error_t error;
    size_t n;
    uint32_t length;
    FsFile *file;

    if (!fsFileExists(file_path))
    {
        TRACE_ERROR("File does not exist '%s'\r\n", file_path);
        return ERROR_NOT_FOUND;
    }
    fsCopyFile(file_path, patched_path, true);
    free(file_path);

    if (generate_certs)
    {
        if (esp32_inject_cert(rootPath, patched_path, mac) != NO_ERROR)
        {
            TRACE_ERROR("Failed to generate and inject certs\r\n");
            return ERROR_NOT_FOUND;
        }
    }

    if (inject_ca)
    {
        if (esp32_inject_ca(rootPath, patched_path, mac) != NO_ERROR)
        {
            TRACE_ERROR("Failed to generate and inject CA\r\n");
            return ERROR_NOT_FOUND;
        }
    }

    if (osStrlen(patch_host) > 0)
    {
        char *oldrtnl = "rtnl.bxcl.de";
        char *oldapi = "prod.de.tbs.toys";

        if (osStrlen(old_patch_host) > 0)
        {
            oldrtnl = old_patch_host;
            oldapi = old_patch_host;
        }

        if (esp32_patch_host(patched_path, patch_host, oldrtnl, oldapi) != NO_ERROR)
        {
            TRACE_ERROR("Failed to patch hostnames\r\n");
            return ERROR_NOT_FOUND;
        }
    }

    if (osStrlen(wifi_ssid) > 0)
    {
        if (esp32_patch_wifi(patched_path, wifi_ssid, wifi_pass) != NO_ERROR)
        {
            TRACE_ERROR("Failed to patch WiFi credentials\r\n");
            return ERROR_NOT_FOUND;
        }
    }

    if (esp32_fixup(patched_path, true) != NO_ERROR)
    {
        TRACE_ERROR("Failed to fixup image\r\n");
        return ERROR_NOT_FOUND;
    }

    // Open the file for reading
    error = fsGetFileSize(patched_path, &length);
    if (error)
    {
        TRACE_ERROR("File does not exist '%s'\r\n", patched_path);
        return ERROR_NOT_FOUND;
    }

    file = fsOpenFile(patched_path, FS_FILE_MODE_READ);
    free(patched_path);

    // Failed to open the file?
    if (file == NULL)
    {
        return ERROR_NOT_FOUND;
    }

    connection->response.statusCode = 200;
    connection->response.contentLength = length;
    connection->response.contentType = "binary/octet-stream";
    connection->response.chunkedEncoding = FALSE;

    error = httpWriteHeader(connection);

    if (error)
    {
        fsCloseFile(file);
        return error;
    }

    while (length > 0)
    {
        n = MIN(length, HTTP_SERVER_BUFFER_SIZE);

        error = fsReadFile(file, connection->buffer, n, &n);
        if (error)
        {
            break;
        }

        error = httpWriteStream(connection, connection->buffer, n);
        if (error)
        {
            break;
        }

        length -= n;
    }

    fsCloseFile(file);

    if (error == NO_ERROR || error == ERROR_END_OF_FILE)
    {
        if (length == 0)
        {
            error = httpFlushStream(connection);
        }
    }

    return error;
}

error_t handleApiFileUpload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    char path[256 + 1];

    osStrcpy(path, "");

    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    if (!queryGet(queryString, "path", path, sizeof(path)))
    {
        osStrcpy(path, "/");
    }

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, true);
    char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);
    sanitizePath(pathAbsolute, true);

    uint_t statusCode = 500;
    char message[512];

    osSnprintf(message, sizeof(message), "OK");

    if (!fsDirExists(pathAbsolute))
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "invalid path: '%.200s'", path);
        TRACE_ERROR("invalid path: '%s' -> '%s'\r\n", path, pathAbsolute);
    }
    else
    {
        multipart_cbr_t cbr;
        file_save_ctx ctx;

        osMemset(&cbr, 0x00, sizeof(cbr));
        osMemset(&ctx, 0x00, sizeof(ctx));

        cbr.multipart_start = &file_save_start;
        cbr.multipart_add = &file_save_add;
        cbr.multipart_end = &file_save_end;

        ctx.root_path = pathAbsolute;
        ctx.overlay = overlay;

        switch (multipart_handle(connection, &cbr, &ctx))
        {
        case NO_ERROR:
            statusCode = 200;
            osSnprintf(message, sizeof(message), "OK");
            break;
        default:
            statusCode = 500;
            break;
        }
    }

    osFreeMem(pathAbsolute);
    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    return httpWriteResponseString(connection, message, false);
}

error_t handleApiContent(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    TRACE_DEBUG("Query: '%s'\r\n", queryString);

    char ogg[16];
    char overlay[16];
    osStrcpy(ogg, "");
    osStrcpy(overlay, "");

    const char *rootPath = NULL;

    if (!queryGet(queryString, "ogg", ogg, sizeof(ogg)))
    {
        strcpy(ogg, "false");
    }

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    bool skipFileHeader = !strcmp(ogg, "true");
    size_t startOffset = skipFileHeader ? 4096 : 0;

    char *file_path = custom_asprintf("%s%s", rootPath, &uri[8]);

    TRACE_DEBUG("Request for '%s', ogg: %s\r\n", file_path, ogg);

    error_t error;
    size_t n;
    uint32_t length;
    FsFile *file;

    // Retrieve the size of the specified file
    error = fsGetFileSize(file_path, &length);

    bool_t isStream = false;
    tonie_info_t *tafInfo = getTonieInfo(file_path, false, client_ctx->settings);

    if (tafInfo->valid && tafInfo->json._source_type == CT_SOURCE_STREAM)
    {
        isStream = true;
        length = client_ctx->settings->encode.stream_max_size;
        connection->response.noCache = true;
    }

    freeTonieInfo(tafInfo);

    if (error || length < startOffset)
    {
        TRACE_ERROR("File does not exist '%s'\r\n", file_path);
        return ERROR_NOT_FOUND;
    }

    /* in case of skipped headers, also reduce the file length */
    length -= startOffset;

    // Open the file for reading
    file = fsOpenFile(file_path, FS_FILE_MODE_READ);
    free(file_path);

    // Failed to open the file?
    if (file == NULL)
    {
        return ERROR_NOT_FOUND;
    }

    char *range_hdr = NULL;

    // Format HTTP response header
    // TODO add status 416 on invalid ranges
    if (!isStream && connection->request.Range.start > 0)
    {
        connection->request.Range.size = length;
        if (connection->request.Range.end >= connection->request.Range.size || connection->request.Range.end == 0)
        {
            connection->request.Range.end = connection->request.Range.size - 1;
        }

        range_hdr = custom_asprintf("bytes %" PRIu32 "-%" PRIu32 "/%" PRIu32, connection->request.Range.start, connection->request.Range.end, connection->request.Range.size);
        connection->response.contentRange = range_hdr;
        connection->response.statusCode = 206;
        connection->response.contentLength = connection->request.Range.end - connection->request.Range.start + 1;
        TRACE_DEBUG("Added response range %s\r\n", connection->response.contentRange);
    }
    else
    {
        connection->response.statusCode = 200;
        connection->response.contentLength = length;
    }
    connection->response.contentType = "audio/ogg";
    connection->response.chunkedEncoding = FALSE;

    error = httpWriteHeader(connection);

    if (range_hdr)
    {
        osFreeMem(range_hdr);
    }

    if (error)
    {
        fsCloseFile(file);
        return error;
    }

    if (!isStream && connection->request.Range.start > 0 && connection->request.Range.start < connection->request.Range.size)
    {
        TRACE_DEBUG("Seeking file to %" PRIu32 "\r\n", connection->request.Range.start);
        fsSeekFile(file, startOffset + connection->request.Range.start, FS_SEEK_SET);
    }
    else
    {
        TRACE_DEBUG("No seeking, sending from beginning\r\n");
        fsSeekFile(file, startOffset, FS_SEEK_SET);
    }

    // Send response body
    while (length > 0)
    {
        // Limit the number of bytes to read at a time
        n = MIN(length, HTTP_SERVER_BUFFER_SIZE);

        // Read data from the specified file
        error = fsReadFile(file, connection->buffer, n, &n);
        // End of input stream?
        if (isStream && error == ERROR_END_OF_FILE && connection->running)
        {
            osDelayTask(500);
            continue;
        }
        if (error)
            break;

        // Send data to the client
        error = httpWriteStream(connection, connection->buffer, n);
        // Any error to report?
        if (error)
            break;

        // Decrement the count of remaining bytes to be transferred
        length -= n;
    }

    // Close the file
    fsCloseFile(file);

    // Successful file transfer?
    if (error == NO_ERROR || error == ERROR_END_OF_FILE)
    {
        if (length == 0)
        {
            // Properly close the output stream
            error = httpFlushStream(connection);
        }
    }

    return error;
}
error_t handleApiContentDownload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    // TODO Rewrite URL
    // Use RUID/Azth from content.json
    // set connection->private.authentication_token
    // TODO Remove JSON suffix

    // http://dev11.lan/content/download/3D8C0F13/500304E0.json
    // http://dev11.lan/v2/content/3d8c0f13500304e0

    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    if (osStrlen(uri) < 34)
    {
        return NO_ERROR;
    }

    char *json_extension = osStrstr(uri, ".json");
    if (json_extension != NULL)
    {
        *json_extension = '\0';
    }

    char *path = (char *)uri + 1 + 7 + 1 + 8 + 1;
    char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);

    char ruid[17];

    contentJson_t contentJson;
    load_content_json(pathAbsolute, &contentJson, false, client_ctx->settings);
    osFreeMem(pathAbsolute);

    osStrncpy(ruid, path, 8);
    osStrncpy(ruid + 8, path + 9, 8);
    for (uint8_t i = 0; i < 16; i++)
    {
        ruid[i] = osTolower(ruid[i]);
    }
    ruid[16] = '\0';

    bool isSys = (ruid[0] == '0' && ruid[1] == '0' && ruid[2] == '0' && ruid[3] == '0' && ruid[4] == '0' && ruid[5] == '0' && ruid[6] == '0');

    error_t error = NO_ERROR;
    if (isSys || contentJson.nocloud)
    {
        osSprintf((char *)uri, "/v1/content/%s", ruid);
        error = handleCloudContent(connection, uri, queryString, client_ctx, true);
    }
    else
    {
        osMemcpy(connection->private.authentication_token, contentJson.cloud_auth, contentJson.cloud_auth_len);
        osSprintf((char *)uri, "/v2/content/%s", ruid);
        error = handleCloudContent(connection, uri, queryString, client_ctx, false);
    }

    free_content_json(&contentJson);
    return error;
}

typedef struct
{
    const char *overlay;
    const char *file_path;
    toniefile_t *taf;
    uint8_t remainder[4];
    int remainder_avail;
    uint32_t audio_id;
} taf_encode_ctx;

error_t taf_encode_start(void *in_ctx, const char *name, const char *filename)
{
    taf_encode_ctx *ctx = (taf_encode_ctx *)in_ctx;

    if (!ctx->taf)
    {
        TRACE_INFO("[TAF] Start encoding to %s\r\n", ctx->file_path);
        TRACE_INFO("[TAF]   first file: %s\r\n", name);

        ctx->taf = toniefile_create(ctx->file_path, ctx->audio_id, false, 0);

        if (ctx->taf == NULL)
        {
            TRACE_INFO("[TAF]   Creating TAF failed\r\n");
            return ERROR_FILE_OPENING_FAILED;
        }
    }
    else
    {
        TRACE_INFO("[TAF]   new chapter for %s\r\n", name);
        toniefile_new_chapter(ctx->taf);
    }

    return NO_ERROR;
}

error_t taf_encode_add(void *in_ctx, void *data, size_t length)
{
    taf_encode_ctx *ctx = (taf_encode_ctx *)in_ctx;
    uint8_t *byte_data = (uint8_t *)data;
    size_t byte_data_start = 0;
    size_t byte_data_length = length;

    /* we have to take into account that the packets are not 4 byte aligned */
    if (ctx->remainder_avail)
    {
        /* there a a few bytes, so first fill the buffer */
        int size = 4 - ctx->remainder_avail;
        if (size > length)
        {
            size = length;
        }
        osMemcpy(&ctx->remainder[ctx->remainder_avail], byte_data, size);

        byte_data_start += size;
        byte_data_length -= size;
        ctx->remainder_avail += size;
    }

    /* either we have a full buffer now or no more data */
    if (ctx->remainder_avail == 4)
    {
        toniefile_encode(ctx->taf, (int16_t *)ctx->remainder, 1);
        ctx->remainder_avail = 0;
    }

    int samples = byte_data_length / 4;
    int remain = byte_data_length % 4;

    if (samples)
    {
        toniefile_encode(ctx->taf, (int16_t *)&byte_data[byte_data_start], samples);
    }

    if (remain)
    {
        osMemcpy(ctx->remainder, &byte_data[byte_data_start + samples * 4], remain);
        ctx->remainder_avail = remain;
    }

    return NO_ERROR;
}

error_t taf_encode_end(void *in_ctx)
{
    TRACE_INFO("[TAF]   end of file\r\n");
    return NO_ERROR;
}

error_t handleApiEncodeFile(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    char_t post_data[POST_BUFFER_SIZE];
    error_t error = parsePostData(connection, post_data, POST_BUFFER_SIZE);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("parsePostData failed with error %s\r\n", error2text(error));
        return error;
    }

    char multisource[99][PATH_LEN];
    uint8_t multisource_size = 0;
    char source[PATH_LEN];
    char target[PATH_LEN];

    if (!queryGet(post_data, "target", target, sizeof(target)))
    {
        TRACE_ERROR("target missing!\r\n");
        return ERROR_INVALID_REQUEST;
    }
    sanitizePath(target, false);
    char *targetAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, target);
    sanitizePath(targetAbsolute, false);

    char_t message[256];
    uint_t statusCode = 200;

    if (fsFileExists(targetAbsolute))
    {
        TRACE_ERROR("File %s already exists!\r\n", targetAbsolute);
        osSnprintf(message, sizeof(message), "File %s already exists!\r\n", targetAbsolute);
        statusCode = 500;
    }
    else
    {
        while (queryGetMulti(post_data, "source", source, sizeof(source), multisource_size))
        {
            sanitizePath(source, false);
            osSprintf(multisource[multisource_size], "%s%c%s", rootPath, PATH_SEPARATOR, source);
            sanitizePath(multisource[multisource_size], false);
            // TRACE_INFO("Source %s\r\n", multisource[multisource_size]);
            if (!fsFileExists(multisource[multisource_size]))
            {
                TRACE_ERROR("Source %s does not exist!\r\n", multisource[multisource_size]);
                osFreeMem(targetAbsolute);
                return ERROR_INVALID_REQUEST;
            }
            multisource_size++;
        }
        if (multisource_size == 0)
        {
            TRACE_ERROR("Source missing!\r\n");
            osFreeMem(targetAbsolute);
            return ERROR_INVALID_REQUEST;
        }

        TRACE_INFO("Encode %" PRIu8 " files to %s\r\n", multisource_size, targetAbsolute);
        size_t current_source = 0;
        error = ffmpeg_convert(multisource, multisource_size, &current_source, targetAbsolute, 0);
        osFreeMem(targetAbsolute);
        if (error != NO_ERROR)
        {
            TRACE_ERROR("ffmpeg_convert failed with error %s\r\n", error2text(error));
            statusCode = 500;
            osSnprintf(message, sizeof(message), "ffmpeg_convert failed with error %s\r\n", error2text(error));
        }
        else
        {
            osSnprintf(message, sizeof(message), "OK\r\n");
        }
    }

    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    return httpWriteResponseString(connection, message, false);
    return error;
}
error_t handleApiPcmUpload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    char name[256];
    char uid[32];
    char path[256 + 1];
    char audio_id_str[128];
    uint32_t audio_id = 0;

    osStrcpy(name, "unnamed");
    osStrcpy(uid, "");
    osStrcpy(path, "");
    osStrcpy(audio_id_str, "");

    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    if (queryGet(queryString, "name", name, sizeof(name)))
    {
        TRACE_INFO("got name '%s'\r\n", name);
    }
    if (queryGet(queryString, "uid", uid, sizeof(uid)))
    {
        TRACE_INFO("got uid '%s'\r\n", uid);
    }
    if (queryGet(queryString, "audioId", audio_id_str, sizeof(audio_id_str)))
    {
        TRACE_INFO("got audioId '%s'\r\n", audio_id_str);
        audio_id = atol(audio_id_str);
    }
    if (!queryGet(queryString, "path", path, sizeof(path)))
    {
        osStrcpy(path, "/");
    }

    sanitizePath(name, false);

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, true);
    char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);
    sanitizePath(pathAbsolute, true);

    uint_t statusCode = 500;
    char message[512];
    osSnprintf(message, sizeof(message), "OK");

    if (!fsDirExists(pathAbsolute))
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "invalid path: '%.200s'", path);
        TRACE_ERROR("invalid path: '%s' -> '%s'\r\n", path, pathAbsolute);
    }
    else
    {
        char *filename = custom_asprintf("%s%c%s", pathAbsolute, PATH_SEPARATOR, name);

        if (!filename)
        {
            TRACE_ERROR("Failed to build filename\r\n");
            return ERROR_FAILURE;
        }
        sanitizePath(filename, false);

        if (fsFileExists(filename))
        {
            TRACE_INFO("Filename '%s' already exists, overwriting\r\n", filename);
        }

        multipart_cbr_t cbr;
        taf_encode_ctx ctx;

        osMemset(&cbr, 0x00, sizeof(cbr));
        osMemset(&ctx, 0x00, sizeof(ctx));

        cbr.multipart_start = &taf_encode_start;
        cbr.multipart_add = &taf_encode_add;
        cbr.multipart_end = &taf_encode_end;

        ctx.file_path = filename;
        ctx.overlay = overlay;
        ctx.audio_id = audio_id;

        switch (multipart_handle(connection, &cbr, &ctx))
        {
        case NO_ERROR:
            statusCode = 200;
            osSnprintf(message, sizeof(message), "OK");
            break;
        default:
            statusCode = 500;
            break;
        }

        if (ctx.taf)
        {
            TRACE_INFO("[TAF] Ended encoding\r\n");
            toniefile_close(ctx.taf);
        }
        osFreeMem(filename);
    }

    osFreeMem(pathAbsolute);

    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    return httpWriteResponseString(connection, message, false);
}

error_t handleApiTafUpload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    char name[256];
    char path[256 + 1];

    osStrcpy(name, "unnamed.taf");
    osStrcpy(path, "");

    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    if (queryGet(queryString, "name", name, sizeof(name)))
    {
        TRACE_INFO("got name '%s'\r\n", name);
    }
    if (!queryGet(queryString, "path", path, sizeof(path)))
    {
        osStrcpy(path, "/");
    }

    sanitizePath(name, false);

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, true);
    char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);
    sanitizePath(pathAbsolute, true);

    uint_t statusCode = 500;
    char message[512];
    osSnprintf(message, sizeof(message), "OK");

    if (!fsDirExists(pathAbsolute))
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "invalid path: '%.200s'", path);
        TRACE_ERROR("invalid path: '%s' -> '%s'\r\n", path, pathAbsolute);
    }
    else
    {
        char *filename = custom_asprintf("%s%c%s", pathAbsolute, PATH_SEPARATOR, name);

        if (!filename)
        {
            TRACE_ERROR("Failed to build filename\r\n");
            osFreeMem(pathAbsolute);
            return ERROR_FAILURE;
        }
        sanitizePath(filename, false);

        if (fsFileExists(filename))
        {
            TRACE_INFO("Filename '%s' already exists, overwriting\r\n", filename);
        }

        multipart_cbr_t cbr;
        file_save_ctx ctx;

        osMemset(&cbr, 0x00, sizeof(cbr));
        osMemset(&ctx, 0x00, sizeof(ctx));

        cbr.multipart_start = &file_save_start;
        cbr.multipart_add = &file_save_add;
        cbr.multipart_end = &file_save_end;

        ctx.root_path = pathAbsolute;
        ctx.overlay = overlay;

        switch (multipart_handle(connection, &cbr, &ctx))
        {
        case NO_ERROR:
            if (!isValidTaf(filename, true))
            {
                TRACE_ERROR("Uploaded TAF file '%s' failed validation\r\n", filename);
                statusCode = 500;
                osSnprintf(message, sizeof(message), "TAF validation failed");
                fsDeleteFile(filename);
                break;
            }
            statusCode = 200;
            osSnprintf(message, sizeof(message), "OK");
            break;
        default:
            statusCode = 500;
            osSnprintf(message, sizeof(message), "Upload failed");
            break;
        }

        osFreeMem(filename);
    }

    osFreeMem(pathAbsolute);

    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    return httpWriteResponseString(connection, message, false);
}

error_t handleApiDirectoryCreate(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    char path[256 + 3];
    size_t size = 0;

    error_t error = httpReceive(connection, &path, sizeof(path) - 3, &size, 0x00);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("httpReceive failed!\r\n");
        return error;
    }
    path[size] = 0;

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, true);
    char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);
    sanitizePath(pathAbsolute, true);

    TRACE_INFO("Creating directory: '%s'\r\n", pathAbsolute);

    uint_t statusCode = 200;
    char message[256 + 64];

    osSnprintf(message, sizeof(message), "OK");

    error_t err = fsCreateDir(pathAbsolute);

    if (err != NO_ERROR)
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "Error creating directory '%s', error %s", path, error2text(err));
        TRACE_ERROR("Error creating directory '%s' -> '%s', error %s\r\n", path, pathAbsolute, error2text(err));
    }
    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    osFreeMem(pathAbsolute);

    return httpWriteResponseString(connection, message, false);
}

error_t handleApiDirectoryDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    char path[256 + 3];
    size_t size = 0;

    error_t error = httpReceive(connection, &path, sizeof(path) - 3, &size, 0x00);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("httpReceive failed!\r\n");
        return error;
    }
    path[size] = 0;

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, true);
    char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);
    sanitizePath(pathAbsolute, true);

    TRACE_INFO("Deleting directory: '%s'\r\n", pathAbsolute);

    uint_t statusCode = 200;
    char message[256 + 64];

    osSnprintf(message, sizeof(message), "OK");

    error_t err = fsRemoveDir(pathAbsolute);

    if (err != NO_ERROR)
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "Error deleting directory '%s', error %s", path, error2text(err));
        TRACE_ERROR("Error deleting directory '%s' -> '%s', error %s\r\n", path, pathAbsolute, error2text(err));
    }
    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    osFreeMem(pathAbsolute);

    return httpWriteResponseString(connection, message, false);
}

error_t handleApiFileDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    char path[256 + 3];
    size_t size = 0;

    error_t error = httpReceive(connection, &path, sizeof(path) - 3, &size, 0x00);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("httpReceive failed!\r\n");
        return error;
    }
    path[size] = 0;

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, false);
    char *pathAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, path);
    sanitizePath(pathAbsolute, false);

    TRACE_INFO("Deleting file: '%s'\r\n", path);

    uint_t statusCode = 200;
    char message[256 + 64];

    osSnprintf(message, sizeof(message), "OK");

    error_t err = fsDeleteFile(pathAbsolute);

    if (err != NO_ERROR)
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "Error deleting file '%s', error %s", path, error2text(err));
        TRACE_ERROR("Error deleting file '%s' -> '%s', error %s\r\n", path, pathAbsolute, error2text(err));
    }
    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    osFreeMem(pathAbsolute);

    return httpWriteResponseString(connection, message, false);
}
error_t handleApiFileMove(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    char_t post_data[POST_BUFFER_SIZE];
    error_t error = parsePostData(connection, post_data, POST_BUFFER_SIZE);
    if (error != NO_ERROR)
    {
        return error;
    }

    char source[256 + 3];
    char target[256 + 3];

    if (!queryGet(post_data, "source", source, sizeof(source)))
    {
        TRACE_ERROR("source missing!\r\n");
        return ERROR_INVALID_REQUEST;
    }
    if (!queryGet(post_data, "target", target, sizeof(target)))
    {
        TRACE_ERROR("target missing!\r\n");
        return ERROR_INVALID_REQUEST;
    }

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(source, false);
    char *sourceAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, source);
    sanitizePath(sourceAbsolute, false);

    sanitizePath(target, false);
    char *targetAbsolute = custom_asprintf("%s%c%s", rootPath, PATH_SEPARATOR, target);
    sanitizePath(targetAbsolute, false);

    TRACE_INFO("Moving file: '%s' to '%s'\r\n", source, target);
    TRACE_INFO("Moving file: '%s' to '%s'\r\n", sourceAbsolute, targetAbsolute);

    uint_t statusCode = 200;
    char message[1024];

    osSnprintf(message, sizeof(message), "OK");

    error_t err = fsMoveFile(sourceAbsolute, targetAbsolute, false);

    if (err != NO_ERROR)
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "Error moving file '%s' to '%s', error %s", source, target, error2text(err));
        TRACE_ERROR("Error moving file '%s' to '%s', error %s\r\n", sourceAbsolute, targetAbsolute, error2text(err));
    }
    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    osFreeMem(sourceAbsolute);
    osFreeMem(targetAbsolute);

    return httpWriteResponseString(connection, message, false);
}

error_t handleApiToniesJsonReload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    tonies_deinit();
    tonies_init();
    httpPrepareHeader(connection, "text/plain; charset=utf-8", 2);
    return httpWriteResponseString(connection, "OK", false);
}
error_t handleApiToniesJson(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char *tonies_path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIES_JSON_FILE);

    error_t err = httpSendResponseUnsafe(connection, uri, tonies_path);
    osFreeMem(tonies_path);
    return err;
}
error_t handleApiToniesJsonUpdate(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char *message = "Triggered tonies.json update";
    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    httpWriteResponseString(connection, message, false);
    return tonies_update();
}

error_t handleApiToniesCustomJson(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char *tonies_custom_path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIES_CUSTOM_JSON_FILE);

    error_t err = httpSendResponseUnsafe(connection, uri, tonies_custom_path);
    osFreeMem(tonies_custom_path);
    return err;
}

static error_t writeApiStatusText(HttpConnection *connection, uint_t statusCode, const char *message)
{
    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;
    return httpWriteResponseString(connection, (char_t *)message, false);
}

static bool jsonIsNonEmptyString(const cJSON *value)
{
    return cJSON_IsString(value) && value->valuestring != NULL && osStrlen(value->valuestring) > 0;
}

static bool isHexHashString(const char *buf)
{
    if (buf == NULL || osStrlen(buf) != 40)
    {
        return false;
    }

    for (size_t i = 0; i < 40; i++)
    {
        char c = (char)toupper((int)buf[i]);
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
        {
            return false;
        }
    }
    return true;
}

static bool jsonGetUInt32Flexible(cJSON *value, uint32_t *out)
{
    // Accept numeric JSON values and numeric strings to tolerate mixed client payloads.
    if (cJSON_IsNumber(value))
    {
        if (value->valuedouble < 0)
        {
            return false;
        }
        *out = (uint32_t)value->valuedouble;
        return true;
    }

    if (cJSON_IsString(value) && value->valuestring != NULL && osStrlen(value->valuestring) > 0)
    {
        char *endptr = NULL;
        unsigned long parsed = strtoul(value->valuestring, &endptr, 10);
        if (endptr == NULL || *endptr != '\0')
        {
            return false;
        }
        *out = (uint32_t)parsed;
        return true;
    }

    return false;
}

typedef struct
{
    char *key;
    size_t index;
} string_key_index_t;

static void freeStringKeyIndexArray(string_key_index_t *keys, size_t keyCount)
{
    if (keys == NULL)
    {
        return;
    }

    for (size_t i = 0; i < keyCount; i++)
    {
        if (keys[i].key != NULL)
        {
            osFreeMem(keys[i].key);
        }
    }
    osFreeMem(keys);
}

static int compareStringKeyIndex(const void *a, const void *b)
{
    const string_key_index_t *left = (const string_key_index_t *)a;
    const string_key_index_t *right = (const string_key_index_t *)b;
    return osStrcmp(left->key, right->key);
}

static int compareStringKeyIndexCaseInsensitive(const void *a, const void *b)
{
    const string_key_index_t *left = (const string_key_index_t *)a;
    const string_key_index_t *right = (const string_key_index_t *)b;
    return osStrcasecmp(left->key, right->key);
}

static error_t buildAudioHashKey(uint32_t audioId, const char *hashValue, char **outKey)
{
    if (outKey == NULL || hashValue == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    char normalizedHash[41];
    for (size_t i = 0; i < 40; i++)
    {
        normalizedHash[i] = osToupper(hashValue[i]);
    }
    normalizedHash[40] = '\0';

    char *key = custom_asprintf("%" PRIu32 "|%s", audioId, normalizedHash);
    if (key == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }

    *outKey = key;
    return NO_ERROR;
}

static error_t validateToniesCustomJson(cJSON *root, char *message, size_t messageSize)
{
    if (!cJSON_IsArray(root))
    {
        osSnprintf(message, messageSize, "Invalid payload: root must be a JSON array");
        return ERROR_INVALID_SYNTAX;
    }

    size_t entryCount = (size_t)cJSON_GetArraySize(root);
    size_t pairCount = 0;
    for (size_t i = 0; i < entryCount; i++)
    {
        cJSON *entry = cJSON_GetArrayItem(root, (int)i);
        if (!cJSON_IsObject(entry))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": expected object", i);
            return ERROR_INVALID_SYNTAX;
        }

        cJSON *model = cJSON_GetObjectItemCaseSensitive(entry, "model");
        cJSON *series = cJSON_GetObjectItemCaseSensitive(entry, "series");
        if (!jsonIsNonEmptyString(model))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'model' is required", i);
            return ERROR_INVALID_SYNTAX;
        }
        if (!jsonIsNonEmptyString(series))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'series' is required", i);
            return ERROR_INVALID_SYNTAX;
        }

        cJSON *noValue = cJSON_GetObjectItemCaseSensitive(entry, "no");
        cJSON *title = cJSON_GetObjectItemCaseSensitive(entry, "title");
        cJSON *episodes = cJSON_GetObjectItemCaseSensitive(entry, "episodes");
        cJSON *release = cJSON_GetObjectItemCaseSensitive(entry, "release");
        cJSON *language = cJSON_GetObjectItemCaseSensitive(entry, "language");
        cJSON *category = cJSON_GetObjectItemCaseSensitive(entry, "category");
        cJSON *pic = cJSON_GetObjectItemCaseSensitive(entry, "pic");
        cJSON *tracks = cJSON_GetObjectItemCaseSensitive(entry, "tracks");

        if (noValue != NULL && !cJSON_IsString(noValue))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'no' must be string", i);
            return ERROR_INVALID_SYNTAX;
        }
        if (title != NULL && !cJSON_IsString(title))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'title' must be string", i);
            return ERROR_INVALID_SYNTAX;
        }
        if (episodes != NULL && !cJSON_IsString(episodes))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'episodes' must be string", i);
            return ERROR_INVALID_SYNTAX;
        }
        if (language != NULL && !cJSON_IsString(language))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'language' must be string", i);
            return ERROR_INVALID_SYNTAX;
        }
        if (category != NULL && !cJSON_IsString(category))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'category' must be string", i);
            return ERROR_INVALID_SYNTAX;
        }
        if (pic != NULL && !cJSON_IsString(pic))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'pic' must be string", i);
            return ERROR_INVALID_SYNTAX;
        }
        if (release != NULL && !cJSON_IsString(release) && !cJSON_IsNumber(release))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'release' must be string or numeric", i);
            return ERROR_INVALID_SYNTAX;
        }
        if (tracks != NULL)
        {
            if (!cJSON_IsArray(tracks))
            {
                osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'tracks' must be array", i);
                return ERROR_INVALID_SYNTAX;
            }
            size_t trackCount = (size_t)cJSON_GetArraySize(tracks);
            for (size_t ti = 0; ti < trackCount; ti++)
            {
                cJSON *track = cJSON_GetArrayItem(tracks, (int)ti);
                if (!cJSON_IsString(track))
                {
                    osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'tracks[%zu]' must be string", i, ti);
                    return ERROR_INVALID_SYNTAX;
                }
            }
        }

        cJSON *audioId = cJSON_GetObjectItemCaseSensitive(entry, "audio_id");
        cJSON *hash = cJSON_GetObjectItemCaseSensitive(entry, "hash");
        if ((audioId != NULL && !cJSON_IsArray(audioId)) || (hash != NULL && !cJSON_IsArray(hash)))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'audio_id' and 'hash' must be arrays", i);
            return ERROR_INVALID_SYNTAX;
        }
        size_t audioCount = cJSON_IsArray(audioId) ? (size_t)cJSON_GetArraySize(audioId) : 0;
        size_t hashCount = cJSON_IsArray(hash) ? (size_t)cJSON_GetArraySize(hash) : 0;

        if ((audioCount > 0 || hashCount > 0) && audioCount != hashCount)
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'audio_id' and 'hash' must have same length", i);
            return ERROR_INVALID_SYNTAX;
        }

        for (size_t j = 0; j < audioCount; j++)
        {
            cJSON *audioIdValue = cJSON_GetArrayItem(audioId, (int)j);
            cJSON *hashValue = cJSON_GetArrayItem(hash, (int)j);
            uint32_t parsedAudioId = 0;

            if (!jsonGetUInt32Flexible(audioIdValue, &parsedAudioId))
            {
                osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'audio_id[%zu]' must be numeric", i, j);
                return ERROR_INVALID_SYNTAX;
            }

            if (!cJSON_IsString(hashValue) || !isHexHashString(hashValue->valuestring))
            {
                osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'hash[%zu]' must be 40-char hex", i, j);
                return ERROR_INVALID_SYNTAX;
            }
            (void)parsedAudioId;
        }

        pairCount += audioCount;
    }

    string_key_index_t *modelKeys = NULL;
    string_key_index_t *pairKeys = NULL;
    size_t modelKeyCount = 0;
    size_t pairKeyCount = 0;
    error_t result = NO_ERROR;

    if (entryCount > 0)
    {
        modelKeys = osAllocMem(sizeof(string_key_index_t) * entryCount);
        if (modelKeys == NULL)
        {
            osSnprintf(message, messageSize, "Out of memory");
            return ERROR_OUT_OF_MEMORY;
        }
        osMemset(modelKeys, 0, sizeof(string_key_index_t) * entryCount);
    }

    if (pairCount > 0)
    {
        pairKeys = osAllocMem(sizeof(string_key_index_t) * pairCount);
        if (pairKeys == NULL)
        {
            freeStringKeyIndexArray(modelKeys, modelKeyCount);
            osSnprintf(message, messageSize, "Out of memory");
            return ERROR_OUT_OF_MEMORY;
        }
        osMemset(pairKeys, 0, sizeof(string_key_index_t) * pairCount);
    }

    for (size_t i = 0; i < entryCount; i++)
    {
        cJSON *entry = cJSON_GetArrayItem(root, (int)i);
        cJSON *model = cJSON_GetObjectItemCaseSensitive(entry, "model");
        modelKeys[modelKeyCount].key = custom_asprintf("%s", model->valuestring);
        modelKeys[modelKeyCount].index = i;
        if (modelKeys[modelKeyCount].key == NULL)
        {
            result = ERROR_OUT_OF_MEMORY;
            osSnprintf(message, messageSize, "Out of memory");
            goto cleanup;
        }
        modelKeyCount++;

        cJSON *audioId = cJSON_GetObjectItemCaseSensitive(entry, "audio_id");
        cJSON *hash = cJSON_GetObjectItemCaseSensitive(entry, "hash");
        size_t audioCount = cJSON_IsArray(audioId) ? (size_t)cJSON_GetArraySize(audioId) : 0;
        for (size_t j = 0; j < audioCount; j++)
        {
            cJSON *audioIdValue = cJSON_GetArrayItem(audioId, (int)j);
            cJSON *hashValue = cJSON_GetArrayItem(hash, (int)j);
            uint32_t parsedAudioId = 0;

            if (!jsonGetUInt32Flexible(audioIdValue, &parsedAudioId) || !cJSON_IsString(hashValue))
            {
                result = ERROR_INVALID_SYNTAX;
                osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE, i);
                goto cleanup;
            }

            error_t keyError = buildAudioHashKey(parsedAudioId, hashValue->valuestring, &pairKeys[pairKeyCount].key);
            if (keyError != NO_ERROR)
            {
                result = keyError;
                osSnprintf(message, messageSize, "Out of memory");
                goto cleanup;
            }
            pairKeys[pairKeyCount].index = i;
            pairKeyCount++;
        }
    }

    if (modelKeyCount > 1)
    {
        qsort(modelKeys, modelKeyCount, sizeof(string_key_index_t), compareStringKeyIndexCaseInsensitive);
        for (size_t i = 1; i < modelKeyCount; i++)
        {
            if (osStrcasecmp(modelKeys[i - 1].key, modelKeys[i].key) == 0)
            {
                result = ERROR_INVALID_SYNTAX;
                osSnprintf(message, messageSize, "Duplicate custom model '%s' at indexes %" PRIuSIZE " and %" PRIuSIZE, modelKeys[i].key, modelKeys[i - 1].index, modelKeys[i].index);
                goto cleanup;
            }
        }
    }

    if (pairKeyCount > 1)
    {
        qsort(pairKeys, pairKeyCount, sizeof(string_key_index_t), compareStringKeyIndex);
        for (size_t i = 1; i < pairKeyCount; i++)
        {
            if (osStrcmp(pairKeys[i - 1].key, pairKeys[i].key) == 0)
            {
                const char *separator = osStrchr(pairKeys[i].key, '|');
                const char *audioIdString = pairKeys[i].key;
                char audioIdBuffer[32];
                if (separator != NULL)
                {
                    size_t copyLen = (size_t)(separator - pairKeys[i].key);
                    if (copyLen >= sizeof(audioIdBuffer))
                    {
                        copyLen = sizeof(audioIdBuffer) - 1;
                    }
                    osMemcpy(audioIdBuffer, pairKeys[i].key, copyLen);
                    audioIdBuffer[copyLen] = '\0';
                    audioIdString = audioIdBuffer;
                }
                result = ERROR_INVALID_SYNTAX;
                osSnprintf(message, messageSize, "Duplicate audio_id+hash pair detected (audio_id=%s) at indexes %" PRIuSIZE " and %" PRIuSIZE, audioIdString, pairKeys[i - 1].index, pairKeys[i].index);
                goto cleanup;
            }
        }
    }

    result = NO_ERROR;
    osSnprintf(message, messageSize, "OK");
cleanup:
    freeStringKeyIndexArray(pairKeys, pairKeyCount);
    freeStringKeyIndexArray(modelKeys, modelKeyCount);
    return result;
}

static cJSON *jsonValueToStringNode(const cJSON *value)
{
    if (cJSON_IsString(value) && value->valuestring != NULL)
    {
        return cJSON_CreateString(value->valuestring);
    }

    if (cJSON_IsNumber(value))
    {
        char buffer[32];
        osSnprintf(buffer, sizeof(buffer), "%.0f", value->valuedouble);
        return cJSON_CreateString(buffer);
    }

    if (cJSON_IsBool(value))
    {
        return cJSON_CreateString(cJSON_IsTrue(value) ? "true" : "false");
    }

    return cJSON_CreateString("");
}

static error_t normalizeStringField(cJSON *entry, const char *fieldName)
{
    cJSON *field = cJSON_GetObjectItemCaseSensitive(entry, fieldName);
    cJSON *normalized = jsonValueToStringNode(field);
    if (normalized == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }

    if (field != NULL)
    {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(entry, fieldName, normalized))
        {
            cJSON_Delete(normalized);
            return ERROR_FAILURE;
        }
    }
    else
    {
        cJSON_AddItemToObject(entry, fieldName, normalized);
    }

    return NO_ERROR;
}

static error_t normalizeStringArrayField(cJSON *entry, const char *fieldName)
{
    cJSON *field = cJSON_GetObjectItemCaseSensitive(entry, fieldName);
    if (!cJSON_IsArray(field))
    {
        cJSON *emptyArray = cJSON_CreateArray();
        if (emptyArray == NULL)
        {
            return ERROR_OUT_OF_MEMORY;
        }
        if (field != NULL)
        {
            if (!cJSON_ReplaceItemInObjectCaseSensitive(entry, fieldName, emptyArray))
            {
                cJSON_Delete(emptyArray);
                return ERROR_FAILURE;
            }
        }
        else
        {
            cJSON_AddItemToObject(entry, fieldName, emptyArray);
        }
        return NO_ERROR;
    }

    size_t count = (size_t)cJSON_GetArraySize(field);
    for (size_t i = 0; i < count; i++)
    {
        cJSON *value = cJSON_GetArrayItem(field, (int)i);
        cJSON *normalized = jsonValueToStringNode(value);
        if (normalized == NULL)
        {
            return ERROR_OUT_OF_MEMORY;
        }
        if (!cJSON_ReplaceItemInArray(field, (int)i, normalized))
        {
            cJSON_Delete(normalized);
            return ERROR_FAILURE;
        }
    }

    return NO_ERROR;
}

static error_t normalizeToniesCustomJsonForStorage(cJSON *root, char *message, size_t messageSize)
{
    // Persist a canonical shape (strings/arrays) so reads do not depend on client-side typing.
    if (!cJSON_IsArray(root))
    {
        osSnprintf(message, messageSize, "Invalid payload: root must be a JSON array");
        return ERROR_INVALID_SYNTAX;
    }

    size_t entryCount = (size_t)cJSON_GetArraySize(root);
    for (size_t i = 0; i < entryCount; i++)
    {
        cJSON *entry = cJSON_GetArrayItem(root, (int)i);
        if (!cJSON_IsObject(entry))
        {
            osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": expected object", i);
            return ERROR_INVALID_SYNTAX;
        }

        const char *stringFields[] = {"no", "model", "title", "series", "episodes", "release", "language", "category", "pic"};
        for (size_t fi = 0; fi < (sizeof(stringFields) / sizeof(stringFields[0])); fi++)
        {
            error_t normalizeFieldError = normalizeStringField(entry, stringFields[fi]);
            if (normalizeFieldError != NO_ERROR)
            {
                osSnprintf(message, messageSize, "Failed to normalize field '%s' at index %" PRIuSIZE, stringFields[fi], i);
                return normalizeFieldError;
            }
        }

        error_t normalizeTracksError = normalizeStringArrayField(entry, "tracks");
        if (normalizeTracksError != NO_ERROR)
        {
            osSnprintf(message, messageSize, "Failed to normalize field 'tracks' at index %" PRIuSIZE, i);
            return normalizeTracksError;
        }

        cJSON *audioId = cJSON_GetObjectItemCaseSensitive(entry, "audio_id");
        if (!cJSON_IsArray(audioId))
        {
            cJSON *emptyAudioId = cJSON_CreateArray();
            if (emptyAudioId == NULL)
            {
                osSnprintf(message, messageSize, "Out of memory while normalizing payload");
                return ERROR_OUT_OF_MEMORY;
            }
            if (audioId != NULL)
            {
                if (!cJSON_ReplaceItemInObjectCaseSensitive(entry, "audio_id", emptyAudioId))
                {
                    cJSON_Delete(emptyAudioId);
                    osSnprintf(message, messageSize, "Failed to normalize payload");
                    return ERROR_FAILURE;
                }
            }
            else
            {
                cJSON_AddItemToObject(entry, "audio_id", emptyAudioId);
            }
            audioId = cJSON_GetObjectItemCaseSensitive(entry, "audio_id");
        }

        size_t audioCount = (size_t)cJSON_GetArraySize(audioId);
        for (size_t j = 0; j < audioCount; j++)
        {
            cJSON *audioIdValue = cJSON_GetArrayItem(audioId, (int)j);
            uint32_t parsedAudioId = 0;
            if (!jsonGetUInt32Flexible(audioIdValue, &parsedAudioId))
            {
                osSnprintf(message, messageSize, "Invalid entry at index %" PRIuSIZE ": 'audio_id[%zu]' must be numeric", i, j);
                return ERROR_INVALID_SYNTAX;
            }

            char normalizedAudioId[16];
            osSnprintf(normalizedAudioId, sizeof(normalizedAudioId), "%" PRIu32, parsedAudioId);
            cJSON *normalizedValue = cJSON_CreateString(normalizedAudioId);
            if (normalizedValue == NULL)
            {
                osSnprintf(message, messageSize, "Out of memory while normalizing payload");
                return ERROR_OUT_OF_MEMORY;
            }

            if (!cJSON_ReplaceItemInArray(audioId, (int)j, normalizedValue))
            {
                cJSON_Delete(normalizedValue);
                osSnprintf(message, messageSize, "Failed to normalize payload");
                return ERROR_FAILURE;
            }
        }

        cJSON *hash = cJSON_GetObjectItemCaseSensitive(entry, "hash");
        if (!cJSON_IsArray(hash))
        {
            cJSON *emptyHash = cJSON_CreateArray();
            if (emptyHash == NULL)
            {
                osSnprintf(message, messageSize, "Out of memory while normalizing payload");
                return ERROR_OUT_OF_MEMORY;
            }
            if (hash != NULL)
            {
                if (!cJSON_ReplaceItemInObjectCaseSensitive(entry, "hash", emptyHash))
                {
                    cJSON_Delete(emptyHash);
                    osSnprintf(message, messageSize, "Failed to normalize payload");
                    return ERROR_FAILURE;
                }
            }
            else
            {
                cJSON_AddItemToObject(entry, "hash", emptyHash);
            }
            hash = cJSON_GetObjectItemCaseSensitive(entry, "hash");
        }

        size_t hashCount = (size_t)cJSON_GetArraySize(hash);
        for (size_t j = 0; j < hashCount; j++)
        {
            cJSON *hashValue = cJSON_GetArrayItem(hash, (int)j);
            if (cJSON_IsString(hashValue) && hashValue->valuestring != NULL)
            {
                char normalizedHash[41];
                for (size_t k = 0; k < 40; k++)
                {
                    normalizedHash[k] = (char)toupper((int)hashValue->valuestring[k]);
                }
                normalizedHash[40] = '\0';
                cJSON *normalizedValue = cJSON_CreateString(normalizedHash);
                if (normalizedValue == NULL)
                {
                    osSnprintf(message, messageSize, "Out of memory while normalizing payload");
                    return ERROR_OUT_OF_MEMORY;
                }
                if (!cJSON_ReplaceItemInArray(hash, (int)j, normalizedValue))
                {
                    cJSON_Delete(normalizedValue);
                    osSnprintf(message, messageSize, "Failed to normalize payload");
                    return ERROR_FAILURE;
                }
            }
        }
    }

    osSnprintf(message, messageSize, "OK");
    return NO_ERROR;
}

static int cmpStringAsc(const void *a, const void *b)
{
    const char *s1 = *(const char *const *)a;
    const char *s2 = *(const char *const *)b;
    return osStrcmp(s1, s2);
}

/**
 * Remove old timestamped backup files while keeping the newest keepCount entries.
 * Backups use <baseFileName>.<YYYYMMDD-HHMMSS>.bak, so lexicographic order is chronological.
 */
static void cleanupToniesCustomJsonBackups(const char *configDir, const char *baseFileName, size_t keepCount)
{
    char *prefix = custom_asprintf("%s.", baseFileName);
    if (prefix == NULL)
    {
        return;
    }
    size_t prefixLen = osStrlen(prefix);
    char *suffix = ".bak";
    size_t suffixLen = osStrlen(suffix);

    FsDir *dir = fsOpenDir(configDir);
    if (dir == NULL)
    {
        osFreeMem(prefix);
        return;
    }

    char **backupFiles = NULL;
    size_t backupCount = 0;
    FsDirEntry entry;
    while (fsReadDir(dir, &entry) == NO_ERROR)
    {
        if (entry.name[0] == '\0')
        {
            continue;
        }
        size_t nameLen = osStrlen(entry.name);
        if (nameLen <= prefixLen + suffixLen)
        {
            continue;
        }
        if (osStrncmp(entry.name, prefix, prefixLen) != 0)
        {
            continue;
        }
        if (osStrcmp(&entry.name[nameLen - suffixLen], suffix) != 0)
        {
            continue;
        }

        char **resized = osAllocMem((backupCount + 1) * sizeof(char *));
        if (resized == NULL)
        {
            break;
        }
        if (backupFiles != NULL)
        {
            osMemcpy(resized, backupFiles, backupCount * sizeof(char *));
            osFreeMem(backupFiles);
        }
        backupFiles = resized;
        backupFiles[backupCount] = strdup(entry.name);
        if (backupFiles[backupCount] == NULL)
        {
            break;
        }
        backupCount++;
    }
    fsCloseDir(dir);

    if (backupCount > keepCount)
    {
        // Backup names contain sortable timestamps (YYYYMMDD-HHMMSS), so lexical sort is chronological.
        qsort(backupFiles, backupCount, sizeof(char *), cmpStringAsc);
        size_t toDelete = backupCount - keepCount;
        for (size_t i = 0; i < toDelete; i++)
        {
            char *fullPath = custom_asprintf("%s%c%s", configDir, PATH_SEPARATOR, backupFiles[i]);
            if (fullPath != NULL)
            {
                fsDeleteFile(fullPath);
                osFreeMem(fullPath);
            }
        }
    }

    for (size_t i = 0; i < backupCount; i++)
    {
        osFreeMem(backupFiles[i]);
    }
    osFreeMem(backupFiles);
    osFreeMem(prefix);
}

static size_t getToniesCustomJsonBackupKeepCount(void)
{
    return (size_t)settings_get_unsigned("tonie_json.custom_backup_keep");
}

static error_t parseJsonRequestBody(HttpConnection *connection, cJSON **outJson, char *message, size_t messageSize)
{
    if (outJson == NULL)
    {
        osSnprintf(message, messageSize, "Internal error");
        return ERROR_INVALID_PARAMETER;
    }

    if (connection->request.byteCount == 0 || connection->request.byteCount > (1024 * 1024))
    {
        osSnprintf(message, messageSize, "Invalid body size");
        return ERROR_INVALID_LENGTH;
    }

    size_t bodySize = connection->request.byteCount;
    char *postData = osAllocMem(bodySize + 1);
    if (postData == NULL)
    {
        osSnprintf(message, messageSize, "Out of memory");
        return ERROR_OUT_OF_MEMORY;
    }
    osMemset(postData, 0, bodySize + 1);

    size_t totalRead = 0;
    while (totalRead < bodySize)
    {
        size_t chunkRead = 0;
        error_t recvError = httpReadStream(connection, postData + totalRead, bodySize - totalRead, &chunkRead, 0x00);
        if (recvError != NO_ERROR)
        {
            osFreeMem(postData);
            osSnprintf(message, messageSize, "Could not read request body");
            return recvError;
        }
        if (chunkRead == 0)
        {
            break;
        }
        totalRead += chunkRead;
    }

    if (totalRead != bodySize)
    {
        osFreeMem(postData);
        osSnprintf(message, messageSize, "Could not read request body");
        return ERROR_END_OF_STREAM;
    }

    cJSON *json = cJSON_ParseWithLengthOpts(postData, totalRead, 0, 0);
    osFreeMem(postData);
    if (json == NULL)
    {
        osSnprintf(message, messageSize, "Invalid JSON payload");
        return ERROR_INVALID_SYNTAX;
    }

    *outJson = json;
    osSnprintf(message, messageSize, "OK");
    return NO_ERROR;
}

static error_t loadToniesCustomJsonRoot(const char *configDir, cJSON **outRoot)
{
    if (configDir == NULL || outRoot == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    char *targetPath = custom_asprintf("%s%c%s", configDir, PATH_SEPARATOR, TONIES_CUSTOM_JSON_FILE);
    if (targetPath == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }

    if (!fsFileExists(targetPath))
    {
        osFreeMem(targetPath);
        *outRoot = cJSON_CreateArray();
        return (*outRoot != NULL) ? NO_ERROR : ERROR_OUT_OF_MEMORY;
    }

    size_t fileSize = 0;
    if (fsGetFileSize(targetPath, (uint32_t *)&fileSize) != NO_ERROR)
    {
        osFreeMem(targetPath);
        return ERROR_FAILURE;
    }

    char *rawJson = osAllocMem(fileSize + 1);
    if (rawJson == NULL)
    {
        osFreeMem(targetPath);
        return ERROR_OUT_OF_MEMORY;
    }
    osMemset(rawJson, 0, fileSize + 1);

    FsFile *file = fsOpenFile(targetPath, FS_FILE_MODE_READ);
    if (file == NULL)
    {
        osFreeMem(rawJson);
        osFreeMem(targetPath);
        return ERROR_FILE_OPENING_FAILED;
    }

    size_t pos = 0;
    while (pos < fileSize)
    {
        size_t sizeRead = 0;
        error_t readError = fsReadFile(file, &rawJson[pos], fileSize - pos, &sizeRead);
        if (readError != NO_ERROR)
        {
            fsCloseFile(file);
            osFreeMem(rawJson);
            osFreeMem(targetPath);
            return readError;
        }
        if (sizeRead == 0)
        {
            break;
        }
        pos += sizeRead;
    }
    fsCloseFile(file);
    osFreeMem(targetPath);

    cJSON *root = cJSON_ParseWithLengthOpts(rawJson, pos, 0, 0);
    osFreeMem(rawJson);
    if (!cJSON_IsArray(root))
    {
        cJSON_Delete(root);
        return ERROR_INVALID_SYNTAX;
    }

    *outRoot = root;
    return NO_ERROR;
}

static error_t saveToniesCustomJsonRoot(const char *configDir, cJSON *root, char *message, size_t messageSize)
{
    error_t validationError = validateToniesCustomJson(root, message, messageSize);
    if (validationError != NO_ERROR)
    {
        return validationError;
    }

    error_t normalizeError = normalizeToniesCustomJsonForStorage(root, message, messageSize);
    if (normalizeError != NO_ERROR)
    {
        return normalizeError;
    }

    char *jsonString = cJSON_PrintUnformatted(root);
    if (jsonString == NULL)
    {
        osSnprintf(message, messageSize, "Could not encode JSON");
        return ERROR_OUT_OF_MEMORY;
    }

    char *targetPath = custom_asprintf("%s%c%s", configDir, PATH_SEPARATOR, TONIES_CUSTOM_JSON_FILE);
    char *tmpPath = custom_asprintf("%s.tmp", targetPath);
    if (targetPath == NULL || tmpPath == NULL)
    {
        osFreeMem(jsonString);
        osFreeMem(targetPath);
        osFreeMem(tmpPath);
        osSnprintf(message, messageSize, "Out of memory");
        return ERROR_OUT_OF_MEMORY;
    }

    if (fsFileExists(targetPath))
    {
        time_t now = time(NULL);
        struct tm *timeInfo = localtime(&now);
        char timestamp[32];
        if (timeInfo != NULL)
        {
            strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", timeInfo);
        }
        else
        {
            osSnprintf(timestamp, sizeof(timestamp), "unknown");
        }

        char *backupPath = custom_asprintf("%s%c%s.%s.bak", configDir, PATH_SEPARATOR, TONIES_CUSTOM_JSON_FILE, timestamp);
        if (backupPath != NULL)
        {
            fsCopyFile(targetPath, backupPath, true);
            osFreeMem(backupPath);
        }
    }

    cleanupToniesCustomJsonBackups(configDir, TONIES_CUSTOM_JSON_FILE, getToniesCustomJsonBackupKeepCount());

    error_t fileError = NO_ERROR;
    FsFile *file = fsOpenFile(tmpPath, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
    if (file == NULL)
    {
        fileError = ERROR_FILE_OPENING_FAILED;
    }
    else
    {
        fileError = fsWriteFile(file, jsonString, osStrlen(jsonString));
        fsCloseFile(file);
    }

    if (fileError == NO_ERROR)
    {
        fileError = fsMoveFile(tmpPath, targetPath, true);
    }
    else
    {
        fsDeleteFile(tmpPath);
    }

    osFreeMem(jsonString);
    osFreeMem(tmpPath);
    osFreeMem(targetPath);

    if (fileError != NO_ERROR)
    {
        osSnprintf(message, messageSize, "Failed to save tonies.custom.json");
        return fileError;
    }

    tonies_deinit();
    tonies_init();
    osSnprintf(message, messageSize, "OK");
    return NO_ERROR;
}

static int findModelIndexInArray(cJSON *root, const char *model)
{
    if (!cJSON_IsArray(root) || model == NULL)
    {
        return -1;
    }

    size_t count = (size_t)cJSON_GetArraySize(root);
    for (size_t i = 0; i < count; i++)
    {
        cJSON *entry = cJSON_GetArrayItem(root, (int)i);
        cJSON *entryModel = cJSON_GetObjectItemCaseSensitive(entry, "model");
        if (cJSON_IsString(entryModel) && entryModel->valuestring != NULL && osStrcasecmp(entryModel->valuestring, model) == 0)
        {
            return (int)i;
        }
    }

    return -1;
}

static bool modelInDeleteList(cJSON *modelsArray, const char *model)
{
    if (!cJSON_IsArray(modelsArray) || model == NULL)
    {
        return false;
    }

    size_t count = (size_t)cJSON_GetArraySize(modelsArray);
    for (size_t i = 0; i < count; i++)
    {
        cJSON *item = cJSON_GetArrayItem(modelsArray, (int)i);
        if (cJSON_IsString(item) && item->valuestring != NULL && osStrcasecmp(item->valuestring, model) == 0)
        {
            return true;
        }
    }

    return false;
}

error_t handleApiToniesCustomJsonUpsert(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;

    char message[256];
    cJSON *requestJson = NULL;
    error_t bodyError = parseJsonRequestBody(connection, &requestJson, message, sizeof(message));
    if (bodyError != NO_ERROR)
    {
        return writeApiStatusText(connection, 400, message);
    }

    cJSON *entries = requestJson;
    cJSON *wrappedArray = NULL;
    if (cJSON_IsObject(requestJson))
    {
        wrappedArray = cJSON_CreateArray();
        if (wrappedArray == NULL)
        {
            cJSON_Delete(requestJson);
            return writeApiStatusText(connection, 500, "Out of memory");
        }
        cJSON *dup = cJSON_Duplicate(requestJson, 1);
        if (dup == NULL)
        {
            cJSON_Delete(wrappedArray);
            cJSON_Delete(requestJson);
            return writeApiStatusText(connection, 500, "Out of memory");
        }
        cJSON_AddItemToArray(wrappedArray, dup);
        entries = wrappedArray;
    }
    else if (!cJSON_IsArray(requestJson))
    {
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 400, "Invalid payload: expected object or array");
    }

    const char *configDir = settings_get_string("internal.configdirfull");
    cJSON *root = NULL;
    error_t loadError = loadToniesCustomJsonRoot(configDir, &root);
    if (loadError != NO_ERROR)
    {
        cJSON_Delete(wrappedArray);
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 500, "Failed to load tonies.custom.json");
    }

    size_t count = (size_t)cJSON_GetArraySize(entries);
    for (size_t i = 0; i < count; i++)
    {
        cJSON *entry = cJSON_GetArrayItem(entries, (int)i);
        if (!cJSON_IsObject(entry))
        {
            cJSON_Delete(root);
            cJSON_Delete(wrappedArray);
            cJSON_Delete(requestJson);
            return writeApiStatusText(connection, 400, "Invalid payload: each entry must be object");
        }

        cJSON *model = cJSON_GetObjectItemCaseSensitive(entry, "model");
        if (!jsonIsNonEmptyString(model))
        {
            cJSON_Delete(root);
            cJSON_Delete(wrappedArray);
            cJSON_Delete(requestJson);
            return writeApiStatusText(connection, 400, "Invalid payload: 'model' is required");
        }

        cJSON *entryCopy = cJSON_Duplicate(entry, 1);
        if (entryCopy == NULL)
        {
            cJSON_Delete(root);
            cJSON_Delete(wrappedArray);
            cJSON_Delete(requestJson);
            return writeApiStatusText(connection, 500, "Out of memory");
        }

        int existingIndex = findModelIndexInArray(root, model->valuestring);
        if (existingIndex >= 0)
        {
            if (!cJSON_ReplaceItemInArray(root, existingIndex, entryCopy))
            {
                cJSON_Delete(entryCopy);
                cJSON_Delete(root);
                cJSON_Delete(wrappedArray);
                cJSON_Delete(requestJson);
                return writeApiStatusText(connection, 500, "Failed to update entry");
            }
        }
        else
        {
            cJSON_AddItemToArray(root, entryCopy);
        }
    }

    error_t saveError = saveToniesCustomJsonRoot(configDir, root, message, sizeof(message));
    cJSON_Delete(root);
    cJSON_Delete(wrappedArray);
    cJSON_Delete(requestJson);
    if (saveError != NO_ERROR)
    {
        return writeApiStatusText(connection, (saveError == ERROR_OUT_OF_MEMORY) ? 500 : 400, message);
    }

    return writeApiStatusText(connection, 200, "OK");
}

error_t handleApiToniesCustomJsonDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;

    char message[256];
    cJSON *requestJson = NULL;
    error_t bodyError = parseJsonRequestBody(connection, &requestJson, message, sizeof(message));
    if (bodyError != NO_ERROR)
    {
        return writeApiStatusText(connection, 400, message);
    }

    cJSON *models = NULL;
    cJSON *modelsCopy = NULL;
    if (cJSON_IsArray(requestJson))
    {
        models = requestJson;
    }
    else if (cJSON_IsObject(requestJson))
    {
        cJSON *requestModels = cJSON_GetObjectItemCaseSensitive(requestJson, "models");
        if (cJSON_IsArray(requestModels))
        {
            // Keep a detached copy so models lifetime is independent from requestJson.
            modelsCopy = cJSON_Duplicate(requestModels, 1);
            if (modelsCopy == NULL)
            {
                cJSON_Delete(requestJson);
                return writeApiStatusText(connection, 500, "Out of memory");
            }
            models = modelsCopy;
        }
    }

    if (!cJSON_IsArray(models) || cJSON_GetArraySize(models) <= 0)
    {
        cJSON_Delete(modelsCopy);
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 400, "Invalid payload: 'models' array is required");
    }

    const char *configDir = settings_get_string("internal.configdirfull");
    cJSON *root = NULL;
    error_t loadError = loadToniesCustomJsonRoot(configDir, &root);
    if (loadError != NO_ERROR)
    {
        cJSON_Delete(modelsCopy);
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 500, "Failed to load tonies.custom.json");
    }

    for (int i = cJSON_GetArraySize(root) - 1; i >= 0; i--)
    {
        cJSON *entry = cJSON_GetArrayItem(root, i);
        cJSON *model = cJSON_GetObjectItemCaseSensitive(entry, "model");
        if (cJSON_IsString(model) && model->valuestring != NULL && modelInDeleteList(models, model->valuestring))
        {
            cJSON_DeleteItemFromArray(root, i);
        }
    }

    error_t saveError = saveToniesCustomJsonRoot(configDir, root, message, sizeof(message));
    cJSON_Delete(root);
    cJSON_Delete(modelsCopy);
    cJSON_Delete(requestJson);
    if (saveError != NO_ERROR)
    {
        return writeApiStatusText(connection, (saveError == ERROR_OUT_OF_MEMORY) ? 500 : 400, message);
    }

    return writeApiStatusText(connection, 200, "OK");
}

error_t handleApiToniesCustomJsonRename(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;

    char message[256];
    cJSON *requestJson = NULL;
    error_t bodyError = parseJsonRequestBody(connection, &requestJson, message, sizeof(message));
    if (bodyError != NO_ERROR)
    {
        return writeApiStatusText(connection, 400, message);
    }

    if (!cJSON_IsObject(requestJson))
    {
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 400, "Invalid payload: expected object");
    }

    cJSON *fromModel = cJSON_GetObjectItemCaseSensitive(requestJson, "fromModel");
    cJSON *toModel = cJSON_GetObjectItemCaseSensitive(requestJson, "toModel");
    if (!jsonIsNonEmptyString(fromModel) || !jsonIsNonEmptyString(toModel))
    {
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 400, "Invalid payload: 'fromModel' and 'toModel' are required");
    }
    if (osStrcasecmp(fromModel->valuestring, toModel->valuestring) == 0)
    {
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 200, "OK");
    }

    const char *configDir = settings_get_string("internal.configdirfull");
    cJSON *root = NULL;
    error_t loadError = loadToniesCustomJsonRoot(configDir, &root);
    if (loadError != NO_ERROR)
    {
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 500, "Failed to load tonies.custom.json");
    }

    int fromIndex = findModelIndexInArray(root, fromModel->valuestring);
    if (fromIndex < 0)
    {
        cJSON_Delete(root);
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 404, "Source model not found");
    }
    if (findModelIndexInArray(root, toModel->valuestring) >= 0)
    {
        cJSON_Delete(root);
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 400, "Target model already exists");
    }

    cJSON *entry = cJSON_GetArrayItem(root, fromIndex);
    cJSON *newModel = cJSON_CreateString(toModel->valuestring);
    if (newModel == NULL)
    {
        cJSON_Delete(root);
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 500, "Out of memory");
    }
    if (!cJSON_ReplaceItemInObjectCaseSensitive(entry, "model", newModel))
    {
        cJSON_Delete(newModel);
        cJSON_Delete(root);
        cJSON_Delete(requestJson);
        return writeApiStatusText(connection, 500, "Failed to rename model");
    }

    error_t saveError = saveToniesCustomJsonRoot(configDir, root, message, sizeof(message));
    cJSON_Delete(root);
    cJSON_Delete(requestJson);
    if (saveError != NO_ERROR)
    {
        return writeApiStatusText(connection, (saveError == ERROR_OUT_OF_MEMORY) ? 500 : 400, message);
    }

    return writeApiStatusText(connection, 200, "OK");
}

static char *getJsonString(cJSON *jsonElement, char *name)
{
    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsString(attr))
    {
        return strdup(attr->valuestring);
    }
    return strdup("");
}

error_t handleApiTonieboxJson(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char *path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIEBOX_JSON_FILE);

    size_t fileSize = 0;
    fsGetFileSize(path, (uint32_t *)(&fileSize));
    TRACE_INFO("Trying to read %s with size %" PRIuSIZE "\r\n", path, fileSize);

    FsFile *fsFile = fsOpenFile(path, FS_FILE_MODE_READ);
    if (fsFile == NULL)
    {
        httpWriteResponseString(connection, "Failed to open file", false);
        return ERROR_FAILURE;
    }
    size_t sizeRead;
    char *data = osAllocMem(fileSize);
    size_t pos = 0;

    while (pos < fileSize)
    {
        fsReadFile(fsFile, &data[pos], fileSize - pos, &sizeRead);
        pos += sizeRead;
    }
    fsCloseFile(fsFile);
    cJSON *inputJson = cJSON_ParseWithLengthOpts(data, fileSize, 0, 0);
    osFreeMem(data);

    /* Create a cJSON array to hold the output */
    cJSON *outputJson = cJSON_CreateArray();

    cJSON *tonieJson;
    cJSON_ArrayForEach(tonieJson, inputJson)
    {
        /* Create a cJSON object for the current item */
        cJSON *jsonObject = cJSON_CreateObject();
        if (jsonObject == NULL)
        {
            cJSON_Delete(outputJson);
            cJSON_Delete(inputJson);
            return ERROR_FAILURE;
        }

        /* Add "id" and "name" to the object */
        char *id = getJsonString(tonieJson, "id");
        char *name = getJsonString(tonieJson, "name");
        cJSON_AddStringToObject(jsonObject, "id", id);
        cJSON_AddStringToObject(jsonObject, "name", name);

        TRACE_DEBUG("Adding box '%s'\r\n", name);

        /* Handle "img_src" and caching logic */
        char *img_src = getJsonString(tonieJson, "img_src");
        if (osStrlen(img_src) > 0 && settings_get_bool("tonie_json.cache_images"))
        {
            cache_entry_t *cache = NULL;
            /* try to get existing cache entry */
            cache = cache_fetch_by_url(img_src);

            /* none existing, create one */
            if (!cache)
            {
                cache = cache_add(img_src);
            }

            /* if that failed as well, use external URL */
            if (cache)
            {
                osFreeMem(img_src);
                img_src = strdup(cache->cached_url);

                TRACE_DEBUG("Cache URL would be: '%s'\r\n", cache->cached_url);

                if (settings_get_bool("tonie_json.cache_preload"))
                {
                    /* try to download and cache the file */
                    cache_fetch_entry(cache);
                }
            }
        }
        cJSON_AddStringToObject(jsonObject, "img_src", img_src);

        /* Handle the crop array */
        cJSON *cropArray = cJSON_GetObjectItem(tonieJson, "crop");
        if (cropArray != NULL && cJSON_IsArray(cropArray))
        {
            cJSON *newCropArray = cJSON_CreateArray();
            if (newCropArray != NULL)
            {
                int cropCount = cJSON_GetArraySize(cropArray);
                for (int index = 0; index < 3; index++)
                {
                    if (index < cropCount)
                    {
                        cJSON *cropElem = cJSON_GetArrayItem(cropArray, index);
                        if (cJSON_IsNumber(cropElem))
                        {
                            cJSON_AddItemToArray(newCropArray, cJSON_CreateNumber(cropElem->valuedouble));
                        }
                        else
                        {
                            /* default value when parsing failed */
                            cJSON_AddItemToArray(newCropArray, cJSON_CreateNumber(0.0));
                        }
                    }
                    else
                    {
                        /* default value */
                        cJSON_AddItemToArray(newCropArray, cJSON_CreateNumber(0.0));
                    }
                }
                cJSON_AddItemToObject(jsonObject, "crop", newCropArray);
            }
        }

        /* Add the jsonObject to the output array */
        cJSON_AddItemToArray(outputJson, jsonObject);

        osFreeMem(id);
        osFreeMem(name);
        osFreeMem(img_src);
    }

    /* Convert the cJSON array to a JSON string */
    char *jsonString = cJSON_PrintUnformatted(outputJson);
    if (jsonString != NULL)
    {
        httpPrepareHeader(connection, "application/json; charset=utf-8", strlen(jsonString));
        httpWriteResponseString(connection, jsonString, false);
        osFreeMem(jsonString);
    }

    /* Clean up */
    cJSON_Delete(inputJson);
    cJSON_Delete(outputJson);

    return NO_ERROR;
}

error_t handleApiTonieboxCustomJson(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char *path = custom_asprintf("%s%c%s", settings_get_string("internal.configdirfull"), PATH_SEPARATOR, TONIEBOX_CUSTOM_JSON_FILE);

    if (!fsFileExists(path))
    {
        FsFile *file = fsOpenFile(path, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE);
        fsWriteFile(file, "[]", 2);
        fsCloseFile(file);
    }

    error_t err = httpSendResponseUnsafe(connection, uri, path);
    osFreeMem(path);
    return err;
}

error_t handleApiToniesJsonSearch(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char searchModel[256];
    char searchSeries[256];
    char searchEpisode[256];
    searchModel[0] = '\0';
    searchSeries[0] = '\0';
    searchEpisode[0] = '\0';
    toniesJson_item_t *result[18];
    size_t result_size;

    queryGet(queryString, "searchModel", searchModel, sizeof(searchModel));
    queryGet(queryString, "searchSeries", searchSeries, sizeof(searchSeries));
    queryGet(queryString, "searchEpisode", searchEpisode, sizeof(searchEpisode));

    tonies_byModelSeriesEpisode(searchModel, searchSeries, searchEpisode, result, &result_size);

    cJSON *jsonArray = cJSON_CreateArray();
    for (size_t i = 0; i < result_size; i++)
    {
        addToniesJsonInfoJson(result[i], NULL, jsonArray);
    }

    char *jsonString = cJSON_PrintUnformatted(jsonArray);
    cJSON_Delete(jsonArray);
    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(jsonString);

    return httpWriteResponse(connection, jsonString, connection->response.contentLength, true);
}
error_t handleApiContentJson(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }
    char *file_path = custom_asprintf("%s%s", rootPath, &uri[13]);
    return httpSendResponseUnsafe(connection, uri, file_path);
}

error_t handleApiContentJsonBase(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx, char **contentPath)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }
    // /content/json/get/3d8c0f13500304e0
    if (osStrlen(uri) != 34)
    {
        return ERROR_NOT_FOUND;
    }
    char ruid[17];
    osStrcpy(ruid, &uri[osStrlen(uri) - 16]);
    getContentPathFromCharRUID(ruid, contentPath, client_ctx->settings);

    return NO_ERROR;
}
error_t handleApiContentJsonGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char *contentPath;
    char *contentJsonPath;
    error_t error = handleApiContentJsonBase(connection, uri, queryString, client_ctx, &contentPath);
    if (error != NO_ERROR)
    {
        return error;
    }

    contentJsonPath = custom_asprintf("%s%s", contentPath, ".json");
    error = httpSendResponseUnsafe(connection, uri, contentJsonPath);
    osFreeMem(contentPath);
    osFreeMem(contentJsonPath);
    return error;
}

error_t handleApiContentJsonSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char *contentPath;
    error_t error = handleApiContentJsonBase(connection, uri, queryString, client_ctx, &contentPath);
    if (error != NO_ERROR)
    {
        return error;
    }

    char_t post_data[POST_BUFFER_SIZE];
    error = parsePostData(connection, post_data, POST_BUFFER_SIZE);
    if (error != NO_ERROR)
    {
        osFreeMem(contentPath);
        return error;
    }

    contentJson_t content_json;
    load_content_json(contentPath, &content_json, true, client_ctx->settings);

    char item_data[256];
    bool_t updated = false;
    if (queryGet(post_data, "source", item_data, sizeof(item_data)))
    {
        if (osStrcmp(item_data, content_json.source))
        {
            osFreeMem(content_json.source);
            content_json.source = strdup(item_data);
            updated = true;
        }
    }
    if (queryGet(post_data, "tonie_model", item_data, sizeof(item_data)))
    {
        if (osStrcmp(item_data, content_json.tonie_model))
        {
            osFreeMem(content_json.tonie_model);
            content_json.tonie_model = strdup(item_data);
            updated = true;
        }
    }
    if (queryGet(post_data, "live", item_data, sizeof(item_data)))
    {
        bool_t target_value = false;
        if (!osStrcmp(item_data, "true"))
        {
            target_value = true;
        }
        if (target_value != content_json.live)
        {
            content_json.live = target_value;
            updated = true;
        }
    }
    if (queryGet(post_data, "nocloud", item_data, sizeof(item_data)))
    {
        bool_t target_value = false;
        if (!osStrcmp(item_data, "true"))
        {
            target_value = true;
        }
        if (target_value != content_json.nocloud)
        {
            content_json.nocloud = target_value;
            updated = true;
        }
    }
    if (queryGet(post_data, "hide", item_data, sizeof(item_data)))
    {
        bool_t target_value = false;
        if (!osStrcmp(item_data, "true"))
        {
            target_value = true;
        }
        if (target_value != content_json.hide)
        {
            content_json.hide = target_value;
            updated = true;
        }
    }
    if (queryGet(post_data, "claimed", item_data, sizeof(item_data)))
    {
        bool_t target_value = false;
        if (!osStrcmp(item_data, "true"))
        {
            target_value = true;
        }
        if (target_value != content_json.claimed)
        {
            content_json.claimed = target_value;
            updated = true;
        }
    }

    if (updated)
    {
        char *json_path = custom_asprintf("%s.json", contentPath);
        error = save_content_json(json_path, &content_json);
        osFreeMem(json_path);
        if (error != NO_ERROR)
        {
            return error;
        }
        TRACE_INFO("Updated content json of %s\r\n", contentPath);
    }
    osFreeMem(contentPath);
    free_content_json(&content_json);

    return httpOkResponse(connection);
}

bool isHexString(const char *buf, size_t maxLen)
{
    bool isHex = true;

    for (size_t i = 0; i < osStrlen(buf) && i < maxLen; i++)
    {
        char letter = toupper(buf[i]);

        isHex &= (letter >= 'A' && letter <= 'F') || (letter >= '0' && letter <= '9');
    }

    return isHex;
}

error_t getTagInfoJson(char ruid[17], cJSON *jsonTarget, client_ctx_t *client_ctx)
{
    error_t error = NO_ERROR;
    /* build filename with 8 chars of the taf/json */
    char *tagPath = custom_asprintf("%.8s%c%.8s", &ruid[0], PATH_SEPARATOR, &ruid[8]);
    for (size_t i = 0; tagPath[i] != '\0'; i++)
    {
        tagPath[i] = toupper(tagPath[i]);
    }
    char *fullTagPath = custom_asprintf("%s%c%s", client_ctx->settings->internal.contentdirfull, PATH_SEPARATOR, tagPath);
    char *fullJsonPath = custom_asprintf("%s%c%s.json", client_ctx->settings->internal.contentdirfull, PATH_SEPARATOR, tagPath);

    if (fsFileExists(fullJsonPath))
    {
        contentJson_t contentJson;
        /* read TAF info - would create .json if not existing */
        // tonie_info_t *tafInfo = getTonieInfoFromRuid(ruid, true, client_ctx->settings);
        tonie_info_t *tafInfo = getTonieInfo(fullTagPath, false, client_ctx->settings);
        /* now update with updated model if found. */
        saveTonieInfo(tafInfo, true);
        contentJson = tafInfo->json;

        if (contentJson._valid)
        {
            /* only process one TAF/json per directory */
            cJSON *jsonEntry = cJSON_CreateObject();
            cJSON_AddStringToObject(jsonEntry, "ruid", ruid);

            char huid[24];
            for (size_t i = 0; i < 8; i++)
            {
                size_t hcharId = (i * 3);
                size_t rcharId = 16 - (i * 2) - 1;
                huid[hcharId + 2] = ':';
                huid[hcharId + 1] = toupper(ruid[rcharId]);
                huid[hcharId] = toupper(ruid[rcharId - 1]);
            }
            huid[23] = '\0';
            cJSON_AddStringToObject(jsonEntry, "uid", huid);

            bool isSys = !osStrncmp(ruid, "0000000", 7);
            if (isSys)
            {
                cJSON_AddStringToObject(jsonEntry, "type", "system");
            }
            else
            {
                cJSON_AddStringToObject(jsonEntry, "type", "tag");
            }
            cJSON_AddBoolToObject(jsonEntry, "valid", tafInfo->valid);
            cJSON_AddBoolToObject(jsonEntry, "exists", tafInfo->exists);
            cJSON_AddBoolToObject(jsonEntry, "live", tafInfo->json.live);
            cJSON_AddBoolToObject(jsonEntry, "nocloud", tafInfo->json.nocloud);
            cJSON_AddBoolToObject(jsonEntry, "hasCloudAuth", tafInfo->json._has_cloud_auth && !tafInfo->json.cloud_override);
            cJSON_AddBoolToObject(jsonEntry, "hide", tafInfo->json.hide);
            cJSON_AddBoolToObject(jsonEntry, "claimed", tafInfo->json.claimed);
            cJSON_AddStringToObject(jsonEntry, "source", tafInfo->json.source);

            cJSON *tracksArray = cJSON_AddArrayToObject(jsonEntry, "trackSeconds");
            for (size_t i = 0; i < tafInfo->additional.track_positions.count; i++)
            {
                cJSON_AddItemToArray(tracksArray, cJSON_CreateNumber(tafInfo->additional.track_positions.pos[i]));
            }

            char *downloadUrl = custom_asprintf("/content/download/%s?overlay=%s", tagPath, client_ctx->settings->internal.overlayUniqueId);
            char *audioUrl = custom_asprintf("%s&skip_header=true", downloadUrl);
            cJSON_AddStringToObject(jsonEntry, "audioUrl", audioUrl);
            if (!tafInfo->exists && !tafInfo->json.nocloud)
            {
                if (contentJson._has_cloud_auth || isSys)
                {
                    cJSON_AddStringToObject(jsonEntry, "downloadTriggerUrl", downloadUrl);
                }
                else
                {
                    cJSON_AddStringToObject(jsonEntry, "downloadTriggerUrl", "");
                }
            }
            osFreeMem(audioUrl);
            osFreeMem(downloadUrl);

            toniesJson_item_t *item = tonies_byModel(contentJson.tonie_model);
            addToniesJsonInfoJson(item, contentJson.tonie_model, jsonEntry);

            toniesJson_item_t *item2 = tonies_byModel(contentJson._source_model);
            if (tafInfo->exists && item != item2)
            {
                cJSON *jsonSourceInfo = cJSON_CreateObject();
                addToniesJsonInfoJson(item2, contentJson._source_model, jsonSourceInfo);
                cJSON *tonieInfoCopy = cJSON_DetachItemFromObject(jsonSourceInfo, "tonieInfo");
                cJSON_AddItemToObject(jsonEntry, "sourceInfo", tonieInfoCopy);
            }

            if (cJSON_IsArray(jsonTarget))
            {
                cJSON_AddItemToArray(jsonTarget, jsonEntry);
            }
            else
            {
                cJSON_AddItemToObject(jsonTarget, "tagInfo", jsonEntry);
            }
        }
        else
        {
            error = ERROR_NOT_FOUND;
        }
        freeTonieInfo(tafInfo);
    }
    else
    {
        error = ERROR_NOT_FOUND;
    }

    osFreeMem(tagPath);
    osFreeMem(fullTagPath);
    osFreeMem(fullJsonPath);

    return error;
}

error_t handleApiTagInfo(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    char ruid[17];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }
    if (!queryGet(queryString, "ruid", ruid, sizeof(ruid)))
    {
        return ERROR_FAILURE;
    }

    cJSON *json = cJSON_CreateObject();

    error_t error = getTagInfoJson(ruid, json, client_ctx);
    if (error != NO_ERROR)
    {
        cJSON_Delete(json);
        return error;
    }

    char *jsonString = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(jsonString);

    return httpWriteResponse(connection, jsonString, connection->response.contentLength, true);
}
error_t handleApiTagIndex(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    FsDir *dir = fsOpenDir(rootPath);
    if (dir == NULL)
    {
        TRACE_ERROR("Failed to open dir '%s'\r\n", rootPath);
        return ERROR_FAILURE;
    }

    cJSON *json = cJSON_CreateObject();
    cJSON *jsonArray = cJSON_AddArrayToObject(json, "tags");

    while (true)
    {
        FsDirEntry entry;
        if (fsReadDir(dir, &entry) != NO_ERROR)
        {
            fsCloseDir(dir);
            break;
        }

        if (!(entry.attributes & FS_FILE_ATTR_DIRECTORY))
        {
            continue;
        }
        if (osStrlen(entry.name) != 8)
        {
            continue;
        }

        if (!isHexString(entry.name, 8))
        {
            continue;
        }

        char ruid[17];
        osStrcpy(ruid, entry.name);

        char *subDirPath = custom_asprintf("%s/%s", rootPath, entry.name);
        FsDir *subDir = fsOpenDir(subDirPath);

        while (true)
        {
            FsDirEntry subEntry;
            if (fsReadDir(subDir, &subEntry) != NO_ERROR)
            {
                break;
            }

            /* do not process directories here */
            if ((subEntry.attributes & FS_FILE_ATTR_DIRECTORY))
            {
                continue;
            }
            /* filename must start with 8 hex characters */
            if (!isHexString(subEntry.name, 8))
            {
                continue;
            }

            /* fill rest of reverse UID */
            osStrncpy(&ruid[8], subEntry.name, 8);
            ruid[16] = '\0';
            for (size_t i = 0; ruid[i] != '\0'; i++)
            {
                ruid[i] = tolower(ruid[i]);
            }

            if (getTagInfoJson(ruid, jsonArray, client_ctx) == NO_ERROR)
            {
                break;
            }
        }
        fsCloseDir(subDir);
        osFreeMem(subDirPath);
    }

    char *jsonString = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(jsonString);

    return httpWriteResponse(connection, jsonString, connection->response.contentLength, true);
}

#define TEST_TOKEN "THIS_IS_A_TEST_TOKEN"

error_t handleApiAuthLogin(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char_t post_data[POST_BUFFER_SIZE];
    error_t error = parsePostData(connection, post_data, POST_BUFFER_SIZE);
    if (error != NO_ERROR)
    {
        return error;
    }

    char username[256];
    if (queryGet(post_data, "username", username, sizeof(username)))
    {
        char passwordHash[256];
        if (queryGet(post_data, "passwordHash", passwordHash, sizeof(passwordHash)))
        {
            if (osStrcmp("admin", username) == 0) // && osStrcmp("admin", passwordHash) == 0)
            {
                char *token = TEST_TOKEN;
                httpInitResponseHeader(connection);
                connection->response.contentType = "text/plain";
                connection->response.contentLength = osStrlen(token);

                return httpWriteResponse(connection, token, connection->response.contentLength, false);
            }
        }
    }
    httpInitResponseHeader(connection);
    connection->response.contentLength = 0;
    connection->response.statusCode = 401; // Unauthorized
    return httpWriteResponse(connection, "", connection->response.contentLength, false);
}
error_t handleApiAuthLogout(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    httpInitResponseHeader(connection);
    connection->response.contentLength = 0;
    connection->response.statusCode = 200; // Unauthorized
    connection->response.contentType = "text/plain";
    return httpWriteResponse(connection, "", connection->response.contentLength, false);
}
error_t handleApiAuthRefreshToken(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char_t post_data[POST_BUFFER_SIZE];
    error_t error = parsePostData(connection, post_data, POST_BUFFER_SIZE);
    if (error != NO_ERROR)
    {
        return error;
    }

    httpInitResponseHeader(connection);
    connection->response.statusCode = 401; // Unauthorized
    connection->response.contentType = "text/plain";
    char refreshToken[256];
    refreshToken[0] = '\0';
    if (queryGet(post_data, "refreshToken", refreshToken, sizeof(refreshToken)))
    {
        if (osStrcmp(TEST_TOKEN, refreshToken) == 0)
        {
            connection->response.statusCode = 200;
        }
    }
    connection->response.contentLength = osStrlen(refreshToken);
    return httpWriteResponse(connection, refreshToken, connection->response.contentLength, false);
}

error_t handleApiMigrateContent2Lib(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    char_t post_data[POST_BUFFER_SIZE];
    error_t error = ERROR_FILE_NOT_FOUND;
    error = parsePostData(connection, post_data, POST_BUFFER_SIZE);
    if (error != NO_ERROR)
    {
        return error;
    }
    char ruid[256];
    char libroot[256];
    bool_t lib_root = false;
    if (queryGet(post_data, "libroot", libroot, sizeof(libroot)))
    {
        if (osStrcmp("true", libroot) == 0)
        {
            lib_root = true;
        }
    }

    if (queryGet(post_data, "ruid", ruid, sizeof(ruid)) && osStrlen(ruid) == 16)
    {
        tonie_info_t *tonieInfo;
        tonieInfo = getTonieInfoFromRuid(ruid, false, client_ctx->settings);

        if (tonieInfo->valid)
        {
            if (tonieInfo->json._source_type != CT_SOURCE_NONE)
            {
                error = ERROR_FILE_NOT_FOUND;
                TRACE_WARNING("Source already set, cannot migrate %s\n", ruid);
            }
            else
            {
                error = moveTAF2Lib(tonieInfo, client_ctx->settings, lib_root);
            }
        }
        else
        {
            error = ERROR_FILE_NOT_FOUND;
        }
        freeTonieInfo(tonieInfo);
    }
    if (error != NO_ERROR)
    {
        return ERROR_FILE_NOT_FOUND;
    }
    return httpOkResponse(connection);
}

error_t handleDeleteOverlay(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay), &client_ctx->settings) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }
    if (get_overlay_id(overlay) == 0)
    {
        TRACE_ERROR("No overlay detected %s\n", overlay);
        return ERROR_FAILURE;
    }
    get_settings_cn(overlay)->internal.config_used = false;
    settings_save();
    TRACE_INFO("Removed overlay %s\n", overlay);

    return httpOkResponse(connection);
}

error_t handleApiCacheFlush(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    /* RESTful API-based cache flush request */
    uint32_t deleted = cache_flush();

    char json_resp[128];
    snprintf(json_resp, sizeof(json_resp), "{\"message\": \"Cache successfully flushed.\", \"deleted_files\": %u}", deleted);

    httpPrepareHeader(connection, "application/json; charset=utf-8", strlen(json_resp));
    return httpWriteResponseString(connection, json_resp, false);
}

error_t handleApiCacheStats(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    cache_stats_t stats;
    cache_stats(&stats);

    char stats_json[512];
    snprintf(stats_json, sizeof(stats_json),
             "{"
             "\"total_entries\": %" PRIuSIZE ","
             "\"exists_entries\": %" PRIuSIZE ","
             "\"total_files\": %" PRIuSIZE ","
             "\"total_size\": %" PRIuSIZE ","
             "\"memory_used\": %" PRIuSIZE ""
             "}",
             stats.total_entries,
             stats.exists_entries,
             stats.total_files,
             stats.total_size,
             stats.memory_used);

    httpPrepareHeader(connection, "application/json; charset=utf-8", osStrlen(stats_json));
    return httpWriteResponseString(connection, stats_json, false);
}

error_t handleApiPluginsGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    cJSON *pluginNames = cJSON_CreateArray();
    cJSON_AddItemToObject(cJSON_CreateObject(), "plugins", pluginNames);
    FsDir *dir = fsOpenDir(client_ctx->settings->internal.pluginsdirfull);
    if (dir)
    {
        while (true)
        {
            FsDirEntry entry;
            if (fsReadDir(dir, &entry) != NO_ERROR)
            {
                fsCloseDir(dir);
                break;
            }
            if (osStrcmp(entry.name, ".") == 0 || osStrcmp(entry.name, "..") == 0)
            {
                continue;
            }
            if ((entry.attributes & FS_FILE_ATTR_DIRECTORY) == FS_FILE_ATTR_DIRECTORY)
            {
                cJSON *pluginName = cJSON_CreateString(entry.name);
                cJSON_AddItemToArray(pluginNames, pluginName);
            }
        }

        char *pluginJson = cJSON_Print(pluginNames);
        httpPrepareHeader(connection, "application/json; charset=utf-8", osStrlen(pluginJson));
        cJSON_Delete(pluginNames);
        return httpWriteResponseString(connection, pluginJson, true);
    }
    return ERROR_FAILURE;
}