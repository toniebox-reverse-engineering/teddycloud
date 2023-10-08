
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

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
#include "fs_ext.h"
#include "cert.h"
#include "esp32.h"

void sanitizePath(char *path, bool isDir)
{
    size_t i, j;
    bool slash = false;

    pathCanonicalize(path);

    /* Merge all double (or more) slashes // */
    for (i = 0, j = 0; path[i]; ++i)
    {
        if (path[i] == '/')
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
    if (j > 1 && path[j - 1] == '/')
        j--;

    /* Null terminate the sanitized path */
    path[j] = '\0';

#ifndef WIN32
    /* If path doesn't start with '/', shift right and add '/' */
    if (path[0] != '/')
    {
        memmove(&path[1], &path[0], j + 1); // Shift right
        path[0] = '/';                      // Add '/' at the beginning
        j++;
    }
#endif

    /* If path doesn't end with '/', add '/' at the end */
    if (isDir)
    {
        if (path[j - 1] != '/')
        {
            path[j] = '/';      // Add '/' at the end
            path[j + 1] = '\0'; // Null terminate
        }
    }
}

error_t queryPrepare(const char *queryString, const char **rootPath, char *overlay, size_t overlay_size)
{
    char special[16];

    osStrcpy(overlay, "");
    osStrcpy(special, "");

    *rootPath = settings_get_string_ovl("internal.contentdirfull", overlay);

    if (*rootPath == NULL || !fsDirExists(*rootPath))
    {
        TRACE_ERROR("internal.contentdirfull not set to a valid path: '%s'\r\n", *rootPath);
        return ERROR_FAILURE;
    }

    if (queryGet(queryString, "special", special, sizeof(special)))
    {
        TRACE_INFO("requested index for '%s'\r\n", special);
        if (!osStrcmp(special, "library"))
        {
            *rootPath = settings_get_string_ovl("internal.librarydirfull", overlay);

            if (*rootPath == NULL || !fsDirExists(*rootPath))
            {
                TRACE_ERROR("internal.librarydirfull not set to a valid path: '%s'\r\n", *rootPath);
                return ERROR_FAILURE;
            }
        }
    }

    if (overlay)
    {
        if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
        {
            TRACE_INFO("got overlay '%s'\r\n", overlay);
        }
    }

    return NO_ERROR;
}

error_t handleApiAssignUnknown(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    const char *rootPath = NULL;
    char *response = "OK";
    error_t ret = NO_ERROR;

    TRACE_INFO("Query: '%s'\r\n", queryString);

    char path[256];
    char overlay[16];

    osStrcpy(path, "");

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay)) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    if (queryGet(queryString, "path", path, sizeof(path)))
    {
        TRACE_INFO("got path '%s'\r\n", path);
    }

    if (ret == NO_ERROR)
    {
        /* important: first canonicalize path, then merge to prevent directory traversal attacks */
        pathSafeCanonicalize(path);
        char *pathAbsolute = custom_asprintf("%s/%s", rootPath, path);
        pathSafeCanonicalize(pathAbsolute);

        TRACE_INFO("Set '%s' for next unknown request\r\n", pathAbsolute);

        settings_set_string_ovl("internal.assign_unknown", pathAbsolute, overlay);
        osFreeMem(pathAbsolute);
    }

    httpInitResponseHeader(connection);
    connection->response.contentType = "text/plain";
    connection->response.contentLength = osStrlen(response);

    return httpWriteResponseString(connection, response, false);
}

error_t handleApiGetIndex(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *jsonArray = cJSON_AddArrayToObject(json, "options");

    char overlay[16];
    osStrcpy(overlay, "");
    if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
    {
        TRACE_INFO("got overlay '%s'\r\n", overlay);
    }
    for (size_t pos = 0; pos < settings_get_size(); pos++)
    {
        setting_item_t *opt = settings_get_ovl(pos, overlay);

        if (opt->internal || opt->type == TYPE_TREE_DESC)
        {
            continue;
        }

        cJSON *jsonEntry = cJSON_CreateObject();
        cJSON_AddStringToObject(jsonEntry, "ID", opt->option_name);
        cJSON_AddStringToObject(jsonEntry, "shortname", opt->option_name);
        cJSON_AddStringToObject(jsonEntry, "description", opt->description);
        cJSON_AddStringToObject(jsonEntry, "label", opt->label);

        switch (opt->type)
        {
        case TYPE_BOOL:
            cJSON_AddStringToObject(jsonEntry, "type", "bool");
            cJSON_AddBoolToObject(jsonEntry, "value", settings_get_bool_ovl(opt->option_name, overlay));
            break;
        case TYPE_UNSIGNED:
            cJSON_AddStringToObject(jsonEntry, "type", "uint");
            cJSON_AddNumberToObject(jsonEntry, "value", settings_get_unsigned_ovl(opt->option_name, overlay));
            cJSON_AddNumberToObject(jsonEntry, "min", opt->min.unsigned_value);
            cJSON_AddNumberToObject(jsonEntry, "max", opt->max.unsigned_value);
            break;
        case TYPE_SIGNED:
            cJSON_AddStringToObject(jsonEntry, "type", "int");
            cJSON_AddNumberToObject(jsonEntry, "value", settings_get_signed_ovl(opt->option_name, overlay));
            cJSON_AddNumberToObject(jsonEntry, "min", opt->min.signed_value);
            cJSON_AddNumberToObject(jsonEntry, "max", opt->max.signed_value);
            break;
        case TYPE_HEX:
            cJSON_AddStringToObject(jsonEntry, "type", "hex");
            cJSON_AddNumberToObject(jsonEntry, "value", settings_get_unsigned_ovl(opt->option_name, overlay));
            cJSON_AddNumberToObject(jsonEntry, "min", opt->min.unsigned_value);
            cJSON_AddNumberToObject(jsonEntry, "max", opt->max.unsigned_value);
            break;
        case TYPE_STRING:
            cJSON_AddStringToObject(jsonEntry, "type", "string");
            cJSON_AddStringToObject(jsonEntry, "value", settings_get_string_ovl(opt->option_name, overlay));
            break;
        case TYPE_FLOAT:
            cJSON_AddStringToObject(jsonEntry, "type", "float");
            cJSON_AddNumberToObject(jsonEntry, "value", settings_get_float_ovl(opt->option_name, overlay));
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

error_t handleApiGetBoxes(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *ctx)
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

error_t handleApiGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    const char *item = &uri[5 + 3 + 1];

    char response[32];
    osStrcpy(response, "ERROR");
    const char *response_ptr = response;

    char overlay[16];
    osStrcpy(overlay, "");
    if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
    {
        TRACE_INFO("got overlay '%s'\r\n", overlay);
    }
    setting_item_t *opt = settings_get_by_name_ovl(item, overlay);

    if (opt)
    {
        switch (opt->type)
        {
        case TYPE_BOOL:
            osSprintf(response, "%s", settings_get_bool_ovl(item, overlay) ? "true" : "false");
            break;
        case TYPE_HEX:
        case TYPE_UNSIGNED:
            osSprintf(response, "%d", settings_get_unsigned_ovl(item, overlay));
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

error_t handleApiSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char response[256];
    osSprintf(response, "ERROR");
    const char *item = &uri[9];

    char_t data[BODY_BUFFER_SIZE];
    size_t size;
    if (BODY_BUFFER_SIZE <= connection->request.byteCount)
    {
        TRACE_ERROR("Body size for setting '%s' %zu bigger than buffer size %i bytes\r\n", item, connection->request.byteCount, BODY_BUFFER_SIZE);
    }
    else
    {
        error_t error = httpReceive(connection, &data, BODY_BUFFER_SIZE, &size, 0x00);
        if (error != NO_ERROR)
        {
            TRACE_ERROR("httpReceive failed!");
            return error;
        }
        data[size] = 0;

        TRACE_INFO("Setting: '%s' to '%s'\r\n", item, data);

        char overlay[16];
        osStrcpy(overlay, "");
        if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
        {
            TRACE_INFO("got overlay '%s'\r\n", overlay);
        }
        setting_item_t *opt = settings_get_by_name_ovl(item, overlay);
        bool success = false;

        if (opt)
        {
            switch (opt->type)
            {
            case TYPE_BOOL:
            {
                success = settings_set_bool_ovl(item, !strcasecmp(data, "true"), overlay);
                break;
            }
            case TYPE_STRING:
            {
                success = settings_set_string_ovl(item, data, overlay);
                break;
            }
            case TYPE_HEX:
            {
                uint32_t value = strtoul(data, NULL, 16);
                success = settings_set_unsigned_ovl(item, value, overlay);
                break;
            }

            case TYPE_UNSIGNED:
            {
                uint32_t value = strtoul(data, NULL, 10);
                success = settings_set_unsigned_ovl(item, value, overlay);
                break;
            }

            case TYPE_SIGNED:
            {
                int32_t value = strtol(data, NULL, 10);
                success = settings_set_signed_ovl(item, value, overlay);
                break;
            }

            case TYPE_FLOAT:
            {
                float value = strtof(data, NULL);
                success = settings_set_float_ovl(item, value, overlay);
                break;
            }

            default:
                break;
            }
        }
        else
        {
            TRACE_ERROR("Setting '%s' is unknown", item);
        }

        if (success)
        {
            osStrcpy(response, "OK");
        }
    }

    httpPrepareHeader(connection, "text/plain; charset=utf-8", 0);
    return httpWriteResponseString(connection, response, false);
}

error_t handleApiFileIndex(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char *jsonString = strdup("{\"files\":[]}");

    do
    {
        char overlay[16];
        const char *rootPath = NULL;

        if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay)) != NO_ERROR)
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
        char *pathAbsolute = custom_asprintf("%s/%s", rootPath, path);
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

            char dateString[64];

            osSnprintf(dateString, sizeof(dateString), " %04" PRIu16 "-%02" PRIu8 "-%02" PRIu8 ",  %02" PRIu8 ":%02" PRIu8 ":%02" PRIu8,
                       entry.modified.year, entry.modified.month, entry.modified.day,
                       entry.modified.hours, entry.modified.minutes, entry.modified.seconds);

            char *filePathAbsolute = custom_asprintf("%s/%s", pathAbsolute, entry.name);
            pathSafeCanonicalize(filePathAbsolute);

            char desc[64];
            desc[0] = 0;
            tonie_info_t *tafInfo = getTonieInfo(filePathAbsolute, client_ctx->settings);
            if (tafInfo->valid)
            {
                osSnprintf(desc, sizeof(desc), "TAF:%08X:", tafInfo->tafHeader->audio_id);
                for (int pos = 0; pos < tafInfo->tafHeader->sha1_hash.len; pos++)
                {
                    char tmp[3];
                    osSprintf(tmp, "%02X", tafInfo->tafHeader->sha1_hash.data[pos]);
                    osStrcat(desc, tmp);
                }
            }
            osFreeMem(filePathAbsolute);
            freeTonieInfo(tafInfo);

            cJSON *jsonEntry = cJSON_CreateObject();
            cJSON_AddStringToObject(jsonEntry, "name", entry.name);
            cJSON_AddStringToObject(jsonEntry, "date", dateString);
            cJSON_AddNumberToObject(jsonEntry, "size", entry.size);
            cJSON_AddBoolToObject(jsonEntry, "isDirectory", (entry.attributes & FS_FILE_ATTR_DIRECTORY));
            cJSON_AddStringToObject(jsonEntry, "desc", desc);

            cJSON_AddItemToArray(jsonArray, jsonEntry);

            pos++;
        }

        osFreeMem(pathAbsolute);
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
    ctx->filename = custom_asprintf("%s/%s", ctx->root_path, filename);
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
    char message[128];
    char overlay[128];
    osStrcpy(overlay, "");
    if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
    {
        TRACE_INFO("got overlay '%s'\r\n", overlay);
    }
    const char *rootPath = settings_get_string_ovl("core.certdir", overlay);

    if (rootPath == NULL || !fsDirExists(rootPath))
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "core.certdir not set to a valid path");
        TRACE_ERROR("core.certdir not set to a valid path\r\n");
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

error_t handleApiUploadFirmware(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    uint_t statusCode = 500;
    char message[128];
    char overlay[128];

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

error_t handleApiPatchFirmware(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    const char *rootPath = get_settings()->internal.firmwaredirfull;

    TRACE_INFO("Patch firmware\r\n");
    TRACE_DEBUG("Query: '%s'\r\n", queryString);

    bool generate_certs = false;
    bool inject_ca = true;
    char patch_host[32];
    char filename[255];
    char mac[13];
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

    const char *sep = osStrchr(filename, '_');
    if (!sep || strlen(&sep[1]) < 12)
    {
        TRACE_ERROR("Invalid file pattern '%s'\r\n", filename);
        return ERROR_NOT_FOUND;
    }
    osStrncpy(mac, &sep[1], 12);
    mac[12] = 0;

    char *file_path = custom_asprintf("%s/%s", rootPath, filename);
    char *patched_path = custom_asprintf("%s/patched_%s.bin", rootPath, mac);

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
        if (esp32_patch_host(patched_path, patch_host) != NO_ERROR)
        {
            TRACE_ERROR("Failed to patch hostnames\r\n");
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
    char overlay[128];
    char path[128];

    osStrcpy(path, "");

    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay)) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    if (!queryGet(queryString, "path", path, sizeof(path)))
    {
        osStrcpy(path, "/");
    }

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, true);
    char *pathAbsolute = custom_asprintf("%s/%s", rootPath, path);
    sanitizePath(pathAbsolute, true);

    uint_t statusCode = 500;
    char message[256];

    osSnprintf(message, sizeof(message), "OK");

    if (!fsDirExists(pathAbsolute))
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "invalid path: '%s'", path);
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
    const char *rootPath = settings_get_string("internal.contentdirfull");

    TRACE_DEBUG("Query: '%s'\r\n", queryString);

    char ogg[16];
    char overlay[16];
    char special[16];

    osStrcpy(ogg, "");
    osStrcpy(overlay, "");
    osStrcpy(special, "");

    if (!queryGet(queryString, "ogg", ogg, sizeof(ogg)))
    {
        strcpy(ogg, "false");
    }
    if (queryGet(queryString, "overlay", overlay, sizeof(overlay)))
    {
        TRACE_DEBUG("got overlay '%s'\r\n", overlay);
    }
    if (queryGet(queryString, "special", special, sizeof(special)))
    {
        TRACE_DEBUG("requested index for special '%s'\r\n", special);
        if (!osStrcmp(special, "library"))
        {
            rootPath = settings_get_string("internal.librarydirfull");

            if (rootPath == NULL || !fsDirExists(rootPath))
            {
                TRACE_ERROR("internal.librarydirfull not set to a valid path: '%s'\r\n", rootPath);
                return ERROR_FAILURE;
            }
        }
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
    tonie_info_t *tafInfo = getTonieInfo(file_path, client_ctx->settings);

    if (tafInfo->valid && tafInfo->stream)
    {
        isStream = true;
        length = CONTENT_LENGTH_MAX;
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

        ctx->taf = toniefile_create(ctx->file_path, ctx->audio_id);

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

error_t handleApiPcmUpload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[128];
    char name[256];
    char uid[32];
    char path[128];
    char audio_id_str[128];
    uint32_t audio_id = 0;

    osStrcpy(name, "unnamed");
    osStrcpy(uid, "");
    osStrcpy(path, "");
    osStrcpy(audio_id_str, "");

    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay)) != NO_ERROR)
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
    char *pathAbsolute = custom_asprintf("%s/%s", rootPath, path);
    sanitizePath(pathAbsolute, true);

    uint_t statusCode = 500;
    char message[256];
    osSnprintf(message, sizeof(message), "OK");

    if (!fsDirExists(pathAbsolute))
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "invalid path: '%s'", path);
        TRACE_ERROR("invalid path: '%s' -> '%s'\r\n", path, pathAbsolute);
    }
    else
    {
        char *filename = custom_asprintf("%s/%s.taf", pathAbsolute, name);

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

error_t handleApiDirectoryCreate(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    char overlay[16];
    const char *rootPath = NULL;

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay)) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    char path[256];
    size_t size = 0;

    error_t error = httpReceive(connection, &path, sizeof(path), &size, 0x00);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("httpReceive failed!");
        return error;
    }
    path[size] = 0;

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, true);
    char *pathAbsolute = custom_asprintf("%s/%s", rootPath, path);
    sanitizePath(pathAbsolute, true);

    TRACE_INFO("Creating directory: '%s'\r\n", pathAbsolute);

    uint_t statusCode = 200;
    char message[256 + 64];

    osSnprintf(message, sizeof(message), "OK");

    error_t err = fsCreateDir(pathAbsolute);

    if (err != NO_ERROR)
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "Error creating directory '%s', error %d", path, err);
        TRACE_ERROR("Error creating directory '%s' -> '%s', error %d\r\n", path, pathAbsolute, err);
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

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay)) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }
    char path[256];
    size_t size = 0;

    error_t error = httpReceive(connection, &path, sizeof(path), &size, 0x00);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("httpReceive failed!");
        return error;
    }
    path[size] = 0;

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, true);
    char *pathAbsolute = custom_asprintf("%s/%s", rootPath, path);
    sanitizePath(pathAbsolute, true);

    TRACE_INFO("Deleting directory: '%s'\r\n", pathAbsolute);

    uint_t statusCode = 200;
    char message[256 + 64];

    osSnprintf(message, sizeof(message), "OK");

    error_t err = fsRemoveDir(pathAbsolute);

    if (err != NO_ERROR)
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "Error deleting directory '%s', error %d", path, err);
        TRACE_ERROR("Error deleting directory '%s' -> '%s', error %d\r\n", path, pathAbsolute, err);
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

    if (queryPrepare(queryString, &rootPath, overlay, sizeof(overlay)) != NO_ERROR)
    {
        return ERROR_FAILURE;
    }

    char path[256];
    size_t size = 0;

    error_t error = httpReceive(connection, &path, sizeof(path), &size, 0x00);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("httpReceive failed!");
        return error;
    }
    path[size] = 0;

    TRACE_INFO("Deleting file: '%s'\r\n", path);

    /* first canonicalize path, then merge to prevent directory traversal bugs */
    sanitizePath(path, false);
    char *pathAbsolute = custom_asprintf("%s/%s", rootPath, path);
    sanitizePath(pathAbsolute, false);

    uint_t statusCode = 200;
    char message[256 + 64];

    osSnprintf(message, sizeof(message), "OK");

    error_t err = fsDeleteFile(pathAbsolute);

    if (err != NO_ERROR)
    {
        statusCode = 500;
        osSnprintf(message, sizeof(message), "Error deleting file '%s', error %d", path, err);
        TRACE_ERROR("Error deleting file '%s' -> '%s', error %d\r\n", path, pathAbsolute, err);
    }
    httpPrepareHeader(connection, "text/plain; charset=utf-8", osStrlen(message));
    connection->response.statusCode = statusCode;

    osFreeMem(pathAbsolute);

    return httpWriteResponseString(connection, message, false);
}

error_t handleApiToniesJson(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    return httpSendResponseUnsafe(connection, uri, TONIES_JSON_PATH);
}
error_t handleApiToniesCustomJson(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    return httpSendResponseUnsafe(connection, uri, TONIES_CUSTOM_JSON_PATH);
}