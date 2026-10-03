#include "libraryMeta.h"

#include "cJSON.h"
#include "os_port.h"
#include "debug.h"
#include "json_helper.h"
#include "server_helpers.h"
#include "fs_ext.h"

static cJSON *library_meta_read(const char *json_path)
{
    if (!fsFileExists(json_path))
    {
        return cJSON_CreateObject();
    }

    size_t fileSize = 0;
    fsGetFileSize(json_path, (uint32_t *)(&fileSize));

    FsFile *fsFile = fsOpenFile(json_path, FS_FILE_MODE_READ);
    if (fsFile == NULL)
    {
        return cJSON_CreateObject();
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

    cJSON *root = cJSON_ParseWithLengthOpts(data, fileSize, 0, 0);
    osFreeMem(data);

    if (root == NULL)
    {
        TRACE_WARNING("Failed to parse library meta json '%s', starting fresh\r\n", json_path);
        return cJSON_CreateObject();
    }

    return root;
}

bool_t library_meta_get_listened(const char *content_path)
{
    char *jsonPath = custom_asprintf("%s.json", content_path);
    cJSON *root = library_meta_read(jsonPath);
    bool_t listened = jsonGetBool(root, "listened");
    cJSON_Delete(root);
    osFreeMem(jsonPath);
    return listened;
}

error_t library_meta_set_listened(const char *content_path, bool_t listened)
{
    char *jsonPath = custom_asprintf("%s.json", content_path);
    cJSON *root = library_meta_read(jsonPath);

    cJSON_DeleteItemFromObject(root, "listened");
    cJSON_AddBoolToObject(root, "listened", listened);

    char *jsonPathTmp = custom_asprintf("%s.tmp", jsonPath);
    error_t error = NO_ERROR;
    char *jsonRaw = cJSON_Print(root);

    FsFile *file = fsOpenFile(jsonPathTmp, FS_FILE_MODE_WRITE);
    if (file != NULL)
    {
        error = fsWriteFile(file, jsonRaw, osStrlen(jsonRaw));
        fsCloseFile(file);
    }
    else
    {
        error = ERROR_FILE_OPENING_FAILED;
    }

    if (error == NO_ERROR)
    {
        error = fsMoveFile(jsonPathTmp, jsonPath, true);
    }

    cJSON_Delete(root);
    osFreeMem(jsonRaw);
    osFreeMem(jsonPathTmp);
    osFreeMem(jsonPath);

    return error;
}
