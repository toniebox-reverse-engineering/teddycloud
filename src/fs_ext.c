
#include "fs_ext.h"

#include <errno.h>           // for errno
#include <stdint.h>          // for uint8_t
#include <stdio.h>           // for fopen, FILE
#include <stdlib.h>          // for NULL, free
#include <string.h>          // for strdup, strlen, strrchr, strerror
#include "error.h"           // for NO_ERROR, ERROR_END_OF_FILE, ERROR_FILE_...
#include "debug.h"           // for TRACE_INFO, TRACE_ERROR, TRACE_LEVEL_INFO
#include "fs_port_config.h"  // for PATH_SEPARATOR
#include "os_port.h"         // for osStrlen

#define FILE_COPY_BUFFER_SIZE 4096 // You can adjust this buffer size as needed

void fsFixPath(char_t *path)
{
#ifdef _WIN32
    // Replace forward slashes with backslashes for Windows systems
    for (int i = 0; path[i] != '\0'; i++)
    {
        if (path[i] == PATH_SEPARATOR_LINUX)
            path[i] = PATH_SEPARATOR_WINDOWS;
    }
#endif
}

FsFile *fsOpenFileEx(const char_t *path, char *mode)
{
    // Workaround due to missing append in cyclone framwwork.

    // File pointer
    FILE *fp = NULL;

    // Make sure the pathname is valid
    if (path == NULL)
        return NULL;

    // Open the specified file
    fp = fopen(path, mode);

    if (fp == NULL) {
        TRACE_ERROR("Could not open file %s: %s\n", path, strerror(errno));
    }

    // Return a handle to the file
    return fp;
}

error_t fsCompareFiles(const char_t *source_path, const char_t *target_path, size_t *diff_position)
{
    size_t position = 0;
    if (diff_position == NULL)
    {
        diff_position = &position;
    }

    if (!fsFileExists(source_path))
    {
        return ERROR_FILE_NOT_FOUND;
    }
    if (!fsFileExists(target_path))
    {
        return ERROR_FILE_NOT_FOUND;
    }

    FsFile *source_file = fsOpenFileEx(source_path, "rb");
    if (source_file == NULL)
        return ERROR_FILE_OPENING_FAILED;

    FsFile *target_file = fsOpenFileEx(target_path, "rb");
    if (target_file == NULL)
    {
        fsCloseFile(source_file);
        return ERROR_FILE_OPENING_FAILED;
    }

    uint8_t buffer_source[FILE_COPY_BUFFER_SIZE];
    uint8_t buffer_target[FILE_COPY_BUFFER_SIZE];
    size_t bytes_read_source = 0;
    size_t bytes_read_target = 0;
    error_t error = NO_ERROR;
    *diff_position = 0;
    while (error == NO_ERROR)
    {
        error = fsReadFile(source_file, buffer_source, sizeof(buffer_source), &bytes_read_source);
        if (error != NO_ERROR && error != ERROR_END_OF_FILE)
        {
            break;
        }
        error = fsReadFile(target_file, buffer_target, sizeof(buffer_target), &bytes_read_target);
        if (error != NO_ERROR && error != ERROR_END_OF_FILE)
        {
            break;
        }
        if (bytes_read_source != bytes_read_target)
        {
            error = ERROR_ABORTED;
            break;
        }
        for (size_t i = 0; i < bytes_read_source; i++)
        {
            if (buffer_source[i] != buffer_target[i])
            {
                error = ERROR_ABORTED;
                break;
            }
            *diff_position = *diff_position + 1;
        }
    }
    fsCloseFile(source_file);
    fsCloseFile(target_file);
    if (error == ERROR_END_OF_FILE)
    {
        return NO_ERROR;
    }
    return error;
}

error_t fsCopyFile(const char_t *source_path, const char_t *target_path, bool_t overwrite)
{
    // Check if source_path and target_path are not NULL
    if (source_path == NULL || target_path == NULL)
        return ERROR_INVALID_FILE;

    if (!overwrite && fsFileExists(target_path))
        return ERROR_NOT_WRITABLE;

    // Open the source file for reading
    if (!fsFileExists(source_path))
        return ERROR_FILE_NOT_FOUND;
    FsFile *source_file = fsOpenFileEx(source_path, "rb");
    if (source_file == NULL)
        return ERROR_FILE_OPENING_FAILED;

    // Open the target file for writing
    FsFile *target_file = fsOpenFileEx(target_path, "wb");
    if (target_file == NULL)
    {
        fsCloseFile(source_file); // Close the source file
        return ERROR_FILE_OPENING_FAILED;
    }

    // Read from the source file and write to the target file
    uint8_t buffer[FILE_COPY_BUFFER_SIZE];
    size_t bytes_read;

    error_t error = NO_ERROR;
    while (error == NO_ERROR)
    {
        error = fsReadFile(source_file, buffer, sizeof(buffer), &bytes_read);
        if (error == NO_ERROR)
            error = fsWriteFile(target_file, buffer, bytes_read);
    }

    // Close the files
    fsCloseFile(source_file);
    fsCloseFile(target_file);

    if (error == ERROR_END_OF_FILE)
        return NO_ERROR;

    return error;
}
error_t fsMoveFile(const char_t *source_path, const char_t *target_path, bool_t overwrite)
{
    if (!overwrite && fsFileExists(target_path)) {
        return ERROR_NOT_WRITABLE;
    }
    error_t error = fsRenameFile(source_path, target_path);
    if (error == NO_ERROR && !fsFileExists(source_path) && fsFileExists(target_path))
    {
        return error;
    }

    error = fsCopyFile(source_path, target_path, overwrite);
    if (error == NO_ERROR)
    {
        error = fsCompareFiles(source_path, target_path, NULL);
        if (error == NO_ERROR)
        {
            error = fsDeleteFile(source_path);
        }
    }
    return error;
}
error_t fsCreateDirEx(const char_t *path, bool_t recursive)
{
    if (path == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (recursive)
    {
        char_t *path_copy = strdup(path);
        size_t path_len = strlen(path_copy);
        if (path_len == 0)
        {
            free(path_copy);
            return ERROR_INVALID_PARAMETER;
        }
        if (path_copy[path_len - 1] == PATH_SEPARATOR)
        {
            path_copy[path_len - 1] = '\0';
        }
        for (size_t i = 1; i < path_len; i++)
        {
            if (path_copy[i] == PATH_SEPARATOR)
            {
                path_copy[i] = '\0';
                if (!fsDirExists(path_copy))
                {
                    error_t error = fsCreateDir(path_copy);
                    if (error != NO_ERROR)
                    {
                        free(path_copy);
                        return error;
                    }
                }
                path_copy[i] = PATH_SEPARATOR;
            }
        }
        free(path_copy);
    }
    return fsCreateDir(path);
}

error_t fsRemoveFilename(char *dir)
{
    if (dir == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (dir[osStrlen(dir) - 1] == PATH_SEPARATOR)
    {
        return NO_ERROR;
    }
    char *last_slash = strrchr(dir, PATH_SEPARATOR);
    if (last_slash == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }
    *last_slash = '\0';
    return NO_ERROR;
}