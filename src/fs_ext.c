
#include "fs_ext.h"

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

    // Return a handle to the file
    return fp;
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
