#pragma once

#include <stdbool.h>
#include "fs_port.h"

#ifdef _WIN32
#include <direct.h>
#define PATH_MAX 260
#else
#include <unistd.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 260
#endif
#endif
#define PATH_LEN PATH_MAX

void fsFixPath(char_t *path);
FsFile *fsOpenFileEx(const char_t *path, char *mode);
error_t fsCompareFiles(const char_t *source_path, const char_t *target_path, size_t *diff_position);
error_t fsCopyFile(const char_t *source_path, const char_t *target_path, bool_t overwrite);
error_t fsMoveFile(const char_t *source_path, const char_t *target_path, bool_t overwrite);
error_t fsCreateDirEx(const char_t *path, bool_t recursive);
error_t fsRemoveFilename(char *dir);