#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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
/* Copies the bytes [offset, end) of the open file src to the current position of dst */
error_t fsCopyFileRange(FILE *src, uint32_t offset, uint32_t end, FILE *dst);
/* Hands what was written to file over to the OS, so a reader with its own handle sees it */
error_t fsFlushFile(FsFile *file);
error_t fsMoveFile(const char_t *source_path, const char_t *target_path, bool_t overwrite);
/* Gives the file at existingPath a second name, newPath (a hard link), which must not exist yet. Fails where the file
   system has none (FAT, exFAT, many network shares), and always on Windows: NTFS has them, but there a file another
   handle has open cannot be moved by any of its names, so a caller that moves it on copies instead. In the platform
   files (src/platform). */
error_t fsLinkFile(const char_t *existingPath, const char_t *newPath);
error_t fsCreateDirEx(const char_t *path, bool_t recursive);
error_t fsRemoveFilename(char *dir);