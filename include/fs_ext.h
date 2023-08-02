#pragma once

#include <stdbool.h>
#include "fs_port.h"

FsFile *fsOpenFileEx(const char_t *path, char *mode);
error_t fsCopyFile(const char_t *source_path, const char_t *target_path, bool_t overwrite);
