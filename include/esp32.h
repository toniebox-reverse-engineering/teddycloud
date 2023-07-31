
#pragma once

#include "fs_port.h"
#include "error.h"

error_t esp32_dump_image(FsFile *file, size_t offset, size_t length);
error_t esp32_dump_fatfs(FsFile *file, size_t offset, size_t length);
error_t esp32_fat_extract_folder(FsFile *file, size_t offset, size_t length, const char *path, const char *out_path);
error_t esp32_dump_partitions(FsFile *file, size_t offset);
error_t esp32_get_partition(FsFile *file, size_t offset, const char *label, size_t *part_start, size_t *part_size);
error_t esp32_dump_image(FsFile *file, size_t offset, size_t length);
error_t esp32_dump(const char *path);
error_t esp32_fat_extract(const char *firmware, const char *fat_path, const char *out_path);
error_t esp32_fat_inject(const char *firmware, const char *fat_path, const char *in_path);
