
#pragma once

#include <stdbool.h>

#include "fs_port.h"
#include "error.h"

error_t esp32_fixup_fatfs(FsFile *file, size_t offset, size_t length, bool modify);
error_t esp32_fixup_image(FsFile *file, size_t offset, size_t length, bool modify);
error_t esp32_fat_extract_folder(FsFile *file, size_t offset, size_t length, const char *path, const char *out_path);
error_t esp32_fixup_partitions(FsFile *file, size_t offset, bool modify);
error_t esp32_get_partition(FsFile *file, size_t offset, const char *label, size_t *part_start, size_t *part_size);
error_t esp32_fixup(const char *path, bool modify);
error_t esp32_fat_extract(const char *firmware, const char *fat_path, const char *out_path);
error_t esp32_fat_inject(const char *firmware, const char *fat_path, const char *in_path);
error_t esp32_inject_cert(const char *rootPath, const char *patchedPath, const char *mac);
error_t esp32_inject_ca(const char *rootPath, const char *patchedPath, const char *mac);
error_t esp32_patch_host(const char *patchedPath, const char *hostname, const char *oldrtnl, const char *oldapi);
error_t esp32_patch_wifi(const char *path, const char *ssid, const char *pass);

uint32_t mem_replace(uint8_t *buffer, size_t buffer_len, const char *pattern, const char *replace);
