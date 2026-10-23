#pragma once

#include <stddef.h>
#include "error.h"

/**
 * Writes a zip archive that stores the given files uncompressed (Ogg/Opus does not compress).
 * The entry names are taken as UTF-8 and flagged as such (general purpose bit 11), so unzip
 * tools show non-ASCII names correctly regardless of the locale of the server.
 * Limited to the classic zip format: at most 65535 entries and 4 GiB in total.
 *
 * @param zip_path    archive to create
 * @param count       number of entries
 * @param file_paths  files to add
 * @param entry_names names of the entries inside the archive, UTF-8, no directories
 * @return NO_ERROR or ERROR_FAILURE (the partial archive is removed)
 */
error_t zipWriteStored(const char *zip_path, size_t count, const char *const *file_paths, const char *const *entry_names);
