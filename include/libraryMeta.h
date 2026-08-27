#pragma once

#include "fs_port.h"
#include "error.h"

/*
 * Minimal, standalone "listened" flag for library files (<file>.<ext>.json sidecar).
 * Deliberately independent of contentJson_t/load_content_json: that format is shaped
 * around a Tonie tag's content assignment (source, live, cache, cloud_ruid, ...), none
 * of which applies to a plain library audio file. Reading only ever looks at the
 * "listened" key; writing preserves any other keys already present in the sidecar
 * (e.g. files created by the "migrate to library" feature, which carry a full
 * contentJson_t blob) instead of overwriting them.
 */

bool_t library_meta_get_listened(const char *content_path);
error_t library_meta_set_listened(const char *content_path, bool_t listened);
