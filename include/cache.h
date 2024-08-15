#ifndef _CACHE_H
#define _CACHE_H

#include <stdbool.h>
#include <stdint.h>

typedef struct cache_entry_s cache_entry_t;
struct cache_entry_s
{
    cache_entry_t *next;
    uint32_t hash;
    bool exists;
    const char *original_url;
    const char *cached_url;
    const char *file_path;
};

cache_entry_t *cache_add(const char *url);
bool cache_fetch_entry(cache_entry_t *entry);
cache_entry_t *cache_fetch_by_url(const char *url);
cache_entry_t *cache_fetch_by_uri(const char *uri);
cache_entry_t *cache_fetch_by_cached_url(const char *cached_url);

#endif // _CACHE_H