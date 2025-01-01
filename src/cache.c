

#include "cache.h"
#include "web.h"
#include "fs_port.h"
#include "os_port.h"
#include "server_helpers.h"
#include "hash/sha256.h" // for sha256Update, sha256Final, sha256Init

cache_entry_t cache_table = {.next = NULL, .hash = 0, .original_url = NULL, .cached_url = NULL, .file_path = NULL};
uint32_t cache_entries = 0;

uint32_t cache_flush()
{
    uint32_t deleted = 0;
    cache_entry_t *pos = &cache_table;

    while (pos != NULL)
    {
        if (pos->exists)
        {
            // Attempt to delete the local file
            if (pos->file_path && fsDeleteFile(pos->file_path) == NO_ERROR)
            {
                deleted++;
                TRACE_INFO("Deleted cached file: %s\n", pos->file_path);
            }
            else
            {
                TRACE_WARNING("Failed to delete cached file: %s\n", pos->file_path ? pos->file_path : "Unknown path");
            }

            // Set the exists flag to false
            pos->exists = false;
        }

        pos = pos->next;
    }

    return deleted;
}

/**
 * @brief Gathers statistics about the current cache.
 *
 * @param stats Pointer to a structure where the statistics will be stored.
 */
void cache_stats(cache_stats_t *stats)
{
    if (stats == NULL)
    {
        return;
    }

    cache_entry_t *pos = &cache_table;
    memset(stats, 0, sizeof(cache_stats_t)); // Initialize all stats to zero

    while (pos != NULL)
    {
        stats->total_entries++;
        stats->memory_used += sizeof(*pos); // Add size of the cache entry structure

        if (pos->original_url)
        {
            stats->memory_used += strlen(pos->original_url) + 1; // Add length of original_url string
        }
        if (pos->cached_url)
        {
            stats->memory_used += strlen(pos->cached_url) + 1; // Add length of cached_url string
        }
        if (pos->file_path)
        {
            stats->memory_used += strlen(pos->file_path) + 1; // Add length of file_path string
        }
        if (pos->exists)
        {
            stats->exists_entries++;
        }
        if (fsFileExists(pos->file_path))
        {
            stats->total_files++;
            uint32_t size = 0;
            fsGetFileSize(pos->file_path, &size);
            stats->total_size += size;
        }
        pos = pos->next;
    }
}

void cache_entry_add(cache_entry_t *entry)
{
    if (!entry)
    {
        TRACE_ERROR("entry is NULL\r\n");
        return;
    }

    cache_entry_t *pos = &cache_table;

    if (!pos)
    {
        TRACE_ERROR("cache_table is NULL\r\n");
        return;
    }

    TRACE_DEBUG("Starting to add cache entry with the following details:\r\n");
    TRACE_DEBUG("  Hash: %08X\r\n", entry->hash);
    TRACE_DEBUG("  Original URL: %s\r\n", entry->original_url ? entry->original_url : "NULL");
    TRACE_DEBUG("  Cached URL: %s\r\n", entry->cached_url ? entry->cached_url : "NULL");
    TRACE_DEBUG("  File Path: %s\r\n", entry->file_path ? entry->file_path : "NULL");

    while (pos)
    {
        cache_entry_t *next = pos->next;

        if (!next)
        {
            TRACE_DEBUG("End of list reached, adding entry with hash: %08X at the end\r\n", entry->hash);
            pos->next = entry;
            entry->next = NULL;
            return;
        }

        if (entry->hash < next->hash)
        {
            TRACE_DEBUG("Inserting entry with hash: %08X before entry with hash: %08X\r\n", entry->hash, next->hash);
            pos->next = entry;
            entry->next = next;
            return;
        }

        if (entry->hash == next->hash)
        {
            if (!osStrcmp(entry->original_url, next->original_url))
            {
                TRACE_DEBUG("Already added: %08X\r\n", entry->hash);
                return;
            }
            TRACE_DEBUG("Inserting (duplicate short hash) entry with hash: %08X before entry with hash: %08X\r\n", entry->hash, next->hash);
            pos->next = entry;
            entry->next = next;
            return;
        }

        pos = next;
    }

    TRACE_DEBUG("Finished adding cache entry with hash: %08X\r\n", entry->hash);
}

cache_entry_t *cache_add(const char *url)
{
    const char *cachePath = get_settings()->internal.cachedirfull;

    if (cachePath == NULL || !fsDirExists(cachePath))
    {
        TRACE_ERROR("core.cachedirfull not set to a valid path: '%s'", cachePath);
        return NULL;
    }

    uint8_t sha256_calc[SHA256_DIGEST_SIZE];
    char sha256_calc_str[2 * SHA256_DIGEST_SIZE + 1];

    /* hash the image URL */
    Sha256Context ctx;
    sha256Init(&ctx);
    sha256Update(&ctx, url, strlen(url));
    sha256Final(&ctx, sha256_calc);

    for (int pos = 0; pos < SHA256_DIGEST_SIZE; pos++)
    {
        osSprintf(&sha256_calc_str[2 * pos], "%02X", sha256_calc[pos]);
    }

    /* Find the file extension from the URL */
    const char *ext_pos = strrchr(url, '.');
    char *extension = strdup("jpg");

    if (ext_pos && !osStrchr(ext_pos, '/'))
    {
        osFreeMem(extension);
        extension = strdup(&ext_pos[1]);

        /* Remove optional HTTP GET parameters */
        char *query_param = osStrchr(extension, '?');
        if (query_param)
        {
            *query_param = '\0';
        }
    }

    cache_entry_t *entry = osAllocMem(sizeof(cache_entry_t));

    entry->hash = (sha256_calc[0] << 24) | (sha256_calc[1] << 16) | (sha256_calc[2] << 8) | (sha256_calc[3] << 0);
    entry->original_url = strdup(url);
    entry->file_path = custom_asprintf("%s%c%s.%s", cachePath, PATH_SEPARATOR, sha256_calc_str, extension);
    entry->cached_url = custom_asprintf("/cache/%s.%s", sha256_calc_str, extension);
    entry->exists = fsFileExists(entry->file_path);

    cache_entry_add(entry);

    osFreeMem(extension);

    return entry;
}

bool cache_fetch_entry(cache_entry_t *entry)
{
    if (entry->exists && fsFileExists(entry->file_path))
    {
        return true;
    }

    error_t err = web_download(entry->original_url, entry->file_path, &entry->statusCode);
    entry->exists = (err == NO_ERROR);

    return entry->exists;
}

cache_entry_t *cache_fetch_by_url(const char *url)
{
    if (url == NULL)
    {
        TRACE_ERROR("URL is NULL\r\n");
        return NULL;
    }

    cache_entry_t *pos = &cache_table;

    while (pos != NULL)
    {
        if (pos->original_url && osStrcmp(pos->original_url, url) == 0)
        {
            TRACE_DEBUG("Cache entry found for URL: %s\r\n", url);
            cache_fetch_entry(pos);
            return pos;
        }

        pos = pos->next;
    }

    TRACE_DEBUG("No cache entry found for URL: %s\r\n", url);
    return NULL;
}

cache_entry_t *cache_fetch_by_cached_url(const char *cached_url)
{
    if (cached_url == NULL)
    {
        TRACE_ERROR("cached_url is NULL\r\n");
        return NULL;
    }

    /* Find the position of "/cache/" in the URL */
    const char *cache_pos = osStrstr(cached_url, "/cache/");
    if (!cache_pos)
    {
        TRACE_ERROR("'/cache/' not found in cached URL: %s\r\n", cached_url);
        return NULL;
    }

    cache_pos += osStrlen("/cache/");

    if (osStrlen(cache_pos) < 8)
    {
        TRACE_ERROR("Cached URL hash is too short in URL: %s\r\n", cached_url);
        return NULL;
    }

    /* Extract the first 8 characters of the hash from the URL */
    char hash_str[9] = {0};
    osStrncpy(hash_str, cache_pos, 8);

    /* Convert the extracted hash part to a uint32_t */
    uint32_t hash_from_url = (uint32_t)osStrtoul(hash_str, NULL, 16);

    cache_entry_t *pos = &cache_table;

    while (pos != NULL)
    {
        if (pos->hash == hash_from_url)
        {
            TRACE_INFO("Hash match found for hash: %08X. Checking full cached URL...\r\n", hash_from_url);

            /* Compare the full cached URL */
            if (strcmp(pos->cached_url, cached_url) == 0)
            {
                TRACE_INFO("Full cached URL match found for URL: %s\r\n", cached_url);
                cache_fetch_entry(pos);
                return pos;
            }
        }

        pos = pos->next;
    }

    TRACE_INFO("No cache entry found for hash: %08X in cached URL: %s\r\n", hash_from_url, cached_url);
    return NULL;
}

cache_entry_t *cache_fetch_by_path(const char *path)
{
    if (path == NULL)
    {
        TRACE_ERROR("URI is NULL\r\n");
        return NULL;
    }

    // Find the position of "/cache/" in the URI
    const char *cache_pos = strstr(path, "/cache/");
    if (!cache_pos)
    {
        TRACE_ERROR("'/cache/' not found in URI: %s\r\n", path);
        return NULL;
    }

    // Move the pointer to the start of the hash part
    cache_pos += osStrlen("/cache/");

    // Ensure that the hash part exists and has enough characters
    if (osStrlen(cache_pos) < 8) // 4 bytes of hash = 8 hex characters
    {
        TRACE_ERROR("URI hash is too short in URI: %s\r\n", path);
        return NULL;
    }

    // Extract the first 8 characters of the hash from the URI
    char hash_str[9] = {0}; // 8 characters + 1 for null terminator
    osStrncpy(hash_str, cache_pos, 8);

    // Convert the extracted hash part to a uint32_t
    uint32_t hash_from_uri = (uint32_t)osStrtoul(hash_str, NULL, 16);

    cache_entry_t *pos = &cache_table;

    while (pos != NULL)
    {
        if (pos->hash == hash_from_uri)
        {
            TRACE_DEBUG("Hash match found for hash: %08X. Checking full URI...\r\n", hash_from_uri);

            // Compare the path "/cache/[hash].[ext]" in the URI
            if (osStrstr(pos->cached_url, cache_pos) != NULL)
            {
                TRACE_DEBUG("Full URI match found for URI: %s\r\n", path);
                cache_fetch_entry(pos);
                return pos;
            }
        }

        pos = pos->next;
    }

    TRACE_ERROR("No cache entry found for URI: %s\r\n", path);
    return NULL;
}