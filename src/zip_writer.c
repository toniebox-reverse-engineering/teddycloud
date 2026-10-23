#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zip_writer.h"

#define ZIP_LOCAL_HEADER_SIG 0x04034b50u
#define ZIP_CENTRAL_HEADER_SIG 0x02014b50u
#define ZIP_END_OF_CENTRAL_DIR_SIG 0x06054b50u
#define ZIP_VERSION 20
#define ZIP_FLAG_UTF8 0x0800
#define ZIP_METHOD_STORED 0

typedef struct
{
    uint32_t crc;
    uint32_t size;
    uint32_t offset;
    size_t name_len;
} zip_entry_t;

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len)
{
    crc = ~crc;
    for (size_t i = 0; i < len; i++)
    {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++)
        {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

static void put16(FILE *f, uint16_t v)
{
    uint8_t b[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    fwrite(b, 1, sizeof(b), f);
}

static void put32(FILE *f, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    fwrite(b, 1, sizeof(b), f);
}

static void dos_time(uint16_t *dos_date, uint16_t *dos_time_out)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    int year = (t != NULL) ? t->tm_year + 1900 : 1980;

    if (year < 1980)
    {
        *dos_date = (1 << 5) | 1;
        *dos_time_out = 0;
        return;
    }
    *dos_date = (uint16_t)(((year - 1980) << 9) | ((t->tm_mon + 1) << 5) | t->tm_mday);
    *dos_time_out = (uint16_t)((t->tm_hour << 11) | (t->tm_min << 5) | (t->tm_sec / 2));
}

/* the local header needs crc and size, so read the file once before writing it */
static int measure_file(const char *path, uint32_t *crc, uint32_t *size)
{
    uint8_t buf[8192];
    uint64_t total = 0;
    size_t n;
    FILE *f = fopen(path, "rb");

    if (f == NULL)
    {
        return -1;
    }
    *crc = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        *crc = crc32_update(*crc, buf, n);
        total += n;
    }
    if (ferror(f) || total > 0xFFFFFFFFu)
    {
        fclose(f);
        return -1;
    }
    fclose(f);
    *size = (uint32_t)total;
    return 0;
}

static int copy_file(const char *path, FILE *out)
{
    uint8_t buf[8192];
    size_t n;
    FILE *f = fopen(path, "rb");

    if (f == NULL)
    {
        return -1;
    }
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        if (fwrite(buf, 1, n, out) != n)
        {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

error_t zipWriteStored(const char *zip_path, size_t count, const char *const *file_paths, const char *const *entry_names)
{
    zip_entry_t *entries = NULL;
    uint64_t offset = 0;
    uint64_t central_start;
    uint64_t central_size = 0;
    uint16_t date, time_of_day;
    FILE *out = NULL;
    error_t error = ERROR_FAILURE;

    if (count == 0 || count > 0xFFFF)
    {
        return ERROR_FAILURE;
    }
    entries = calloc(count, sizeof(zip_entry_t));
    out = fopen(zip_path, "wb");
    if (entries == NULL || out == NULL)
    {
        goto done;
    }
    dos_time(&date, &time_of_day);

    for (size_t i = 0; i < count; i++)
    {
        zip_entry_t *e = &entries[i];

        e->name_len = strlen(entry_names[i]);
        if (e->name_len == 0 || e->name_len > 0xFFFF || measure_file(file_paths[i], &e->crc, &e->size) != 0)
        {
            goto done;
        }
        e->offset = (uint32_t)offset;

        put32(out, ZIP_LOCAL_HEADER_SIG);
        put16(out, ZIP_VERSION);
        put16(out, ZIP_FLAG_UTF8);
        put16(out, ZIP_METHOD_STORED);
        put16(out, time_of_day);
        put16(out, date);
        put32(out, e->crc);
        put32(out, e->size);
        put32(out, e->size);
        put16(out, (uint16_t)e->name_len);
        put16(out, 0);
        fwrite(entry_names[i], 1, e->name_len, out);
        if (copy_file(file_paths[i], out) != 0)
        {
            goto done;
        }
        offset += 30 + e->name_len + e->size;
        if (offset > 0xFFFFFFFFu)
        {
            goto done;
        }
    }

    central_start = offset;
    for (size_t i = 0; i < count; i++)
    {
        const zip_entry_t *e = &entries[i];

        put32(out, ZIP_CENTRAL_HEADER_SIG);
        put16(out, ZIP_VERSION);
        put16(out, ZIP_VERSION);
        put16(out, ZIP_FLAG_UTF8);
        put16(out, ZIP_METHOD_STORED);
        put16(out, time_of_day);
        put16(out, date);
        put32(out, e->crc);
        put32(out, e->size);
        put32(out, e->size);
        put16(out, (uint16_t)e->name_len);
        put16(out, 0); /* extra field */
        put16(out, 0); /* comment */
        put16(out, 0); /* disk number */
        put16(out, 0); /* internal attributes */
        put32(out, 0); /* external attributes */
        put32(out, e->offset);
        fwrite(entry_names[i], 1, e->name_len, out);
        central_size += 46 + e->name_len;
    }
    if (central_start + central_size > 0xFFFFFFFFu)
    {
        goto done;
    }

    put32(out, ZIP_END_OF_CENTRAL_DIR_SIG);
    put16(out, 0);
    put16(out, 0);
    put16(out, (uint16_t)count);
    put16(out, (uint16_t)count);
    put32(out, (uint32_t)central_size);
    put32(out, (uint32_t)central_start);
    put16(out, 0);

    if (ferror(out) == 0)
    {
        error = NO_ERROR;
    }

done:
    if (out != NULL && fclose(out) != 0)
    {
        error = ERROR_FAILURE;
    }
    if (error != NO_ERROR)
    {
        remove(zip_path);
    }
    free(entries);
    return error;
}
