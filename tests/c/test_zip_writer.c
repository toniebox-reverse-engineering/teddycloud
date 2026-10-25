#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tests.h"
#include "zip_writer.h"

static uint32_t rd16(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static uint32_t rd32(const uint8_t *p)
{
    return rd16(p) | (rd16(p + 2) << 16);
}

static void write_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "wb");
    assert(f != NULL);
    assert(fwrite(data, 1, strlen(data), f) == strlen(data));
    fclose(f);
}

void test_zip_write_stored(void)
{
    const char *zip_path = "bin/test_zip_writer.zip";
    const char *files[] = {"bin/test_zip_writer_a.bin", "bin/test_zip_writer_b.bin"};
    /* typographic quotes as in teddycloud#552 */
    const char *names[] = {"01 Intro.ogg", "09 3. Satz: \xE2\x80\x9EAllegro\xE2\x80\x9D.ogg"};
    uint8_t buf[1024];

    write_file(files[0], "123456789");
    write_file(files[1], "");
    assert(zipWriteStored(zip_path, 2, files, names) == NO_ERROR);

    FILE *f = fopen(zip_path, "rb");
    assert(f != NULL);
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    /* first local header: stored, UTF-8 flag, crc32("123456789"), sizes, name, data */
    assert(rd32(buf) == 0x04034b50u);
    assert(rd16(buf + 6) == 0x0800);
    assert(rd16(buf + 8) == 0);
    assert(rd32(buf + 14) == 0xCBF43926u);
    assert(rd32(buf + 18) == 9 && rd32(buf + 22) == 9);
    size_t name0 = strlen(names[0]);
    assert(rd16(buf + 26) == name0);
    assert(memcmp(buf + 30, names[0], name0) == 0);
    assert(memcmp(buf + 30 + name0, "123456789", 9) == 0);

    /* end of central directory: two entries, UTF-8 name preserved byte for byte */
    const uint8_t *eocd = buf + len - 22;
    assert(rd32(eocd) == 0x06054b50u);
    assert(rd16(eocd + 10) == 2);
    size_t name1 = strlen(names[1]);
    int found = 0;
    for (size_t i = 0; i + name1 <= len; i++)
    {
        found |= memcmp(buf + i, names[1], name1) == 0;
    }
    assert(found);
    const uint8_t *central = buf + rd32(eocd + 16);
    assert(rd32(central) == 0x02014b50u);
    assert(rd16(central + 8) == 0x0800);

    /* a missing source file fails and leaves no partial archive */
    const char *missing[] = {"bin/does_not_exist.bin"};
    assert(zipWriteStored(zip_path, 1, missing, names) != NO_ERROR);
    assert(fopen(zip_path, "rb") == NULL);

    remove(files[0]);
    remove(files[1]);
}
