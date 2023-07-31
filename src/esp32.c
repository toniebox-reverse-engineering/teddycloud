
#define TRACE_LEVEL TRACE_LEVEL_INFO

#ifdef WIN32
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#include "settings.h"
#include "hash/sha256.h"
#include "path.h"
#include "fs_port.h"
#include "fs_ext.h"
#include "path.h"
#include "debug.h"
#include "os_port.h"

#include "ff.h"
#include "diskio.h"

#define ESP_PARTITION_TYPE_APP 0
#define ESP_PARTITION_TYPE_DATA 1

#pragma pack(push, 1)

/*
 ********** ESP32 partition structures **********
 */
struct ESP32_part_entry
{
    uint16_t magic;
    uint8_t partType;
    uint8_t partSubType;
    uint32_t fileOffset;
    uint32_t length;
    uint8_t label[16];
    uint32_t reserved;
};

/*
 ********** ESP32 firmware structures **********
 */
struct ESP32_segment
{
    uint32_t loadAddress;
    uint32_t length;
    // uint8_t data[length];
};

struct ESP32_EFH
{
    uint8_t wp_pin;
    uint8_t spi_drive[3];
    uint16_t chip_id;
    uint8_t min_chip_rev_old;
    uint16_t min_chip_revision;
    uint16_t max_chip_revision;
    uint8_t reserved[4];
    uint8_t has_hash;
};

struct ESP32_header
{
    uint8_t magic;
    uint8_t segments;
    uint8_t flashMode;
    uint8_t flashInfo;
    uint32_t entry;
    struct ESP32_EFH extended;
    // ESP32_segment segment_data[segments];
};

struct ESP32_footer
{
    uint8_t chk;
    uint8_t sha[32];
};

/*
 ********** ESP32 asset wear levelling structures **********
 */
#define WL_CFG_SECTORS_COUNT 1
#define WL_DUMMY_SECTORS_COUNT 1
#define WL_CONFIG_HEADER_SIZE 48
#define WL_STATE_RECORD_SIZE 16
#define WL_STATE_HEADER_SIZE 64
#define WL_STATE_COPY_COUNT 2
#define WL_SECTOR_SIZE 0x1000

struct WL_STATE_T_DATA
{
    uint32_t pos;
    uint32_t max_pos;
    uint32_t move_count;
    uint32_t access_count;
    uint32_t max_count;
    uint32_t block_size;
    uint32_t version;
    uint32_t device_id;
    uint8_t reserved[28];
};

struct WL_CONFIG_T_DATA
{
    uint32_t start_addr;
    uint32_t full_mem_size;
    uint32_t page_size;
    uint32_t sector_size;
    uint32_t updaterate;
    uint32_t wr_size;
    uint32_t version;
    uint32_t temp_buff_size;
};

struct wl_state
{
    struct WL_STATE_T_DATA wl_state;
    size_t fs_offset;
    size_t wl_sectors_size;
    size_t partition_size;
    size_t fat_sectors;
    size_t total_sectors;
    size_t total_records;
    size_t wl_state_size;
    size_t wl_state_sectors_cnt;
    FsFile *file;
};

#pragma pack(pop)

error_t esp32_dump_image(FsFile *file, size_t offset, size_t length);

struct wl_state esp32_wl_state;

size_t esp32_wl_translate(const struct wl_state *state, size_t sector)
{
    sector = (sector + state->wl_state.move_count) % state->fat_sectors;

    if (sector >= state->total_records)
    {
        sector += 1;
    }
    return sector;
}

uint32_t get_fattime()
{
    uint32_t year = 2023;
    uint32_t mon = 7;
    uint32_t day = 31;
    return ((uint32_t)(year - 1980) << 25 | (uint32_t)mon << 21 | (uint32_t)day << 16);
}

DRESULT disk_ioctl(BYTE pdrv, BYTE cmd, void *buff)
{
    return RES_OK;
}

DSTATUS disk_status(BYTE pdrv)
{
    return RES_OK;
}

DSTATUS disk_initialize(BYTE pdrv)
{
    return RES_OK;
}

DRESULT disk_write(BYTE pdrv, const BYTE *buffer, LBA_t sector, UINT count)
{
    struct wl_state *state = (struct wl_state *)&esp32_wl_state;

    while (count)
    {
        size_t trans_sec = esp32_wl_translate(state, sector);

        fsSeekFile(state->file, state->fs_offset + trans_sec * WL_SECTOR_SIZE, FS_SEEK_SET);

        error_t error = fsWriteFile(state->file, (void *)buffer, WL_SECTOR_SIZE);
        if (error != NO_ERROR)
        {
            TRACE_ERROR("Failed to write sector\r\n");
            return RES_ERROR;
        }
        count--;
        sector++;
        buffer += WL_SECTOR_SIZE;
    }
    return RES_OK;
}

DRESULT disk_read(BYTE pdrv, BYTE *buffer, LBA_t sector, UINT count)
{
    struct wl_state *state = (struct wl_state *)&esp32_wl_state;

    while (count)
    {
        size_t trans_sec = esp32_wl_translate(state, sector);

        fsSeekFile(state->file, state->fs_offset + trans_sec * WL_SECTOR_SIZE, FS_SEEK_SET);

        size_t read;
        error_t error = fsReadFile(state->file, buffer, WL_SECTOR_SIZE, &read);
        if (error != NO_ERROR || read != WL_SECTOR_SIZE)
        {
            TRACE_ERROR("Failed to read sector\r\n");
            return RES_ERROR;
        }
        count--;
        sector++;
        buffer += WL_SECTOR_SIZE;
    }
    return RES_OK;
}

error_t esp32_wl_init(struct wl_state *state, FsFile *file, size_t offset, size_t length)
{
    state->fs_offset = offset;
    state->file = file;
    state->partition_size = length;
    state->total_sectors = state->partition_size / WL_SECTOR_SIZE;
    state->wl_state_size = WL_STATE_HEADER_SIZE + WL_STATE_RECORD_SIZE * state->total_sectors;
    state->wl_state_sectors_cnt = (state->wl_state_size + WL_SECTOR_SIZE - 1) / WL_SECTOR_SIZE;
    state->wl_sectors_size = (state->wl_state_sectors_cnt * WL_SECTOR_SIZE * WL_STATE_COPY_COUNT) + WL_SECTOR_SIZE;
    state->fat_sectors = state->total_sectors - 1 - (WL_STATE_COPY_COUNT * state->wl_state_sectors_cnt);

    fsSeekFile(file, offset + state->partition_size - state->wl_sectors_size, FS_SEEK_SET);

    size_t read;
    error_t error = fsReadFile(file, &state->wl_state, sizeof(state->wl_state), &read);

    if (error != NO_ERROR || read != sizeof(state->wl_state))
    {
        TRACE_ERROR("Failed to read wl_state\r\n");
        return ERROR_FAILURE;
    }

    uint8_t state_record_empty[WL_STATE_RECORD_SIZE];
    memset(state_record_empty, 0xFF, WL_STATE_RECORD_SIZE);
    for (int pos = 0; pos < state->wl_state_size; pos++)
    {
        uint8_t state_record[WL_STATE_RECORD_SIZE];
        error = fsReadFile(file, state_record, sizeof(state_record), &read);

        if (read != sizeof(state_record))
        {
            TRACE_ERROR("Failed to read state_record\r\n");
            return ERROR_FAILURE;
        }
        if (!memcmp(state_record_empty, state_record, WL_STATE_RECORD_SIZE))
        {
            break;
        }
        state->total_records++;
    }

    return NO_ERROR;
}

error_t esp32_dump_fatfs(FsFile *file, size_t offset, size_t length)
{
    if (esp32_wl_init(&esp32_wl_state, file, offset, length) != NO_ERROR)
    {
        TRACE_ERROR("Failed to init wear leveling\r\n");
        return ERROR_FAILURE;
    }

    FATFS fs;
    FRESULT ret = f_mount(&fs, "0:", 1);

    if (ret == FR_OK)
    {
        DIR dirInfo;
        FRESULT res = f_opendir(&dirInfo, "\\CERT\\");

        if (res == FR_OK)
        {
            TRACE_INFO("Index of CERT\r\n");
            do
            {
                FILINFO fileInfo;
                if (f_readdir(&dirInfo, &fileInfo) != FR_OK)
                {
                    break;
                }
                if (!fileInfo.fname[0])
                {
                    break;
                }
                TRACE_INFO("  %-12s %-10u %04d-%02d-%02d\r\n", fileInfo.fname, fileInfo.fsize,
                           (fileInfo.fdate >> 25) + 1980,
                           (fileInfo.fdate >> 21) & 15,
                           (fileInfo.fdate >> 16) & 31);
            } while (1);

            f_closedir(&dirInfo);
        }

        f_unmount("0:");
    }

    return NO_ERROR;
}

error_t esp32_fat_extract_folder(FsFile *file, size_t offset, size_t length, const char *path, const char *out_path)
{
    if (esp32_wl_init(&esp32_wl_state, file, offset, length) != NO_ERROR)
    {
        TRACE_ERROR("Failed to init wear leveling\r\n");
        return ERROR_FAILURE;
    }

    FATFS fs;
    FRESULT ret = f_mount(&fs, "0:", 1);

    if (ret != FR_OK)
    {
        TRACE_ERROR("Failed to mount image\r\n");
        return ERROR_FAILURE;
    }
    DIR dirInfo;
    FRESULT res = f_opendir(&dirInfo, path);

    if (res == FR_OK)
    {
        do
        {
            FILINFO fileInfo;
            if (f_readdir(&dirInfo, &fileInfo) != FR_OK)
            {
                break;
            }
            if (!fileInfo.fname[0])
            {
                break;
            }
            char fatFileName[FS_MAX_PATH_LEN];
            osStrcpy(fatFileName, path);
            osStrcat(fatFileName, "\\");
            osStrcat(fatFileName, fileInfo.fname);

            char outFileName[FS_MAX_PATH_LEN];
            osStrcpy(outFileName, out_path);

            pathAddSlash(outFileName, FS_MAX_PATH_LEN);
            pathCombine(outFileName, fileInfo.fname, FS_MAX_PATH_LEN);
            pathCanonicalize(outFileName);

            TRACE_INFO("Write to '%s '%s'\r\n", fatFileName, outFileName);

            FsFile *outFile = fsOpenFile(outFileName, FS_FILE_MODE_WRITE);
            if (!outFile)
            {
                TRACE_ERROR("Failed to open output file\r\n");
                return ERROR_FAILURE;
            }

            FIL fp;
            if (f_open(&fp, fatFileName, FA_READ) != FR_OK)
            {
                TRACE_ERROR("Failed to open FAT file\r\n");
                return ERROR_FAILURE;
            }
            uint8_t buffer[512];
            for (int pos = 0; pos < fileInfo.fsize; pos += sizeof(buffer))
            {
                uint32_t read;
                if (f_read(&fp, buffer, sizeof(buffer), &read) != FR_OK)
                {
                    TRACE_ERROR("Failed to read from FAT file\r\n");
                    return ERROR_FAILURE;
                }

                if (fsWriteFile(outFile, buffer, read) != NO_ERROR)
                {
                    TRACE_ERROR("Failed to write output file\r\n");
                    return ERROR_FAILURE;
                }
            }
            f_close(&fp);
            fsCloseFile(outFile);
        } while (1);

        f_closedir(&dirInfo);
    }

    f_unmount("0:");

    return NO_ERROR;
}

error_t esp32_fat_inject_folder(FsFile *file, size_t offset, size_t length, const char *path, const char *in_path)
{
    if (esp32_wl_init(&esp32_wl_state, file, offset, length) != NO_ERROR)
    {
        TRACE_ERROR("Failed to init wear leveling\r\n");
        return ERROR_FAILURE;
    }

    FATFS fs;
    FRESULT ret = f_mount(&fs, "0:", 1);

    if (ret != FR_OK)
    {
        TRACE_ERROR("Failed to mount image\r\n");
        return ERROR_FAILURE;
    }

    FsDir *dir = fsOpenDir(in_path);
    if (!dir)
    {
        TRACE_ERROR("Failed to open source directory\r\n");
        return ERROR_FAILURE;
    }

    do
    {
        FsDirEntry dirEntry;

        if (fsReadDir(dir, &dirEntry) != NO_ERROR)
        {
            break;
        }

        if (dirEntry.attributes & FS_FILE_ATTR_DIRECTORY)
        {
            continue;
        }

        char fatFileName[FS_MAX_PATH_LEN];
        osStrcpy(fatFileName, path);
        osStrcat(fatFileName, "\\");
        osStrcat(fatFileName, dirEntry.name);

        char inFileName[FS_MAX_PATH_LEN];
        osStrcpy(inFileName, in_path);

        pathAddSlash(inFileName, FS_MAX_PATH_LEN);
        pathCombine(inFileName, dirEntry.name, FS_MAX_PATH_LEN);
        pathCanonicalize(inFileName);

        TRACE_INFO("Write '%s to '%s'\r\n", inFileName, fatFileName);

        FsFile *inFile = fsOpenFileEx(inFileName, "ab+");
        if (!inFile)
        {
            TRACE_ERROR("Failed to open output file\r\n");
            return ERROR_FAILURE;
        }

        FIL fp;
        if (f_open(&fp, fatFileName, FA_WRITE | FA_CREATE_ALWAYS) != FR_OK)
        {
            TRACE_ERROR("Failed to open FAT file\r\n");
            return ERROR_FAILURE;
        }

        uint8_t buffer[512];
        for (int pos = 0; pos < dirEntry.size; pos += sizeof(buffer))
        {
            size_t read;
            if (fsReadFile(inFile, buffer, sizeof(buffer), &read) != NO_ERROR)
            {
                TRACE_ERROR("Failed to read from input file\r\n");
                return ERROR_FAILURE;
            }

            uint32_t written;
            if (f_write(&fp, buffer, read, &written) != FR_OK)
            {
                TRACE_ERROR("Failed to write to FAT file\r\n");
                return ERROR_FAILURE;
            }
        }
        f_close(&fp);
        fsCloseFile(inFile);

    } while (1);

    fsCloseDir(dir);

    f_unmount("0:");

    return NO_ERROR;
}

error_t esp32_dump_partitions(FsFile *file, size_t offset)
{
    size_t offset_current = offset;
    struct ESP32_part_entry entry;
    int num = 0;
    error_t error;

    while (true)
    {
        fsSeekFile(file, offset_current, FS_SEEK_SET);

        size_t read;
        error = fsReadFile(file, &entry, sizeof(entry), &read);

        if (read != sizeof(entry))
        {
            TRACE_ERROR("Failed to read entry\r\n");
            return ERROR_FAILURE;
        }

        if (entry.magic == 0x50AA)
        {
            TRACE_INFO("#%d  Type: %d, SubType: %02X, Offset: 0x%06X, Length: 0x%06X, Label: '%s'\r\n", num, entry.partType, entry.partSubType, entry.fileOffset, entry.length, entry.label);

            if (entry.partType == ESP_PARTITION_TYPE_APP)
            {
                esp32_dump_image(file, entry.fileOffset, entry.length);
            }
            if (entry.partType == ESP_PARTITION_TYPE_DATA && entry.partSubType == 0x81)
            {
                esp32_dump_fatfs(file, entry.fileOffset, entry.length);
            }
        }
        else
        {
            break;
        }

        offset_current += sizeof(entry);
        num++;
    }

    return error;
}

error_t esp32_get_partition(FsFile *file, size_t offset, const char *label, size_t *part_start, size_t *part_size)
{
    size_t offset_current = offset;
    struct ESP32_part_entry entry;
    int num = 0;
    error_t error;
    TRACE_INFO("Search for partition '%s'\r\n", label);

    while (true)
    {
        fsSeekFile(file, offset_current, FS_SEEK_SET);

        size_t read;
        error = fsReadFile(file, &entry, sizeof(entry), &read);

        if (error != NO_ERROR || read != sizeof(entry))
        {
            TRACE_ERROR("Failed to read entry\r\n");
            return ERROR_FAILURE;
        }

        if (entry.magic == 0x50AA)
        {
            if (!osStrcmp((const char *)entry.label, label))
            {
                TRACE_INFO("Found partition '%s' at 0x%06" PRIx32 "\r\n", label, entry.fileOffset);
                *part_start = entry.fileOffset;
                *part_size = entry.length;
                return NO_ERROR;
            }
        }
        else
        {
            break;
        }

        offset_current += sizeof(entry);
        num++;
    }

    TRACE_ERROR("Partition '%s' not found\r\n", label);
    return ERROR_FAILURE;
}

void esp32_chk_update(uint8_t *chk, void *buffer, size_t length)
{
    for (size_t pos = 0; pos < length; pos++)
    {
        *chk ^= ((uint8_t *)buffer)[pos];
    }
}

error_t esp32_dump_image(FsFile *file, size_t offset, size_t length)
{
    size_t offset_current = offset;
    struct ESP32_header header;

    fsSeekFile(file, offset_current, FS_SEEK_SET);

    uint8_t chk_calc = 0xEF;
    Sha256Context ctx;
    sha256Init(&ctx);

    size_t read;
    error_t error = fsReadFile(file, &header, sizeof(header), &read);

    if (read != sizeof(header))
    {
        TRACE_ERROR("Failed to read header\r\n");
        return ERROR_FAILURE;
    }

    sha256Update(&ctx, &header, sizeof(header));
    offset_current += sizeof(header);

    if (header.magic != 0xE9)
    {
        TRACE_INFO("No image found\r\n");
        return ERROR_FAILURE;
    }

    for (int seg = 0; seg < header.segments; seg++)
    {
        struct ESP32_segment segment;

        fsSeekFile(file, offset_current, FS_SEEK_SET);
        error = fsReadFile(file, &segment, sizeof(segment), &read);

        if (read != sizeof(segment))
        {
            TRACE_ERROR("Failed to read segment\r\n");
            return ERROR_FAILURE;
        }
        TRACE_INFO("#%d Address: 0x%08X, Len: 0x%06X, Offset: 0x%06X\r\n", seg, segment.loadAddress, segment.length, (uint32_t)offset_current);

        sha256Update(&ctx, &segment, sizeof(segment));
        offset_current += sizeof(segment);

        for (size_t pos = 0; pos < segment.length;)
        {
            uint8_t buffer[512];
            size_t maxLen = sizeof(buffer);

            if (maxLen > segment.length - pos)
            {
                maxLen = segment.length - pos;
            }

            fsSeekFile(file, offset_current, FS_SEEK_SET);
            error = fsReadFile(file, buffer, maxLen, &read);
            if (read != maxLen)
            {
                TRACE_ERROR("Failed to read data\r\n");
                return ERROR_FAILURE;
            }
            sha256Update(&ctx, buffer, maxLen);
            esp32_chk_update(&chk_calc, buffer, maxLen);
            offset_current += maxLen;
            pos += maxLen;
        }
    }
    TRACE_INFO(" Offset: 0x%06X\r\n", (uint32_t)offset_current);

    while ((offset_current & 0x0F) != 0x0F)
    {
        uint8_t null = 0;
        sha256Update(&ctx, &null, sizeof(null));
        offset_current++;
    }
    fsSeekFile(file, offset_current, FS_SEEK_SET);

    uint8_t chk;
    error = fsReadFile(file, &chk, sizeof(chk), &read);

    if (read != sizeof(chk))
    {
        TRACE_ERROR("Failed to read chk\r\n");
        return ERROR_FAILURE;
    }
    TRACE_INFO("CHK: 0x%02X\r\n", chk);
    TRACE_INFO("CHK: 0x%02X (calculated)\r\n", chk_calc);

    sha256Update(&ctx, &chk_calc, sizeof(chk_calc));

    uint8_t sha256_calc[32];
    sha256Final(&ctx, sha256_calc);
    if (header.extended.has_hash)
    {
        uint8_t sha256[32];
        error = fsReadFile(file, &sha256, sizeof(sha256), &read);

        if (read != sizeof(sha256))
        {
            TRACE_ERROR("Failed to read sha256\r\n");
            return ERROR_FAILURE;
        }
        char buf[sizeof(sha256) * 2 + 1];
        for (int pos = 0; pos < sizeof(sha256); pos++)
        {
            osSprintf(&buf[pos * 2], "%02X", sha256[pos]);
        }
        TRACE_INFO("SHA1: %s\r\n", buf);

        for (int pos = 0; pos < sizeof(sha256_calc); pos++)
        {
            osSprintf(&buf[pos * 2], "%02X", sha256_calc[pos]);
        }
        TRACE_INFO("SHA1: %s (calculated)\r\n", buf);
    }
    return error;
}

error_t esp32_dump(const char *path)
{
    uint32_t length;
    error_t error = fsGetFileSize(path, &length);

    if (error || length < 0x9000)
    {
        TRACE_ERROR("File does not exist or is too small '%s'\r\n", path);
        return ERROR_NOT_FOUND;
    }

    FsFile *file = fsOpenFile(path, FS_FILE_MODE_READ);

    esp32_dump_image(file, 0, length);
    esp32_dump_partitions(file, 0x9000);

    return NO_ERROR;
}

error_t esp32_fat_extract(const char *firmware, const char *fat_path, const char *out_path)
{
    uint32_t length;
    error_t error = fsGetFileSize(firmware, &length);

    if (error || length < 0x9000)
    {
        TRACE_ERROR("File does not exist or is too small '%s'\r\n", firmware);
        return ERROR_NOT_FOUND;
    }

    FsFile *file = fsOpenFile(firmware, FS_FILE_MODE_READ);

    size_t part_offset;
    size_t part_size;
    error = esp32_get_partition(file, 0x9000, "assets", &part_offset, &part_size);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Asset partition not found\r\n");
        return ERROR_NOT_FOUND;
    }

    esp32_fat_extract_folder(file, part_offset, part_size, "CERT", out_path);

    return NO_ERROR;
}

error_t esp32_fat_inject(const char *firmware, const char *fat_path, const char *in_path)
{
    uint32_t length;
    error_t error = fsGetFileSize(firmware, &length);

    if (error || length < 0x9000)
    {
        TRACE_ERROR("File does not exist or is too small '%s'\r\n", firmware);
        return ERROR_NOT_FOUND;
    }

    FsFile *file = fsOpenFileEx(firmware, "ab+");

    size_t part_offset;
    size_t part_size;
    error = esp32_get_partition(file, 0x9000, "assets", &part_offset, &part_size);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Asset partition not found\r\n");
        return ERROR_NOT_FOUND;
    }

    esp32_fat_inject_folder(file, part_offset, part_size, "CERT", in_path);

    return NO_ERROR;
}