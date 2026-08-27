
#pragma once
#include <stdint.h>
#include "fs_ext.h"
#include "hash/sha1.h"

#define OPUS_FRAME_SIZE_MS OPUS_FRAMESIZE_60_MS
#define OPUS_SAMPLING_RATE 48000
// #define OPUS_BIT_RATE 96000
#define OPUS_FRAME_SIZE OPUS_SAMPLING_RATE * 60 / 1000 /* samples: 60ms at 48kHz */
#define OPUS_CHANNELS 2
#define OPUS_PACKET_PAD 64
#define OPUS_PACKET_MINSIZE 64

#define TONIEFILE_FRAME_SIZE 4096
#define TONIEFILE_MAX_CHAPTERS 100
#define TONIEFILE_MAX_SOURCES (TONIEFILE_MAX_CHAPTERS - 1)
#define TONIEFILE_PAD_END 64

#define OGG_HEADER_LENGTH 27
/* max lacing values per ogg page (255), minus a safety margin for the packet
   that finally fills the block */
#define OGG_SEGMENTS_RESERVE 8
/*
    quint32 Signature;
    quint8 Version;
    quint8 Flags;
    quint64 GranulePosition;
    quint32 SerialNumber;
    quint32 SequenceNumber;
    quint32 Checksum;
    quint8 TotalSegments;
*/

#define TEDDY_BENCH_AUDIO_ID_DEDUCT 0x50000000
#define SPECIAL_AUDIO_ID_ONE 1

typedef struct toniefile_s toniefile_t;

typedef struct
{
    uint32_t payload_size;
    uint8_t sha1_hash[SHA1_DIGEST_SIZE];
    bool_t has_sha1_hash;
    uint32_t track_page_nums[TONIEFILE_MAX_CHAPTERS];
    size_t track_page_nums_count;
    bool_t has_ogg_state;
    uint64_t ogg_granule_position;
    uint64_t ogg_packet_count;
    uint64_t taf_block_num;
    uint64_t pageno;
} toniefile_live_header_t;

typedef struct
{
    bool_t active;
    size_t current_source;
    error_t error;
    OsTaskId taskId;
    bool_t quit;
    bool_t stop_on_playback_stop;
    uint32_t generation;
    OsTaskParameters taskParams;
    void *ctx;
} stream_ctx_t;

typedef struct
{
    char *source;
    size_t skip_seconds;
    char *targetFile;
    bool_t append;
    bool_t sweep;
} ffmpeg_stream_ctx_t;

toniefile_t *toniefile_create(const char *fullPath, uint32_t audio_id, bool append, int32_t size);
error_t toniefile_close(toniefile_t *ctx);
error_t toniefile_encode(toniefile_t *ctx, int16_t *sample_buffer, size_t samples_available);
error_t toniefile_write_header(toniefile_t *ctx);
error_t toniefile_write_taf_header(FsFile *file, uint32_t audio_id, const toniefile_live_header_t *live_header);
error_t toniefile_new_chapter(toniefile_t *ctx);

bool toniefile_is_valid(const char *file_path);

FILE *ffmpeg_decode_audio_start(const char *input_source);
FILE *ffmpeg_decode_audio_start_skip(const char *input_source, size_t skip_seconds, size_t skip_bytes);
error_t ffmpeg_decode_audio_end(FILE *ffmpeg_pipe, error_t error);
error_t ffmpeg_decode_audio(FILE *ffmpeg_pipe, int16_t *buffer, size_t size, size_t *blocks_read);
error_t ffmpeg_stream_with_audio_id(char source[TONIEFILE_MAX_SOURCES][PATH_LEN], size_t source_len, size_t *current_source, const char *target_taf, size_t skip_seconds, bool_t *active, bool_t *sweep, bool_t append, bool_t isStream, uint32_t audio_id);
error_t ffmpeg_stream(char source[TONIEFILE_MAX_SOURCES][PATH_LEN], size_t source_len, size_t *current_source, const char *target_taf, size_t skip_seconds, bool_t *active, bool_t *sweep, bool_t append, bool_t isStream);
error_t ffmpeg_convert(char source[TONIEFILE_MAX_SOURCES][PATH_LEN], size_t source_len, size_t *current_source, const char *target_taf, size_t skip_seconds);
void ffmpeg_stream_task(void *param);
