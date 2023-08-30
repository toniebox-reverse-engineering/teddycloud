

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "toniefile.h"
#include "error.h"
#include "path.h"
#include "fs_port.h"
#include "os_port.h"
#include "debug.h"
#include "opus.h"
#include "ogg/ogg.h"
#include "server_helpers.h"
#include "version.h"
#include "proto/toniebox.pb.taf-header.pb-c.h"

struct toniefile_s
{
    const char *fullPath;
    FsFile *file;
    size_t file_pos;

    /* opus */
    OpusEncoder *enc;
    opus_int16 audio_frame[OPUS_CHANNELS * OPUS_FRAME_SIZE];
    int audio_frame_used;

    /* ogg */
    ogg_stream_state os;
    uint64_t ogg_granule_position;
    uint64_t ogg_packet_count;
};

static void comment_add(uint8_t *buffer, size_t *length, const char *str)
{
    uint32_t value = strlen(str);
    osMemcpy(&buffer[*length], &value, sizeof(uint32_t));
    *length += sizeof(uint32_t);
    osStrcpy((char *)&buffer[*length], str);
    *length += strlen(str);
}

void generate_taf_header(uint8_t *buffer, size_t *length, TonieboxAudioFileHeader *tafHeader)
{
    /*
    TonieboxAudioFileHeader tafHeaderS = TONIEBOX_AUDIO_FILE_HEADER__INIT;
    tafHeaderS.n_track_page_nums = 0;
    tafHeaderS.track_page_nums = malloc(sizeof(uint32_t) * 99);
    tafHeaderS.track_page_nums[tafHeaderS.n_track_page_nums++] = 1234;
*/
    size_t dataLength = toniebox_audio_file_header__get_packed_size(tafHeader);
    if (dataLength <= *length)
    {
        toniebox_audio_file_header__pack(tafHeader, buffer);
    }
    toniebox_audio_file_header__free_unpacked(tafHeader, NULL);
}

toniefile_t *toniefile_create(const char *fullPath)
{
    int err;

    toniefile_t *ctx = osAllocMem(sizeof(toniefile_t));
    osMemset(ctx, 0x00, sizeof(toniefile_t));

    ctx->fullPath = fullPath;
    ctx->file = fsOpenFile(fullPath, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);

    if (ctx->file == NULL)
    {
        return NULL;
    }

    ctx->enc = opus_encoder_create(OPUS_SAMPLING_RATE, OPUS_CHANNELS, OPUS_APPLICATION_AUDIO, &err);
    if (err != OPUS_OK)
    {
        TRACE_ERROR("Cannot create opus encoder: %s\n", opus_strerror(err));
        return NULL;
    }

    opus_encoder_ctl(ctx->enc, OPUS_SET_BITRATE(OPUS_BIT_RATE));
    opus_encoder_ctl(ctx->enc, OPUS_SET_VBR(1));
    opus_encoder_ctl(ctx->enc, OPUS_SET_EXPERT_FRAME_DURATION(OPUS_FRAME_SIZE_MS));

    ogg_stream_init(&ctx->os, 0xDEADBEEF);

    unsigned char header_data[] = {
        'O', 'p', 'u', 's', 'H', 'e', 'a', 'd',                         // "OpusHead" string
        1,                                                              // Version
        OPUS_CHANNELS,                                                  // Channel count
        0x38, 0x01,                                                     // Pre-skip
        OPUS_SAMPLING_RATE & 0xFF, OPUS_SAMPLING_RATE >> 8, 0x00, 0x00, // Original sample rate; 0xFFFFFFF implies unknown
        0, 0,                                                           // Output gain
        0                                                               // Channel mapping family
    };

    unsigned char comment_data[0x1B4];

    size_t comment_data_pos = 0;
    osMemset(comment_data, '0', sizeof(comment_data));
    osStrcpy((char *)&comment_data[comment_data_pos], "OpusTags");
    comment_data_pos += 8;

    comment_add(comment_data, &comment_data_pos, "teddyCloud");

    int comments = 2;
    osMemcpy(&comment_data[comment_data_pos], &comments, sizeof(uint32_t));
    comment_data_pos += sizeof(uint32_t);

    char *version_str = custom_asprintf("version=%s", BUILD_FULL_NAME_LONG);
    comment_add(comment_data, &comment_data_pos, version_str);
    osFreeMem(version_str);

    /* add padding*/
    int remain = sizeof(comment_data) - comment_data_pos - 4;
    osMemcpy(&comment_data[comment_data_pos], &remain, sizeof(uint32_t));
    comment_data_pos += sizeof(uint32_t);
    osMemcpy(&comment_data[comment_data_pos], "pad=", 4);

    /* write packets */
    ogg_packet header_packet;
    ogg_packet comment_packet;

    header_packet.packet = header_data;
    header_packet.bytes = sizeof(header_data);
    header_packet.b_o_s = 1;
    header_packet.e_o_s = 0;
    header_packet.granulepos = 0;
    header_packet.packetno = ctx->ogg_packet_count++;

    comment_packet.packet = comment_data;
    comment_packet.bytes = sizeof(comment_data);
    comment_packet.b_o_s = 0;
    comment_packet.e_o_s = 0;
    comment_packet.granulepos = 0;
    comment_packet.packetno = ctx->ogg_packet_count++;

    ogg_stream_packetin(&ctx->os, &header_packet);
    ogg_stream_packetin(&ctx->os, &comment_packet);

    ctx->file_pos = 0;
    ogg_page og;
    // Fetch OGG pages and write them to the output file
    while (ogg_stream_flush(&ctx->os, &og))
    {
        /* write the freshly padded block of frames*/
        if (fsWriteFile(ctx->file, og.header, og.header_len) != NO_ERROR)
        {
            return NULL;
        }
        /* write the freshly padded block of frames*/
        if (fsWriteFile(ctx->file, og.body, og.body_len) != NO_ERROR)
        {
            return NULL;
        }
        ctx->file_pos += og.header_len + og.body_len;
    }

    return ctx;
}

error_t toniefile_close(toniefile_t *ctx)
{
    fsCloseFile(ctx->file);
    opus_encoder_destroy(ctx->enc);
    ogg_stream_clear(&ctx->os);

    osFreeMem(ctx);

    return NO_ERROR;
}

static void samples_copy(opus_int16 *dst, int *dst_used, opus_int16 *src, int *src_used, int samples)
{
    osMemcpy(&dst[*dst_used * OPUS_CHANNELS], &src[*src_used * OPUS_CHANNELS], samples * sizeof(uint16_t) * OPUS_CHANNELS);
    *dst_used += samples;
    *src_used += samples;
}

error_t toniefile_encode(toniefile_t *ctx, int16_t *sample_buffer, size_t samples_available)
{
    int samples_processed = 0;
    uint8_t output_frame[TONIEFILE_FRAME_SIZE];

    // TRACE_INFO("samples_available: %lu\n", samples_available);
    while (samples_processed < samples_available)
    {
        /* get the maximum copyable number of samples */
        size_t samples = OPUS_FRAME_SIZE - ctx->audio_frame_used;
        size_t samples_remaining = samples_available - samples_processed;
        if (samples > samples_remaining)
        {
            samples = samples_remaining;
        }
        // TRACE_INFO("  samples: %lu (%lu/%lu)\n", samples, samples_processed, samples_available);

        samples_copy(ctx->audio_frame, &ctx->audio_frame_used, sample_buffer, &samples_processed, samples);

        /* buffer full? */
        if (ctx->audio_frame_used >= OPUS_FRAME_SIZE)
        {
            int block_remain = TONIEFILE_FRAME_SIZE - (ctx->file_pos % TONIEFILE_FRAME_SIZE);

            if (block_remain < 64)
            {
                TRACE_ERROR("Not enough space in this block\r\n");
                return ERROR_FAILURE;
            }

            /* calc frame size using lacing usage */
            int frame_payload = block_remain - 27;
            if ((frame_payload % 256) == 0)
            {
                /* need to reduce due to lacing causing one byte extra. will fix that 1-byte gap later by patching lacing table */
                frame_payload--;
            }
            int frame_dest = 255 * frame_payload / 256;

            int frame_len = opus_encode(ctx->enc, ctx->audio_frame, OPUS_FRAME_SIZE, output_frame, frame_dest);
            // TRACE_INFO("opus_encode: %d/%d\r\n", frame_len, frame_dest);

            if (frame_len <= 0)
            {
                TRACE_ERROR("Cannot encode: %s\r\n", opus_strerror(frame_len));
                return ERROR_FAILURE;
            }

            /* we did not exactly hit the destination size and are close to block size. pad frame */
            if (block_remain < 0x200 && frame_len != frame_dest)
            {
                int target_length = frame_dest;

                int ret = opus_packet_pad(output_frame, frame_len, target_length);
                // TRACE_INFO("opus_packet_pad: %d -> %d\r\n", frame_len, target_length);
                if (ret < 0)
                {
                    TRACE_ERROR("Cannot pad: %s\r\n", opus_strerror(ret));
                    return ERROR_FAILURE;
                }
                frame_len = target_length;
            }

            ctx->ogg_granule_position += OPUS_FRAME_SIZE;
            /* now fill output page */
            ogg_packet op;
            op.packet = output_frame;
            op.bytes = frame_len;
            op.b_o_s = 0;
            op.e_o_s = 0;
            op.granulepos = ctx->ogg_granule_position;
            op.packetno = ctx->ogg_packet_count;

            ctx->ogg_packet_count++;

            ogg_stream_packetin(&ctx->os, &op);

            /* analyze output page size and patch lacing table if necessary */
            int resulting_size = (ctx->file_pos + 27 + ctx->os.lacing_fill + ctx->os.body_fill) % TONIEFILE_FRAME_SIZE;
            int remaining_size = TONIEFILE_FRAME_SIZE - resulting_size;

            /* yeah, make sure we occupy the rest of the block with a lacing table using more entries than it normally would need */
            if (remaining_size < 64 && remaining_size < ctx->os.lacing_vals[0])
            {
                /* decrease first entry by the number of lacing entries to add */
                ctx->os.lacing_vals[0] -= remaining_size;
                for (int pos = 0; pos < remaining_size; pos++)
                {
                    /* add one entry */
                    ctx->os.lacing_vals[ctx->os.lacing_fill] = 1;
                    ctx->os.lacing_fill++;
                }
            }

            ogg_page og;
            while (ogg_stream_flush(&ctx->os, &og))
            {
                if (fsWriteFile(ctx->file, og.header, og.header_len) != NO_ERROR)
                {
                    return ERROR_FAILURE;
                }
                if (fsWriteFile(ctx->file, og.body, og.body_len) != NO_ERROR)
                {
                    return ERROR_FAILURE;
                }
                size_t prev = ctx->file_pos;
                ctx->file_pos += og.header_len + og.body_len;

                if ((prev / TONIEFILE_FRAME_SIZE) != (ctx->file_pos / TONIEFILE_FRAME_SIZE))
                {
                    if (ctx->file_pos % TONIEFILE_FRAME_SIZE)
                    {
                        TRACE_ERROR("Block alignment mismatch 0x%08lX\r\n", ctx->file_pos)
                        return ERROR_FAILURE;
                    }
                }
            }

            /* fill again */
            ctx->audio_frame_used = 0;
        }
    }

    return NO_ERROR;
}