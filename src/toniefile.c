

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "toniefile.h"
#include "hash/sha1.h"
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
    size_t audio_length;

    /* opus */
    OpusEncoder *enc;
    opus_int16 audio_frame[OPUS_CHANNELS * OPUS_FRAME_SIZE];
    int audio_frame_used;

    /* ogg */
    ogg_stream_state os;
    uint64_t ogg_granule_position;
    uint64_t ogg_packet_count;

    /* TAF */
    TonieboxAudioFileHeader taf;
    Sha1Context sha1;
    size_t taf_block_num;
};

static void toniefile_comment_add(uint8_t *buffer, size_t *length, const char *str)
{
    uint32_t value = strlen(str);
    osMemcpy(&buffer[*length], &value, sizeof(uint32_t));
    *length += sizeof(uint32_t);
    osStrcpy((char *)&buffer[*length], str);
    *length += strlen(str);
}

static size_t toniefile_header(uint8_t *buffer, size_t length, TonieboxAudioFileHeader *tafHeader)
{
    uint16_t proto_frame_size = TONIEFILE_FRAME_SIZE - 4; // Offset 4, dynamic size of protobuf
    tafHeader->_fill.len = proto_frame_size;
    tafHeader->_fill.data = osAllocMem(tafHeader->_fill.len);
    osMemset(tafHeader->_fill.data, 0x00, tafHeader->_fill.len);

    size_t dataLength = toniebox_audio_file_header__get_packed_size(tafHeader);
    tafHeader->_fill.len = tafHeader->_fill.len + (proto_frame_size - dataLength); // Cut size to TONIEFILE_FRAME_SIZE

    dataLength = toniebox_audio_file_header__get_packed_size(tafHeader);
    if (dataLength == proto_frame_size + 1)
    {
        tafHeader->_fill.len--;
    }
    if (dataLength != proto_frame_size && dataLength != proto_frame_size - 1)
    {
        TRACE_ERROR("TAF header size %" PRIuSIZE " not equal to frame size %" PRIu16 "\r\n", dataLength, proto_frame_size);
        return 0;
    }
    if (dataLength > length)
    {
        TRACE_ERROR("TAF header size %" PRIuSIZE " bigger than buffer %" PRIu16 "\r\n", dataLength, proto_frame_size);
        return 0;
    }
    return toniebox_audio_file_header__pack(tafHeader, buffer);
}

toniefile_t *toniefile_create(const char *fullPath, uint32_t audio_id)
{
    int err;

    toniefile_t *ctx = osAllocMem(sizeof(toniefile_t));
    osMemset(ctx, 0x00, sizeof(toniefile_t));

    /* init TAF header */
    toniebox_audio_file_header__init(&ctx->taf);
    ctx->taf.audio_id = audio_id;
    ctx->taf.n_track_page_nums = 0;
    ctx->taf.track_page_nums = osAllocMem(sizeof(uint32_t) * TONIEFILE_MAX_CHAPTERS);
    sha1Init(&ctx->sha1);

    /* open file */
    ctx->fullPath = fullPath;
    ctx->file = fsOpenFile(fullPath, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);

    if (ctx->file == NULL)
    {
        return NULL;
    }
    fsSeekFile(ctx->file, TONIEFILE_FRAME_SIZE, SEEK_SET);

    /* init OPUS */
    ctx->enc = opus_encoder_create(OPUS_SAMPLING_RATE, OPUS_CHANNELS, OPUS_APPLICATION_AUDIO, &err);
    if (err != OPUS_OK)
    {
        TRACE_ERROR("Cannot create opus encoder: %s\n", opus_strerror(err));
        return NULL;
    }

    opus_encoder_ctl(ctx->enc, OPUS_SET_BITRATE(OPUS_BIT_RATE));
    opus_encoder_ctl(ctx->enc, OPUS_SET_VBR(1));
    opus_encoder_ctl(ctx->enc, OPUS_SET_EXPERT_FRAME_DURATION(OPUS_FRAME_SIZE_MS));

    /* init OGG */
    ogg_stream_init(&ctx->os, audio_id);

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

    bool_t customTags = true;
    if (customTags)
    {
        toniefile_comment_add(comment_data, &comment_data_pos, "teddyCloud");

        int comments = 2;
        osMemcpy(&comment_data[comment_data_pos], &comments, sizeof(uint32_t));
        comment_data_pos += sizeof(uint32_t);

        char *version_str = custom_asprintf("version=%s", BUILD_FULL_NAME_LONG);
        toniefile_comment_add(comment_data, &comment_data_pos, version_str);
        osFreeMem(version_str);
    }
    else
    {
        int comments = 3;
        toniefile_comment_add(comment_data, &comment_data_pos, "libopus 1.2.1");
        osMemcpy(&comment_data[comment_data_pos], &comments, sizeof(uint32_t));
        comment_data_pos += sizeof(uint32_t);
        toniefile_comment_add(comment_data, &comment_data_pos, "encoder=opusenc from opus-tools 0.1.10");
        toniefile_comment_add(comment_data, &comment_data_pos, "encoder_options=--bitrate 64 --vbr --comp 10 --framesize 20");
    }

    /* add padding of first block */
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
        ctx->audio_length += og.header_len + og.body_len;

        sha1Update(&ctx->sha1, og.header, og.header_len);
        sha1Update(&ctx->sha1, og.body, og.body_len);
    }

    toniefile_new_chapter(ctx);

    return ctx;
}

error_t toniefile_close(toniefile_t *ctx)
{
    ctx->taf.sha1_hash.data = osAllocMem(SHA1_DIGEST_SIZE);
    ctx->taf.sha1_hash.len = SHA1_DIGEST_SIZE;
    ctx->taf.num_bytes = ctx->audio_length;
    sha1Final(&ctx->sha1, ctx->taf.sha1_hash.data);

    uint8_t buffer[TONIEFILE_FRAME_SIZE];

    osMemset(buffer, 0x00, sizeof(buffer));
    uint32_t proto_size = (uint32_t)toniefile_header(buffer, sizeof(buffer), &ctx->taf);

    fsSeekFile(ctx->file, 0, SEEK_SET);
    uint8_t proto_be[4];
    proto_be[0] = proto_size >> 24;
    proto_be[1] = proto_size >> 16;
    proto_be[2] = proto_size >> 8;
    proto_be[3] = proto_size;
    if (fsWriteFile(ctx->file, proto_be, sizeof(proto_be)) != NO_ERROR)
    {
        return ERROR_WRITE_FAILED;
    }

    fsSeekFile(ctx->file, 4, SEEK_SET);
    if (fsWriteFile(ctx->file, buffer, proto_size) != NO_ERROR)
    {
        return ERROR_WRITE_FAILED;
    }

    fsCloseFile(ctx->file);

    osFreeMem(ctx->taf._fill.data);
    osFreeMem(ctx->taf.sha1_hash.data);
    osFreeMem(ctx->taf.track_page_nums);
    opus_encoder_destroy(ctx->enc);
    ogg_stream_clear(&ctx->os);

    osFreeMem(ctx);

    return NO_ERROR;
}

static void toniefile_samples_copy(opus_int16 *dst, int *dst_used, opus_int16 *src, int *src_used, int samples)
{
    osMemcpy(&dst[*dst_used * OPUS_CHANNELS], &src[*src_used * OPUS_CHANNELS], samples * sizeof(uint16_t) * OPUS_CHANNELS);
    *dst_used += samples;
    *src_used += samples;
}

error_t toniefile_new_chapter(toniefile_t *ctx)
{
    if (ctx->taf.n_track_page_nums >= TONIEFILE_MAX_CHAPTERS - 1)
    {
        return ERROR_FAILURE;
    }
    ctx->taf.track_page_nums[ctx->taf.n_track_page_nums++] = ctx->taf_block_num;
    TRACE_INFO("new chapter at 0x%08" PRIXSIZE "\r\n", ctx->taf_block_num);

    return NO_ERROR;
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

        toniefile_samples_copy(ctx->audio_frame, &ctx->audio_frame_used, sample_buffer, &samples_processed, samples);

        /* buffer full? */
        if (ctx->audio_frame_used >= OPUS_FRAME_SIZE)
        {
            int page_used = (ctx->file_pos % TONIEFILE_FRAME_SIZE) + 27 + ctx->os.lacing_fill - ctx->os.lacing_returned + ctx->os.body_fill - ctx->os.body_returned;
            int page_remain = TONIEFILE_FRAME_SIZE - page_used;

            int frame_payload = (page_remain / 256) * 255 + (page_remain % 256) - 1;
            int reconstructed = (frame_payload / 255) + 1 + frame_payload;

            /* when due to segment sizes we would end up with a 1 byte gap, make sure that the next run will have at least 64 byte.
             * reason why this could happen is that "adding one byte" would require one segment more and thus occupies two byte more.
             * if this would happen, just reduce the calculated free space such that there is room for another segment.
             */
            if (page_remain != reconstructed && frame_payload > OPUS_PACKET_MINSIZE)
            {
                frame_payload -= OPUS_PACKET_MINSIZE;
            }
            if (frame_payload < OPUS_PACKET_MINSIZE)
            {
                TRACE_ERROR("Not enough space in this block\r\n");
                return ERROR_FAILURE;
            }

            int frame_len = opus_encode(ctx->enc, ctx->audio_frame, OPUS_FRAME_SIZE, output_frame, frame_payload);
            // TRACE_INFO("opus_encode: %d/%d\r\n", frame_len, frame_dest);

            if (frame_len <= 0)
            {
                TRACE_ERROR("Cannot encode: %s\r\n", opus_strerror(frame_len));
                return ERROR_FAILURE;
            }

            /* we did not exactly hit the destination size and are close to block size. pad packet */
            if (frame_payload - frame_len < OPUS_PACKET_PAD)
            {
                int target_length = frame_payload;

                int ret = opus_packet_pad(output_frame, frame_len, target_length);
                // TRACE_INFO("opus_packet_pad: %d -> %d\r\n", frame_len, target_length);
                if (ret < 0)
                {
                    TRACE_ERROR("Cannot pad: %s\r\n", opus_strerror(ret));
                    return ERROR_FAILURE;
                }
                frame_len = target_length;
            }

            /* we have to retrieve the actually encoded samples in this frame */
            int frames = opus_packet_get_samples_per_frame(output_frame, OPUS_SAMPLING_RATE) * opus_packet_get_nb_frames(output_frame, frame_len);
            if (frames != OPUS_FRAME_SIZE)
            {
                TRACE_ERROR("frame count unexpected: %d instead of %d\r\n", frames, OPUS_FRAME_SIZE);
            }
            ctx->ogg_granule_position += frames;

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

            page_used = (ctx->file_pos % TONIEFILE_FRAME_SIZE) + 27 + ctx->os.lacing_fill + ctx->os.body_fill;
            page_remain = TONIEFILE_FRAME_SIZE - page_used;

            if (page_remain < TONIEFILE_PAD_END)
            {
                if (page_remain)
                {
                    TRACE_INFO("unexpected small padding at %llu (%llu s)\r\n", ctx->ogg_granule_position, ctx->ogg_granule_position / OPUS_FRAME_SIZE * 60 / 1000)
                    return ERROR_FAILURE;
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
                    ctx->audio_length += og.header_len + og.body_len;

                    sha1Update(&ctx->sha1, og.header, og.header_len);
                    sha1Update(&ctx->sha1, og.body, og.body_len);

                    if ((prev / TONIEFILE_FRAME_SIZE) != (ctx->file_pos / TONIEFILE_FRAME_SIZE))
                    {
                        ctx->taf_block_num++;
                        if (ctx->file_pos % TONIEFILE_FRAME_SIZE)
                        {
                            TRACE_ERROR("Block alignment mismatch 0x%08" PRIXSIZE "\r\n", ctx->file_pos)
                            return ERROR_FAILURE;
                        }
                    }
                }
            }
            /* fill again */
            ctx->audio_frame_used = 0;
        }
    }

    return NO_ERROR;
}