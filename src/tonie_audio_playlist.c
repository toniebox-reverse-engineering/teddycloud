#include "tonie_audio_playlist_internal.h"

#include "fs_ext.h"
#include "fs_port.h"
#include "toniefile.h"
#include "server_helpers.h"
#include "cJSON.h"
#include "json_helper.h"
#include "handler.h"
#include "hash/sha1.h"
#include "ogg/ogg.h"
#include "opus.h"
#include "rand.h"

#define TAP_REMUX_MAX_PACKET_SIZE (TONIEFILE_FRAME_SIZE * 2)
#define TAP_REMUX_MAX_PENDING_PACKETS 16
#define TAP_REMUX_OPUS_HEAD_OFFSET 0x200

static uint8_t tap_normalize_shuffle(uint32_t shuffle)
{
    if (shuffle == TAP_SHUFFLE_ALL || shuffle == TAP_SHUFFLE_ONE)
    {
        return (uint8_t)shuffle;
    }

    return TAP_SHUFFLE_NONE;
}

static error_t tap_random_u32(uint32_t *value)
{
    if (value == NULL)
    {
        return ERROR_FAILURE;
    }

    return rand_get_algo()->read(rand_get_context(), (uint8_t *)value, sizeof(*value));
}

bool_t tap_final_cache_is_current(tonie_audio_playlist_t *tap)
{
    if (tap == NULL || !tap->_valid || tap->audio_id == 0 || tap->shuffle != TAP_SHUFFLE_NONE || tap->_filepath_resolved == NULL)
    {
        return false;
    }

    if (!fsFileExists(tap->_filepath_resolved))
    {
        return false;
    }

    tonie_info_t *tonieInfo = getTonieInfoV2(tap->_filepath_resolved, false, get_settings()->core.tap_taf_validation, get_settings());
    bool_t current = tonieInfo != NULL &&
                     tonieInfo->valid &&
                     tonieInfo->tafHeader != NULL &&
                     tonieInfo->tafHeader->audio_id == tap->audio_id;
    if (tonieInfo != NULL)
    {
        freeTonieInfo(tonieInfo);
    }

    return current;
}

typedef struct
{
    uint8_t data[TAP_REMUX_MAX_PACKET_SIZE];
    size_t len;
} tap_remux_packet_t;

typedef struct
{
    bool_t write_output;
    FsFile *file;
    uint32_t audio_id;
    Sha1Context sha1;
    tap_remux_packet_t pending[TAP_REMUX_MAX_PENDING_PACKETS];
    size_t pending_count;
    uint64_t pending_granule_position;
    size_t payload_size;
    uint64_t granule_position;
    uint64_t packet_count;
    uint64_t pageno;
    uint32_t track_page_nums[TONIEFILE_MAX_CHAPTERS];
    size_t track_page_nums_count;
    uint8_t opus_head[TAP_REMUX_MAX_PACKET_SIZE];
    size_t opus_head_len;
    bool_t have_opus_head;
    bool_t have_opus_tags;
    uint8_t page_header[OGG_HEADER_LENGTH + 255];
    uint8_t page_body[TONIEFILE_FRAME_SIZE];
    uint8_t scratch[TAP_REMUX_MAX_PACKET_SIZE];
    bool_t header_pages_written;
} tap_remux_ctx_t;

static void tap_remux_put_le32(uint8_t *data, uint32_t value)
{
    data[0] = value & 0xFF;
    data[1] = (value >> 8) & 0xFF;
    data[2] = (value >> 16) & 0xFF;
    data[3] = (value >> 24) & 0xFF;
}

static void tap_remux_put_le64(uint8_t *data, uint64_t value)
{
    for (size_t i = 0; i < 8; i++)
    {
        data[i] = (value >> (i * 8)) & 0xFF;
    }
}

static size_t tap_remux_lacing_count(size_t packet_len)
{
    return (packet_len / 255) + 1;
}

static size_t tap_remux_write_lacing(uint8_t *target, size_t packet_len)
{
    size_t count = 0;
    while (packet_len >= 255)
    {
        target[count++] = 255;
        packet_len -= 255;
    }
    target[count++] = (uint8_t)packet_len;
    return count;
}

static size_t tap_remux_pending_page_len(tap_remux_ctx_t *ctx)
{
    size_t len = OGG_HEADER_LENGTH;
    for (size_t i = 0; i < ctx->pending_count; i++)
    {
        len += tap_remux_lacing_count(ctx->pending[i].len) + ctx->pending[i].len;
    }
    return len;
}

static size_t tap_remux_pending_page_len_with_candidate(tap_remux_ctx_t *ctx, size_t candidate_index, size_t candidate_len)
{
    size_t len = OGG_HEADER_LENGTH;
    for (size_t i = 0; i < ctx->pending_count; i++)
    {
        size_t packet_len = i == candidate_index ? candidate_len : ctx->pending[i].len;
        len += tap_remux_lacing_count(packet_len) + packet_len;
    }
    return len;
}

static size_t tap_remux_current_block_remaining(tap_remux_ctx_t *ctx)
{
    size_t rest = ctx->payload_size % TONIEFILE_FRAME_SIZE;
    return rest == 0 ? TONIEFILE_FRAME_SIZE : TONIEFILE_FRAME_SIZE - rest;
}

static error_t tap_remux_write_page(tap_remux_ctx_t *ctx, tap_remux_packet_t *packets, size_t packet_count, uint64_t granule_position, uint8_t header_type)
{
    size_t segment_count = 0;
    size_t body_len = 0;
    for (size_t i = 0; i < packet_count; i++)
    {
        segment_count += tap_remux_lacing_count(packets[i].len);
        body_len += packets[i].len;
    }

    if (segment_count > 255 || body_len > sizeof(ctx->page_body))
    {
        return ERROR_FAILURE;
    }

    osMemset(ctx->page_header, 0x00, sizeof(ctx->page_header));
    osMemcpy(ctx->page_header, "OggS", 4);
    ctx->page_header[4] = 0;
    ctx->page_header[5] = header_type;
    tap_remux_put_le64(&ctx->page_header[6], granule_position);
    tap_remux_put_le32(&ctx->page_header[14], ctx->audio_id);
    tap_remux_put_le32(&ctx->page_header[18], (uint32_t)ctx->pageno);
    ctx->page_header[26] = (uint8_t)segment_count;

    size_t lacing_pos = OGG_HEADER_LENGTH;
    size_t body_pos = 0;
    for (size_t i = 0; i < packet_count; i++)
    {
        lacing_pos += tap_remux_write_lacing(&ctx->page_header[lacing_pos], packets[i].len);
        osMemcpy(&ctx->page_body[body_pos], packets[i].data, packets[i].len);
        body_pos += packets[i].len;
    }

    ogg_page og;
    og.header = ctx->page_header;
    og.header_len = (long)lacing_pos;
    og.body = ctx->page_body;
    og.body_len = (long)body_len;
    ogg_page_checksum_set(&og);

    if (ctx->write_output)
    {
        error_t error = fsWriteFile(ctx->file, og.header, og.header_len);
        if (error != NO_ERROR)
        {
            return error;
        }
        error = fsWriteFile(ctx->file, og.body, og.body_len);
        if (error != NO_ERROR)
        {
            return error;
        }
        error = fsFlushFile(ctx->file);
        if (error != NO_ERROR)
        {
            return error;
        }
    }

    sha1Update(&ctx->sha1, og.header, og.header_len);
    sha1Update(&ctx->sha1, og.body, og.body_len);
    ctx->payload_size += og.header_len + og.body_len;
    ctx->packet_count += packet_count;
    ctx->pageno++;
    return NO_ERROR;
}

static error_t tap_remux_pad_pending_to_block(tap_remux_ctx_t *ctx, size_t target_page_len)
{
    size_t page_len = tap_remux_pending_page_len(ctx);
    if (page_len > target_page_len)
    {
        return ERROR_FAILURE;
    }
    if (page_len == target_page_len)
    {
        return NO_ERROR;
    }

    for (size_t reverse = 0; reverse < ctx->pending_count; reverse++)
    {
        size_t i = ctx->pending_count - 1 - reverse;
        size_t original_len = ctx->pending[i].len;
        size_t max_len = TAP_REMUX_MAX_PACKET_SIZE;

        for (size_t target_len = original_len + 1; target_len < max_len; target_len++)
        {
            if (tap_remux_pending_page_len_with_candidate(ctx, i, target_len) != target_page_len)
            {
                continue;
            }

            osMemcpy(ctx->scratch, ctx->pending[i].data, original_len);
            int old_samples = opus_packet_get_samples_per_frame(ctx->scratch, OPUS_SAMPLING_RATE) * opus_packet_get_nb_frames(ctx->scratch, (opus_int32)original_len);
            if (old_samples <= 0)
            {
                return ERROR_FAILURE;
            }

            int ret = opus_packet_pad(ctx->scratch, (opus_int32)original_len, (opus_int32)target_len);
            if (ret != OPUS_OK)
            {
                continue;
            }

            int new_samples = opus_packet_get_samples_per_frame(ctx->scratch, OPUS_SAMPLING_RATE) * opus_packet_get_nb_frames(ctx->scratch, (opus_int32)target_len);
            if (new_samples != old_samples)
            {
                continue;
            }

            osMemcpy(ctx->pending[i].data, ctx->scratch, target_len);
            ctx->pending[i].len = target_len;
            return NO_ERROR;
        }
    }

    return ERROR_FAILURE;
}

static error_t tap_remux_flush_pending_aligned(tap_remux_ctx_t *ctx)
{
    if (ctx->pending_count == 0)
    {
        return NO_ERROR;
    }

    size_t target_page_len = tap_remux_current_block_remaining(ctx);
    error_t error = tap_remux_pad_pending_to_block(ctx, target_page_len);
    if (error != NO_ERROR)
    {
        TRACE_ERROR("Could not align TAP remux Ogg page from %" PRIuSIZE " to %" PRIuSIZE " bytes\r\n", tap_remux_pending_page_len(ctx), target_page_len);
        return error;
    }

    error = tap_remux_write_page(ctx, ctx->pending, ctx->pending_count, ctx->pending_granule_position, 0);
    ctx->pending_count = 0;
    ctx->pending_granule_position = 0;

    if (error == NO_ERROR && (ctx->payload_size % TONIEFILE_FRAME_SIZE) != 0)
    {
        TRACE_ERROR("TAP remux page alignment failed at %" PRIuSIZE "\r\n", ctx->payload_size);
        return ERROR_FAILURE;
    }

    return error;
}

static error_t tap_remux_add_audio_packet(tap_remux_ctx_t *ctx, const uint8_t *packet, size_t packet_len, uint32_t samples)
{
    if (packet_len > TAP_REMUX_MAX_PACKET_SIZE)
    {
        return ERROR_FAILURE;
    }

    tap_remux_packet_t candidate;
    osMemcpy(candidate.data, packet, packet_len);
    candidate.len = packet_len;

    if (ctx->pending_count >= TAP_REMUX_MAX_PENDING_PACKETS)
    {
        error_t error = tap_remux_flush_pending_aligned(ctx);
        if (error != NO_ERROR)
        {
            return error;
        }
    }

    size_t projected_len = tap_remux_pending_page_len(ctx) + tap_remux_lacing_count(packet_len) + packet_len;
    if (ctx->pending_count > 0 && projected_len > tap_remux_current_block_remaining(ctx))
    {
        error_t error = tap_remux_flush_pending_aligned(ctx);
        if (error != NO_ERROR)
        {
            return error;
        }
    }

    projected_len = OGG_HEADER_LENGTH + tap_remux_lacing_count(packet_len) + packet_len;
    if (ctx->pending_count == 0 && projected_len > tap_remux_current_block_remaining(ctx))
    {
        return ERROR_FAILURE;
    }

    ctx->granule_position += samples;
    osMemcpy(&ctx->pending[ctx->pending_count], &candidate, sizeof(candidate));
    ctx->pending_count++;
    ctx->pending_granule_position = ctx->granule_position;

    if (tap_remux_pending_page_len(ctx) == tap_remux_current_block_remaining(ctx))
    {
        return tap_remux_flush_pending_aligned(ctx);
    }

    return NO_ERROR;
}

static error_t tap_remux_write_initial_packet(tap_remux_ctx_t *ctx, const uint8_t *packet, size_t packet_len, uint8_t header_type)
{
    if (packet_len > TAP_REMUX_MAX_PACKET_SIZE)
    {
        return ERROR_FAILURE;
    }

    tap_remux_packet_t temp;
    osMemcpy(temp.data, packet, packet_len);
    temp.len = packet_len;
    return tap_remux_write_page(ctx, &temp, 1, 0, header_type);
}

static bool_t tap_remux_opus_head_compatible(const uint8_t *reference, size_t reference_len, const uint8_t *candidate, size_t candidate_len)
{
    if (reference_len < 19 || candidate_len < 19)
    {
        return FALSE;
    }
    if (osMemcmp(reference, "OpusHead", 8) != 0 || osMemcmp(candidate, "OpusHead", 8) != 0)
    {
        return FALSE;
    }
    if (reference[8] != candidate[8] || reference[9] != candidate[9] || reference[18] != candidate[18])
    {
        return FALSE;
    }

    uint8_t channels = reference[9];
    uint8_t mapping_family = reference[18];
    size_t required_len = mapping_family == 0 ? 19 : (size_t)21 + channels;
    if (reference_len < required_len || candidate_len < required_len)
    {
        return FALSE;
    }

    if (mapping_family != 0 && osMemcmp(&reference[19], &candidate[19], required_len - 19) != 0)
    {
        return FALSE;
    }

    return TRUE;
}

static error_t tap_remux_process_packet(tap_remux_ctx_t *ctx, const uint8_t *packet, size_t packet_len, size_t source_index, size_t packet_index)
{
    if (packet_len == 0 || packet_len > TAP_REMUX_MAX_PACKET_SIZE)
    {
        return ERROR_FAILURE;
    }

    if (packet_index == 0)
    {
        if (packet_len < 8 || osMemcmp(packet, "OpusHead", 8) != 0)
        {
            return ERROR_FAILURE;
        }
        if (!ctx->have_opus_head)
        {
            osMemcpy(ctx->opus_head, packet, packet_len);
            ctx->opus_head_len = packet_len;
            ctx->have_opus_head = TRUE;
            return tap_remux_write_initial_packet(ctx, packet, packet_len, 0x02);
        }
        if (!tap_remux_opus_head_compatible(ctx->opus_head, ctx->opus_head_len, packet, packet_len))
        {
            TRACE_ERROR("TAP remux source OpusHead incompatible at source %" PRIuSIZE "\r\n", source_index);
            return ERROR_FAILURE;
        }
        return NO_ERROR;
    }

    if (packet_index == 1)
    {
        if (packet_len < 8 || osMemcmp(packet, "OpusTags", 8) != 0)
        {
            return ERROR_FAILURE;
        }
        if (!ctx->have_opus_tags)
        {
            ctx->have_opus_tags = TRUE;
            error_t error = tap_remux_write_initial_packet(ctx, packet, packet_len, 0);
            if (error == NO_ERROR && ctx->payload_size != TAP_REMUX_OPUS_HEAD_OFFSET)
            {
                TRACE_ERROR("TAP remux OpusHead/Tags size is %" PRIuSIZE " instead of %u\r\n", ctx->payload_size, TAP_REMUX_OPUS_HEAD_OFFSET);
                return ERROR_FAILURE;
            }
            ctx->header_pages_written = TRUE;
            return error;
        }
        return NO_ERROR;
    }

    int frames = opus_packet_get_samples_per_frame(packet, OPUS_SAMPLING_RATE) * opus_packet_get_nb_frames(packet, (opus_int32)packet_len);
    if (frames <= 0)
    {
        return ERROR_FAILURE;
    }

    return tap_remux_add_audio_packet(ctx, packet, packet_len, (uint32_t)frames);
}

static error_t tap_remux_process_source(tap_remux_ctx_t *ctx, const char *source_path, size_t source_index)
{
    FsFile *source = fsOpenFile(source_path, FS_FILE_MODE_READ);
    if (source == NULL)
    {
        return ERROR_FILE_OPENING_FAILED;
    }

    error_t error = fsSeekFile(source, TONIEFILE_FRAME_SIZE, SEEK_SET);
    if (error != NO_ERROR)
    {
        fsCloseFile(source);
        return error;
    }

    uint8_t ogg_header[OGG_HEADER_LENGTH + 255];
    uint8_t ogg_body[TONIEFILE_FRAME_SIZE];
    uint8_t packet[TAP_REMUX_MAX_PACKET_SIZE];
    size_t packet_len = 0;
    size_t packet_index = 0;

    while (true)
    {
        size_t read_length = 0;
        error = fsReadFile(source, ogg_header, OGG_HEADER_LENGTH, &read_length);
        if (error == ERROR_END_OF_FILE || read_length == 0)
        {
            error = NO_ERROR;
            break;
        }
        if (error != NO_ERROR || read_length != OGG_HEADER_LENGTH)
        {
            error = error != NO_ERROR ? error : ERROR_END_OF_FILE;
            break;
        }
        if (osMemcmp(ogg_header, "OggS", 4) != 0)
        {
            error = ERROR_INVALID_FILE;
            break;
        }

        uint8_t segment_count = ogg_header[26];
        error = fsReadFile(source, &ogg_header[OGG_HEADER_LENGTH], segment_count, &read_length);
        if (error != NO_ERROR || read_length != segment_count)
        {
            error = error != NO_ERROR ? error : ERROR_END_OF_FILE;
            break;
        }

        size_t body_len = 0;
        for (size_t i = 0; i < segment_count; i++)
        {
            body_len += ogg_header[OGG_HEADER_LENGTH + i];
        }
        if (body_len > sizeof(ogg_body))
        {
            error = ERROR_FAILURE;
            break;
        }

        error = fsReadFile(source, ogg_body, body_len, &read_length);
        if (error != NO_ERROR || read_length != body_len)
        {
            error = error != NO_ERROR ? error : ERROR_END_OF_FILE;
            break;
        }

        size_t body_pos = 0;
        for (size_t i = 0; i < segment_count; i++)
        {
            uint8_t segment_len = ogg_header[OGG_HEADER_LENGTH + i];
            if (packet_len + segment_len > sizeof(packet))
            {
                error = ERROR_FAILURE;
                break;
            }
            osMemcpy(&packet[packet_len], &ogg_body[body_pos], segment_len);
            packet_len += segment_len;
            body_pos += segment_len;

            if (segment_len < 255)
            {
                error = tap_remux_process_packet(ctx, packet, packet_len, source_index, packet_index);
                if (error != NO_ERROR)
                {
                    break;
                }
                packet_len = 0;
                packet_index++;
            }
        }
        if (error != NO_ERROR)
        {
            break;
        }
    }

    fsCloseFile(source);
    if (error == NO_ERROR && packet_len != 0)
    {
        error = ERROR_INVALID_FILE;
    }
    return error;
}

static error_t tap_remux_taf(tonie_audio_playlist_t *tap, size_t *runtime_indices, size_t runtime_files_count, const char *target_taf, size_t *current_source, bool_t *active, bool_t write_output, toniefile_live_header_t *live_header, uint32_t *predicted_size)
{
    if (tap == NULL || tap->files == NULL || runtime_indices == NULL || runtime_files_count == 0 || runtime_files_count > TONIEFILE_MAX_SOURCES || live_header == NULL || predicted_size == NULL)
    {
        return ERROR_FAILURE;
    }

    tap_remux_ctx_t *ctx = osAllocMem(sizeof(tap_remux_ctx_t));
    if (ctx == NULL)
    {
        return ERROR_FAILURE;
    }
    osMemset(ctx, 0x00, sizeof(*ctx));
    ctx->write_output = write_output;
    ctx->audio_id = (uint32_t)tap->audio_id;
    sha1Init(&ctx->sha1);
    toniefile_live_header_t planned_header;
    bool_t have_planned_header = FALSE;
    if (write_output && live_header != NULL)
    {
        osMemcpy(&planned_header, live_header, sizeof(planned_header));
        have_planned_header = TRUE;
    }

    if (active != NULL)
    {
        *active = TRUE;
    }

    if (write_output)
    {
        ctx->file = fsOpenFile(target_taf, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);
        if (ctx->file == NULL)
        {
            osFreeMem(ctx);
            if (active != NULL)
            {
                *active = FALSE;
            }
            return ERROR_FILE_OPENING_FAILED;
        }

        error_t header_error = toniefile_write_taf_header(ctx->file, ctx->audio_id, live_header);
        if (header_error != NO_ERROR)
        {
            fsCloseFile(ctx->file);
            osFreeMem(ctx);
            if (active != NULL)
            {
                *active = FALSE;
            }
            return header_error;
        }
        header_error = fsSeekFile(ctx->file, TONIEFILE_FRAME_SIZE, SEEK_SET);
        if (header_error != NO_ERROR)
        {
            fsCloseFile(ctx->file);
            osFreeMem(ctx);
            if (active != NULL)
            {
                *active = FALSE;
            }
            return header_error;
        }
        header_error = fsFlushFile(ctx->file);
        if (header_error != NO_ERROR)
        {
            fsCloseFile(ctx->file);
            osFreeMem(ctx);
            if (active != NULL)
            {
                *active = FALSE;
            }
            return header_error;
        }
    }

    error_t error = NO_ERROR;
    for (size_t i = 0; i < runtime_files_count; i++)
    {
        size_t file_index = runtime_indices[i];
        if (file_index >= tap->filesCount)
        {
            error = ERROR_INVALID_FILE;
            break;
        }

        const char *source_path = tap->files[file_index]._filepath_resolved;
        if (current_source != NULL)
        {
            *current_source = i;
        }
        if (source_path == NULL || !toniefile_is_valid(source_path))
        {
            error = ERROR_INVALID_FILE;
            break;
        }

        if (i == 0)
        {
            ctx->track_page_nums[ctx->track_page_nums_count++] = 0;
        }
        else
        {
            error = tap_remux_flush_pending_aligned(ctx);
            if (error != NO_ERROR)
            {
                break;
            }
            if ((ctx->payload_size % TONIEFILE_FRAME_SIZE) != 0 || ctx->track_page_nums_count >= TONIEFILE_MAX_CHAPTERS)
            {
                error = ERROR_FAILURE;
                break;
            }
            ctx->track_page_nums[ctx->track_page_nums_count++] = ctx->payload_size / TONIEFILE_FRAME_SIZE;
        }

        error = tap_remux_process_source(ctx, source_path, i);
        if (error != NO_ERROR)
        {
            break;
        }
    }

    if (error == NO_ERROR)
    {
        error = tap_remux_flush_pending_aligned(ctx);
    }

    if (error == NO_ERROR)
    {
        uint8_t sha1_hash[SHA1_DIGEST_SIZE];
        sha1Final(&ctx->sha1, sha1_hash);

        osMemset(live_header, 0, sizeof(*live_header));
        live_header->payload_size = ctx->payload_size;
        osMemcpy(live_header->sha1_hash, sha1_hash, sizeof(live_header->sha1_hash));
        live_header->has_sha1_hash = TRUE;
        live_header->track_page_nums_count = ctx->track_page_nums_count;
        osMemcpy(live_header->track_page_nums, ctx->track_page_nums, ctx->track_page_nums_count * sizeof(uint32_t));
        live_header->has_ogg_state = TRUE;
        live_header->ogg_granule_position = ctx->granule_position;
        live_header->ogg_packet_count = ctx->packet_count;
        live_header->taf_block_num = ctx->payload_size / TONIEFILE_FRAME_SIZE;
        live_header->pageno = ctx->pageno;
        *predicted_size = ctx->payload_size + TONIEFILE_FRAME_SIZE;

        if (write_output && have_planned_header &&
            (planned_header.payload_size != live_header->payload_size ||
             planned_header.track_page_nums_count != live_header->track_page_nums_count ||
             planned_header.ogg_granule_position != live_header->ogg_granule_position ||
             planned_header.ogg_packet_count != live_header->ogg_packet_count ||
             planned_header.taf_block_num != live_header->taf_block_num ||
             planned_header.pageno != live_header->pageno ||
             osMemcmp(planned_header.sha1_hash, live_header->sha1_hash, SHA1_DIGEST_SIZE) != 0 ||
             osMemcmp(planned_header.track_page_nums, live_header->track_page_nums, live_header->track_page_nums_count * sizeof(uint32_t)) != 0))
        {
            TRACE_WARNING("TAP remux live header differed from generated header; initial stream header may be stale\r\n");
        }

        if (write_output && ctx->payload_size != live_header->payload_size)
        {
            error = ERROR_FAILURE;
        }
        if (write_output && error == NO_ERROR)
        {
            error = toniefile_write_taf_header(ctx->file, ctx->audio_id, live_header);
            if (error == NO_ERROR)
            {
                error = fsFlushFile(ctx->file);
            }
        }
    }

    if (ctx->file != NULL)
    {
        fsCloseFile(ctx->file);
    }
    if (active != NULL)
    {
        *active = FALSE;
    }
    osFreeMem(ctx);
    return error;
}

error_t tap_load(char *filename, tonie_audio_playlist_t *tap)
{
    size_t fileSize = 0;
    error_t error = fsGetFileSize(filename, (uint32_t *)(&fileSize));
    tap->_cached = false;
    tap->_valid = false;

    if (error != NO_ERROR)
    {
        return error;
    }
    if (fileSize == 0)
    {
        return ERROR_INVALID_FILE;
    }

    FsFile *fsFile = fsOpenFile(filename, FS_FILE_MODE_READ);
    if (fsFile == NULL)
    {
        return ERROR_FILE_OPENING_FAILED;
    }

    size_t sizeRead;
    char *data = osAllocMem(fileSize);
    if (data == NULL)
    {
        fsCloseFile(fsFile);
        return ERROR_OUT_OF_MEMORY;
    }
    size_t pos = 0;

    while (pos < fileSize)
    {
        sizeRead = 0;
        error = fsReadFile(fsFile, &data[pos], fileSize - pos, &sizeRead);
        if (error != NO_ERROR || sizeRead == 0)
        {
            if (error == NO_ERROR)
            {
                error = ERROR_END_OF_FILE;
            }
            break;
        }
        pos += sizeRead;
    }
    fsCloseFile(fsFile);
    if (error != NO_ERROR)
    {
        osFreeMem(data);
        return error;
    }

    cJSON *tapJson = cJSON_ParseWithLengthOpts(data, fileSize, 0, 0);
    osFreeMem(data);
    if (tapJson == NULL)
    {
        // const char *error_ptr = cJSON_GetErrorPtr();
        TRACE_ERROR("Json parse error\r\n");
        error = ERROR_INVALID_FILE;
    }
    else
    {
        tap->type = jsonGetString(tapJson, "type");
        if (tap->type == NULL)
        {
            error = ERROR_OUT_OF_MEMORY;
        }
        else if (osStrcmp(tap->type, "tap") == 0)
        {
            tap->audio_id = jsonGetUInt32(tapJson, "audio_id");
            tap->filepath = jsonGetString(tapJson, "filepath");
            tap->shuffle = tap_normalize_shuffle(jsonGetUInt32(tapJson, "shuffle"));
            if (tap->filepath == NULL || tap->filepath[0] == '\0')
            {
                error = tap->filepath == NULL ? ERROR_OUT_OF_MEMORY : ERROR_INVALID_FILE;
            }

            if (error == NO_ERROR)
            {
                tap->_filepath_resolved = strdup(tap->filepath);
                if (tap->_filepath_resolved == NULL)
                {
                    error = ERROR_OUT_OF_MEMORY;
                }
                else
                {
                    resolveSpecialPathPrefix(&tap->_filepath_resolved, get_settings());
                }
            }

            if (error == NO_ERROR)
            {
                tap->name = jsonGetString(tapJson, "name");
                if (tap->name == NULL)
                {
                    error = ERROR_OUT_OF_MEMORY;
                }
            }

            const cJSON *filesJson = error == NO_ERROR ? cJSON_GetObjectItemCaseSensitive(tapJson, "files") : NULL;
            if (error == NO_ERROR && !cJSON_IsArray(filesJson))
            {
                error = ERROR_INVALID_FILE;
            }
            if (error == NO_ERROR)
            {
                int filesCount = cJSON_GetArraySize(filesJson);
                uint8_t shuffle = tap_normalize_shuffle(tap->shuffle);
                size_t maxFiles = shuffle == TAP_SHUFFLE_ONE ? TAP_SHUFFLE_ONE_MAX_CANDIDATES : TONIEFILE_MAX_SOURCES;
                if (filesCount <= 0 || (size_t)filesCount > maxFiles)
                {
                    error = ERROR_INVALID_FILE;
                }
                else
                {
                    tap->filesCount = (size_t)filesCount;
                    tap->files = osAllocMem(tap->filesCount * sizeof(tap_file_t));
                    if (tap->files == NULL)
                    {
                        error = ERROR_OUT_OF_MEMORY;
                    }
                    else
                    {
                        osMemset(tap->files, 0x00, tap->filesCount * sizeof(tap_file_t));
                    }
                }
            }
            if (error == NO_ERROR)
            {
                size_t i = 0;
                cJSON *fileJson;
                cJSON_ArrayForEach(fileJson, filesJson)
                {
                    if (i >= tap->filesCount || !cJSON_IsObject(fileJson))
                    {
                        error = ERROR_INVALID_FILE;
                        break;
                    }

                    tap->files[i].filepath = jsonGetString(fileJson, "filepath");
                    if (tap->files[i].filepath == NULL || tap->files[i].filepath[0] == '\0')
                    {
                        error = tap->files[i].filepath == NULL ? ERROR_OUT_OF_MEMORY : ERROR_INVALID_FILE;
                        break;
                    }

                    tap->files[i]._filepath_resolved = strdup(tap->files[i].filepath);
                    if (tap->files[i]._filepath_resolved == NULL)
                    {
                        error = ERROR_OUT_OF_MEMORY;
                        break;
                    }
                    resolveSpecialPathPrefix(&tap->files[i]._filepath_resolved, get_settings());

                    tap->files[i].name = jsonGetString(fileJson, "name");
                    if (tap->files[i].name == NULL)
                    {
                        error = ERROR_OUT_OF_MEMORY;
                        break;
                    }
                    i++;
                }
                if (error == NO_ERROR && i != tap->filesCount)
                {
                    error = ERROR_INVALID_FILE;
                }
            }
        }
        else
        {
            error = ERROR_INVALID_FILE;
        }
    }

    cJSON_Delete(tapJson);
    if (error == NO_ERROR)
    {
        tap->_valid = true;
        if (tap_final_cache_is_current(tap))
        {
            tap->_cached = true;
        }
    }
    else
    {
        tap_free(tap);
    }
    return error;
}
error_t tap_save(char *filename, tonie_audio_playlist_t *tap)
{

    cJSON *tapJson = cJSON_CreateObject();
    error_t error = NO_ERROR;

    cJSON_AddStringToObject(tapJson, "type", TAP_TYPE_TAP);
    cJSON_AddNumberToObject(tapJson, "audio_id", tap->audio_id);
    cJSON_AddNumberToObject(tapJson, "shuffle", tap_normalize_shuffle(tap->shuffle));
    cJSON_AddStringToObject(tapJson, "filepath", tap->filepath);
    cJSON_AddStringToObject(tapJson, "name", tap->name);
    if (tap->files != NULL)
    {
        cJSON *filesJson = cJSON_AddArrayToObject(tapJson, "files");
        for (size_t i = 0; i < tap->filesCount; i++)
        {
            cJSON *fileJson = cJSON_CreateObject();
            cJSON_AddStringToObject(fileJson, "filepath", tap->files[i].filepath);
            cJSON_AddStringToObject(fileJson, "name", tap->files[i].name);
            cJSON_AddItemToArray(filesJson, fileJson);
        }
    }
    char *jsonRaw = cJSON_Print(tapJson);

    FsFile *fsFile = fsOpenFile(filename, FS_FILE_MODE_WRITE);
    if (fsFile == NULL)
    {
        error = ERROR_FILE_OPENING_FAILED;
    }
    else
    {
        error = fsWriteFile(fsFile, jsonRaw, osStrlen(jsonRaw));
        fsCloseFile(fsFile);
    }

    cJSON_Delete(tapJson);
    osFreeMem(jsonRaw);
    return error;
}

void tap_free(tonie_audio_playlist_t *tap)
{
    if (tap->files != NULL)
    {
        for (size_t i = 0; i < tap->filesCount; i++)
        {
            osFreeMem(tap->files[i].filepath);
            osFreeMem(tap->files[i]._filepath_resolved);
            osFreeMem(tap->files[i].name);
        }
        osFreeMem(tap->files);
    }
    if (tap->type != NULL)
    {
        osFreeMem(tap->type);
    }
    if (tap->filepath != NULL)
    {
        osFreeMem(tap->filepath);
    }
    if (tap->_filepath_resolved != NULL)
    {
        osFreeMem(tap->_filepath_resolved);
    }
    if (tap->name != NULL)
    {
        osFreeMem(tap->name);
    }

    osMemset(tap, 0, sizeof(tonie_audio_playlist_t));
}

error_t tap_prepare_runtime_indices(tonie_audio_playlist_t *tap, size_t **runtime_indices, size_t *runtime_files_count)
{
    if (runtime_indices == NULL || runtime_files_count == NULL)
    {
        return ERROR_FAILURE;
    }

    *runtime_indices = NULL;
    *runtime_files_count = 0;

    if (tap == NULL || tap->files == NULL || tap->filesCount == 0)
    {
        return ERROR_FAILURE;
    }

    uint8_t shuffle = tap_normalize_shuffle(tap->shuffle);
    size_t selected_count = shuffle == TAP_SHUFFLE_ONE ? 1 : tap->filesCount;
    if (selected_count == 0 || selected_count > TONIEFILE_MAX_SOURCES)
    {
        return ERROR_INVALID_FILE;
    }

    size_t *indices = osAllocMem(selected_count * sizeof(size_t));
    if (indices == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }

    if (shuffle == TAP_SHUFFLE_ONE)
    {
        uint32_t random_value;
        error_t error = tap_random_u32(&random_value);
        if (error != NO_ERROR)
        {
            osFreeMem(indices);
            return error;
        }

        indices[0] = random_value % tap->filesCount;
    }
    else
    {
        for (size_t i = 0; i < selected_count; i++)
        {
            indices[i] = i;
        }

        if (shuffle == TAP_SHUFFLE_ALL)
        {
            for (size_t i = selected_count - 1; i > 0; i--)
            {
                uint32_t random_value;
                error_t error = tap_random_u32(&random_value);
                if (error != NO_ERROR)
                {
                    osFreeMem(indices);
                    return error;
                }

                size_t j = random_value % (i + 1);
                size_t swap = indices[i];
                indices[i] = indices[j];
                indices[j] = swap;
            }
        }
    }

    *runtime_indices = indices;
    *runtime_files_count = selected_count;
    return NO_ERROR;
}

void tap_free_runtime_indices(size_t *runtime_indices)
{
    if (runtime_indices != NULL)
    {
        osFreeMem(runtime_indices);
    }
}

error_t tap_predict_taf_live_header(tonie_audio_playlist_t *tap, size_t *runtime_indices, size_t runtime_files_count, toniefile_live_header_t *live_header, uint32_t *predicted_size)
{
    return tap_remux_taf(tap, runtime_indices, runtime_files_count, NULL, NULL, NULL, FALSE, live_header, predicted_size);
}

error_t tap_publish_taf_replace_safe(const char *tmp_taf, const char *final_taf)
{
    if (tmp_taf == NULL || final_taf == NULL)
    {
        return ERROR_INVALID_FILE;
    }

    if (!toniefile_is_valid(tmp_taf))
    {
        TRACE_ERROR("TAP publish source %s is not a valid TAF\r\n", tmp_taf);
        return ERROR_INVALID_FILE;
    }

    char *backup_taf = custom_asprintf("%s.replace.bak", final_taf);
    if (backup_taf == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }

    error_t error = NO_ERROR;
    bool_t final_exists = fsFileExists(final_taf);

    if (fsFileExists(backup_taf))
    {
        if (final_exists)
        {
            error = fsDeleteFile(backup_taf);
            if (error != NO_ERROR && fsFileExists(backup_taf))
            {
                TRACE_ERROR("Could not delete stale TAP backup file %s, error=%s\r\n", backup_taf, error2text(error));
                osFreeMem(backup_taf);
                return error;
            }
        }
        else
        {
            TRACE_WARNING("Recover TAP final %s from stale backup %s\r\n", final_taf, backup_taf);
            error = fsRenameFile(backup_taf, final_taf);
            if (error != NO_ERROR || !fsFileExists(final_taf))
            {
                if (error == NO_ERROR)
                {
                    error = ERROR_FAILURE;
                }
                TRACE_ERROR("Could not recover TAP final %s from backup %s, error=%s\r\n", final_taf, backup_taf, error2text(error));
                osFreeMem(backup_taf);
                return error;
            }
            final_exists = TRUE;
        }
    }

    if (!final_exists)
    {
        TRACE_VERBOSE("Publish TAP %s -> %s\r\n", tmp_taf, final_taf);
        error = fsRenameFile(tmp_taf, final_taf);
        if (error != NO_ERROR || !fsFileExists(final_taf))
        {
            if (error == NO_ERROR)
            {
                error = ERROR_FAILURE;
            }
            TRACE_ERROR("Could not publish TAP %s from %s, error=%s\r\n", final_taf, tmp_taf, error2text(error));
        }
        osFreeMem(backup_taf);
        return error;
    }

    TRACE_VERBOSE("Backup TAP final %s -> %s before replace\r\n", final_taf, backup_taf);
    error = fsRenameFile(final_taf, backup_taf);
    if (error != NO_ERROR || !fsFileExists(backup_taf))
    {
        if (error == NO_ERROR)
        {
            error = ERROR_FAILURE;
        }
        TRACE_ERROR("Could not backup TAP final %s to %s, error=%s\r\n", final_taf, backup_taf, error2text(error));
        osFreeMem(backup_taf);
        return error;
    }

    TRACE_VERBOSE("Replace TAP final %s from %s\r\n", final_taf, tmp_taf);
    error = fsRenameFile(tmp_taf, final_taf);
    if (error == NO_ERROR)
    {
        if (!fsFileExists(final_taf))
        {
            error = ERROR_FAILURE;
        }
    }

    if (error != NO_ERROR)
    {
        TRACE_ERROR("Could not replace TAP final %s from %s, error=%s\r\n", final_taf, tmp_taf, error2text(error));
        error_t rollback_error = fsRenameFile(backup_taf, final_taf);
        if (rollback_error != NO_ERROR || !fsFileExists(final_taf))
        {
            if (rollback_error == NO_ERROR)
            {
                rollback_error = ERROR_FAILURE;
            }
            TRACE_ERROR("Could not restore TAP final %s from backup %s, error=%s\r\n", final_taf, backup_taf, error2text(rollback_error));
        }
    }
    else if (fsFileExists(backup_taf))
    {
        error_t cleanup_error = fsDeleteFile(backup_taf);
        if (cleanup_error != NO_ERROR && fsFileExists(backup_taf))
        {
            TRACE_WARNING("Could not delete TAP backup file %s, error=%s\r\n", backup_taf, error2text(cleanup_error));
        }
    }

    osFreeMem(backup_taf);
    return error;
}

static error_t tap_generate_taf(tonie_audio_playlist_t *tap, size_t *runtime_indices, size_t runtime_files_count, size_t *current_source, bool_t *generator_active, bool_t force, bool_t preserve_on_client_disconnect, const toniefile_live_header_t *live_header)
{
    error_t error = NO_ERROR;
    bool_t sweep = false;
    tonie_info_t *tonieInfo = getTonieInfo(tap->_filepath_resolved, false, get_settings());

    // The TAP audio_id is the playlist version source for cache validity.
    if (force || !tonieInfo->valid || tonieInfo->tafHeader->audio_id != tap->audio_id)
    {
        char *tmp_taf = custom_asprintf("%s.tmp", tap->_filepath_resolved);
        char source[TONIEFILE_MAX_SOURCES][PATH_LEN];
        if (tmp_taf == NULL)
        {
            freeTonieInfo(tonieInfo);
            return ERROR_OUT_OF_MEMORY;
        }
        if (runtime_indices == NULL || runtime_files_count == 0)
        {
            osFreeMem(tmp_taf);
            freeTonieInfo(tonieInfo);
            return ERROR_INVALID_FILE;
        }

        toniefile_live_header_t remux_header;
        uint32_t remux_predicted_size = 0;
        bool_t remux_available = false;
        error_t remux_probe_error = tap_remux_taf(tap, runtime_indices, runtime_files_count, NULL, NULL, NULL, FALSE, &remux_header, &remux_predicted_size);
        if (remux_probe_error == NO_ERROR)
        {
            remux_available = true;
            TRACE_INFO("TAP remux path selected for %s\r\n", tmp_taf);
            if (live_header != NULL && live_header->has_sha1_hash && live_header->has_ogg_state &&
                (live_header->payload_size != remux_header.payload_size ||
                 live_header->track_page_nums_count != remux_header.track_page_nums_count ||
                 live_header->ogg_granule_position != remux_header.ogg_granule_position ||
                 live_header->ogg_packet_count != remux_header.ogg_packet_count ||
                 live_header->taf_block_num != remux_header.taf_block_num ||
                 live_header->pageno != remux_header.pageno ||
                 osMemcmp(live_header->sha1_hash, remux_header.sha1_hash, SHA1_DIGEST_SIZE) != 0 ||
                 osMemcmp(live_header->track_page_nums, remux_header.track_page_nums, remux_header.track_page_nums_count * sizeof(uint32_t)) != 0))
            {
                TRACE_WARNING("TAP remux handler prediction differed from generation prediction; using generation prediction\r\n");
            }
        }

        if (remux_available)
        {
            error = tap_remux_taf(tap, runtime_indices, runtime_files_count, tmp_taf, current_source, generator_active, TRUE, &remux_header, &remux_predicted_size);
        }
        else
        {
            if (live_header != NULL && live_header->has_sha1_hash && live_header->has_ogg_state)
            {
                TRACE_ERROR("TAP remux live header is available but remux generation is unavailable, error=%s\r\n", error2text(remux_probe_error));
                error = remux_probe_error != NO_ERROR ? remux_probe_error : ERROR_FAILURE;
            }
            else
            {
                TRACE_WARNING("TAP remux unavailable, falling back to FFmpeg generation, error=%s\r\n", error2text(remux_probe_error));
            }
        }

        if (!remux_available && error == NO_ERROR)
        {
            if (runtime_files_count > TONIEFILE_MAX_SOURCES)
            {
                error = ERROR_INVALID_FILE;
            }

            if (error == NO_ERROR)
            {
                for (size_t i = 0; i < runtime_files_count; i++)
                {
                    size_t file_index = runtime_indices[i];
                    if (file_index >= tap->filesCount)
                    {
                        error = ERROR_INVALID_FILE;
                        break;
                    }

                    osStrcpy(source[i], tap->files[file_index]._filepath_resolved);
                }
            }
            if (error == NO_ERROR)
            {
                if (tap->audio_id != 0)
                {
                    error = ffmpeg_stream_with_audio_id(source, runtime_files_count, current_source, tmp_taf, 0, generator_active, &sweep, false, preserve_on_client_disconnect, (uint32_t)tap->audio_id);
                }
                else
                {
                    error = ffmpeg_stream(source, runtime_files_count, current_source, tmp_taf, 0, generator_active, &sweep, false, preserve_on_client_disconnect);
                }
            }
        }
        if (error == NO_ERROR)
        {
            TRACE_VERBOSE("TAP generation left %s for handler-owned publish\r\n", tmp_taf);
        }
        else
        {
            error_t delete_error = fsDeleteFile(tmp_taf);
            if (delete_error != NO_ERROR)
            {
                TRACE_WARNING("Could not delete failed temporary TAP file %s, error=%s\r\n", tmp_taf, error2text(delete_error));
            }
        }
        osFreeMem(tmp_taf);
        freeTonieInfo(tonieInfo);
    }
    return error;
}

void tap_generate_task(void *param)
{
    tap_generate_param_t *tap_ctx = (tap_generate_param_t *)param;
    stream_ctx_t *stream_ctx = (stream_ctx_t *)tap_ctx->stream_ctx;
    tap_ctx->generator_started = true;

    tap_ctx->error = tap_generate_taf(tap_ctx->tap, tap_ctx->runtime_indices, tap_ctx->runtime_files_count, &tap_ctx->current_source, &tap_ctx->generator_active, tap_ctx->force, tap_ctx->preserve_on_client_disconnect, &tap_ctx->live_header);
    tap_ctx->generator_done = true;

    if (stream_ctx != NULL && tap_ctx->generation == stream_ctx->generation)
    {
        stream_ctx->current_source = tap_ctx->current_source;
        stream_ctx->error = tap_ctx->error;
        stream_ctx->active = tap_ctx->generator_active;
        stream_ctx->quit = true;
    }
    osDeleteTask((OsTaskId) OS_SELF_TASK_ID);
}
