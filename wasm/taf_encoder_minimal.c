/**
 * @file taf_encoder_minimal.c
 * @brief Minimal standalone TAF encoder for WebAssembly
 * 
 * This is a clean-room implementation extracting only the core encoding logic
 * from toniefile.c, with no dependencies on cyclone, server helpers, or file I/O.
 * 
 * Uses memory buffers instead of files for WASM compatibility.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef WASM_BUILD
#include <emscripten.h>
#else
#define EMSCRIPTEN_KEEPALIVE
#endif

// Opus and OGG includes
#include "opus.h"
#include "ogg/ogg.h"

// Standalone SHA1 for TAF validation
#include "sha1_standalone.h"

// Protobuf for TAF header
#include "proto/toniebox.pb.taf-header.pb-c.h"

// Constants from toniefile.h
#define OPUS_FRAME_SIZE_MS OPUS_FRAMESIZE_60_MS
#define OPUS_SAMPLING_RATE 48000
#define OPUS_FRAME_SIZE (OPUS_SAMPLING_RATE * 60 / 1000) /* 2880 samples: 60ms at 48kHz */
#define OPUS_CHANNELS 2
#define OPUS_PACKET_MINSIZE 64

#define TONIEFILE_FRAME_SIZE 4096
#define TONIEFILE_MAX_CHAPTERS 100
#define OGG_HEADER_LENGTH 27

// Encoder context
typedef struct {
    // Opus encoder
    OpusEncoder *enc;
    
    // OGG stream
    ogg_stream_state os;
    
    // TAF header
    TonieboxAudioFileHeader taf;
    
    // SHA1 for audio data
    Sha1Context sha1;
    
    // Audio frame buffer
    int16_t audio_frame[OPUS_FRAME_SIZE * OPUS_CHANNELS];
    int audio_frame_used;
    
    // Output buffer (memory-based)
    uint8_t *output_buffer;
    size_t output_size;
    size_t output_capacity;
    
    // Tracking
    uint64_t ogg_granule_position;
    uint64_t ogg_packet_count;
    uint32_t taf_block_num;
    size_t audio_length;
    
    // Bitrate
    int bitrate;
} taf_encoder_t;

// Helper: Write to memory buffer
static int buffer_write(taf_encoder_t *ctx, const void *data, size_t length) {
    size_t required = ctx->output_size + length;
    
    // Grow buffer if needed
    if (required > ctx->output_capacity) {
        size_t new_capacity = ctx->output_capacity * 2;
        if (new_capacity < required) {
            new_capacity = required;
        }
        
        uint8_t *new_buffer = (uint8_t *)realloc(ctx->output_buffer, new_capacity);
        if (!new_buffer) {
            return -1;
        }
        
        ctx->output_buffer = new_buffer;
        ctx->output_capacity = new_capacity;
    }
    
    // Write data
    memcpy(ctx->output_buffer + ctx->output_size, data, length);
    ctx->output_size += length;
    
    // Update SHA1 hash
    sha1Update(&ctx->sha1, (const uint8_t *)data, length);
    ctx->audio_length += length;
    
    return 0;
}

// Helper: Seek in memory buffer
static int buffer_seek(taf_encoder_t *ctx, size_t offset) {
    if (offset > ctx->output_size) {
        return -1;
    }
    // For memory buffer, we just track position
    // Actual seeking is done by writing at specific offsets
    return 0;
}

// Helper: Write at specific offset
static int buffer_write_at(taf_encoder_t *ctx, size_t offset, const void *data, size_t length) {
    if (offset + length > ctx->output_capacity) {
        return -1;
    }
    memcpy(ctx->output_buffer + offset, data, length);
    return 0;
}

// Helper: Add comment to OGG
static void add_comment(uint8_t *buffer, size_t *pos, const char *comment) {
    uint32_t len = strlen(comment);
    memcpy(&buffer[*pos], &len, sizeof(uint32_t));
    *pos += sizeof(uint32_t);
    memcpy(&buffer[*pos], comment, len);
    *pos += len;
}

// Helper: Encode TAF header using protobuf
static size_t encode_taf_header(uint8_t *buffer, size_t buffer_size, TonieboxAudioFileHeader *header) {
    return toniebox_audio_file_header__pack(header, buffer);
}

/**
 * Create TAF encoder
 * @param audio_id Audio ID for the TAF file
 * @param bitrate Bitrate in kbps (e.g., 96 for 96kbps)
 * @return Encoder context or NULL on error
 */
EMSCRIPTEN_KEEPALIVE
taf_encoder_t *taf_encoder_create(uint32_t audio_id, int bitrate) {
    printf("taf_encoder_create: audio_id=%u, bitrate=%d\n", audio_id, bitrate);
    int err;
    
    taf_encoder_t *ctx = (taf_encoder_t *)calloc(1, sizeof(taf_encoder_t));
    if (!ctx) {
        return NULL;
    }
    
    // Explicitly zero the structure
    memset(ctx, 0, sizeof(taf_encoder_t));
    
    ctx->bitrate = bitrate > 0 ? bitrate : 96; // Default 96kbps
    
    // Allocate output buffer (start with 10MB)
    ctx->output_capacity = 10 * 1024 * 1024;
    ctx->output_buffer = (uint8_t *)malloc(ctx->output_capacity);
    if (!ctx->output_buffer) {
        free(ctx);
        return NULL;
    }
    
    // Initialize TAF header
    toniebox_audio_file_header__init(&ctx->taf);
    ctx->taf.audio_id = audio_id;
    ctx->taf.num_bytes = 0; // Will be updated on close
    ctx->taf.n_track_page_nums = 0;
    ctx->taf.track_page_nums = (uint32_t *)calloc(TONIEFILE_MAX_CHAPTERS, sizeof(uint32_t));
    ctx->taf.sha1_hash.data = NULL;  // Will be allocated in finalize
    ctx->taf.sha1_hash.len = 0;
    
    // Initialize SHA1
    sha1Init(&ctx->sha1);
    
    // Initialize Opus encoder
    ctx->enc = opus_encoder_create(OPUS_SAMPLING_RATE, OPUS_CHANNELS, OPUS_APPLICATION_AUDIO, &err);
    if (err != OPUS_OK) {
        free(ctx->taf.track_page_nums);
        free(ctx->output_buffer);
        free(ctx);
        return NULL;
    }
    
    opus_encoder_ctl(ctx->enc, OPUS_SET_BITRATE(ctx->bitrate * 1000));
    opus_encoder_ctl(ctx->enc, OPUS_SET_VBR(1));
    opus_encoder_ctl(ctx->enc, OPUS_SET_COMPLEXITY(10));
    opus_encoder_ctl(ctx->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC));
    opus_encoder_ctl(ctx->enc, OPUS_SET_LSB_DEPTH(16));
    opus_encoder_ctl(ctx->enc, OPUS_SET_EXPERT_FRAME_DURATION(OPUS_FRAME_SIZE_MS));
    
    // Initialize OGG stream
    ogg_stream_init(&ctx->os, audio_id);
    
    // Reserve first 4KB (TONIEFILE_FRAME_SIZE) for TAF header
    // This matches toniefile.c which starts writing at file_pos = TONIEFILE_FRAME_SIZE
    // Audio data starts at offset 4096, and SHA1 is calculated over audio only
    ctx->output_size = TONIEFILE_FRAME_SIZE;
    memset(ctx->output_buffer, 0, TONIEFILE_FRAME_SIZE);
    
    // Create Opus header packet
    uint8_t header_data[] = {
        'O', 'p', 'u', 's', 'H', 'e', 'a', 'd',  // "OpusHead"
        1,                                         // Version
        OPUS_CHANNELS,                             // Channel count
        0x38, 0x01,                                // Pre-skip
        OPUS_SAMPLING_RATE & 0xFF, OPUS_SAMPLING_RATE >> 8, 0x00, 0x00,  // Sample rate
        0, 0,                                      // Output gain
        0                                          // Channel mapping family
    };
    
    // Create comment packet
    uint8_t comment_data[0x1B4];
    size_t comment_pos = 0;
    memset(comment_data, '0', sizeof(comment_data));
    strcpy((char *)&comment_data[comment_pos], "OpusTags");
    comment_pos += 8;
    
    add_comment(comment_data, &comment_pos, "teddyCloud WASM");
    
    int comments = 1;
    memcpy(&comment_data[comment_pos], &comments, sizeof(uint32_t));
    comment_pos += sizeof(uint32_t);
    
    add_comment(comment_data, &comment_pos, "encoder=teddyCloud WASM TAF Encoder");
    
    // Add padding
    int remain = sizeof(comment_data) - comment_pos - 4;
    memcpy(&comment_data[comment_pos], &remain, sizeof(uint32_t));
    comment_pos += sizeof(uint32_t);
    memcpy(&comment_data[comment_pos], "pad=", 4);
    
    // Create OGG packets
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
    
    // Flush header pages
    ogg_page og;
    while (ogg_stream_flush(&ctx->os, &og)) {
        buffer_write(ctx, og.header, og.header_len);
        buffer_write(ctx, og.body, og.body_len);
    }
    
    // Add first chapter at start
    ctx->taf.track_page_nums[ctx->taf.n_track_page_nums++] = ctx->taf_block_num;
    
    return ctx;
}

/**
 * Encode PCM samples
 * @param ctx Encoder context
 * @param samples PCM samples (interleaved stereo, 16-bit)
 * @param num_samples Number of samples PER CHANNEL
 * @return 0 on success, -1 on error
 */
EMSCRIPTEN_KEEPALIVE
int taf_encoder_encode(taf_encoder_t *ctx, int16_t *samples, int num_samples) {
    //printf("taf_encoder_encode: ctx=%p, samples=%p, num_samples=%d\n", ctx, samples, num_samples);
    if (!ctx || !samples) {
        return -1;
    }
    
    int samples_processed = 0;
    
    while (samples_processed < num_samples) {
        // Copy samples to frame buffer
        int samples_to_copy = OPUS_FRAME_SIZE - ctx->audio_frame_used;
        int samples_remaining = num_samples - samples_processed;
        if (samples_to_copy > samples_remaining) {
            samples_to_copy = samples_remaining;
        }
        
        for (int i = 0; i < samples_to_copy; i++) {
            ctx->audio_frame[(ctx->audio_frame_used + i) * 2] = samples[(samples_processed + i) * 2];
            ctx->audio_frame[(ctx->audio_frame_used + i) * 2 + 1] = samples[(samples_processed + i) * 2 + 1];
        }
        
        ctx->audio_frame_used += samples_to_copy;
        samples_processed += samples_to_copy;
        
        // Frame full? Encode it
        if (ctx->audio_frame_used >= OPUS_FRAME_SIZE) {
#define OPUS_PACKET_PAD 64

            // Calculate available space in current block
            int page_used = (ctx->output_size % TONIEFILE_FRAME_SIZE) + OGG_HEADER_LENGTH +
                           ctx->os.lacing_fill - ctx->os.lacing_returned +
                           ctx->os.body_fill - ctx->os.body_returned;
            int page_remain = TONIEFILE_FRAME_SIZE - page_used;
            
            int frame_payload = (page_remain / 256) * 255 + (page_remain % 256) - 1;
            int reconstructed = (frame_payload / 255) + 1 + frame_payload;
            
            /* when due to segment sizes we would end up with a 1 byte gap, make sure that the next run will have at least 64 byte.
             * reason why this could happen is that "adding one byte" would require one segment more and thus occupies two byte more.
             * if this would happen, just reduce the calculated free space such that there is room for another segment.
             */
            bool frame_payload_minified = false;
            if (page_remain != reconstructed && frame_payload > OPUS_PACKET_MINSIZE) {
                frame_payload -= OPUS_PACKET_MINSIZE;
                frame_payload_minified = true;
            }

            
            // Ensure minimum packet size
            if (frame_payload < OPUS_PACKET_MINSIZE - 1) {
                // Not enough space for even a minimal packet.
                // Force flush the current page to finish the block.
                //printf("taf_encoder_encode: Page full (remain=%d), forcing flush\n", page_remain);
                ogg_page og;
                if (ogg_stream_flush(&ctx->os, &og)) {
                    buffer_write(ctx, og.header, og.header_len);
                    buffer_write(ctx, og.body, og.body_len);
                    ctx->taf_block_num++;
                    
                    // Recalculate
                    page_used = (ctx->output_size % TONIEFILE_FRAME_SIZE) + OGG_HEADER_LENGTH +
                           ctx->os.lacing_fill - ctx->os.lacing_returned +
                           ctx->os.body_fill - ctx->os.body_returned;
                    page_remain = TONIEFILE_FRAME_SIZE - page_used;
                    frame_payload = (page_remain / 256) * 255 + (page_remain % 256) - 1;
                    //printf("taf_encoder_encode: Flushed. New page_remain=%d\n", page_remain);
                }
                
                if (frame_payload < OPUS_PACKET_MINSIZE - 1) {
                    return -1;
                }
            }
            
            // Encode Opus frame
            //printf("taf_encoder_encode: Encoding frame...\n");
            unsigned char output_frame[TONIEFILE_FRAME_SIZE];
            //printf("taf_encoder_encode: Calling opus_encode (payload=%d)\n", frame_payload);
            int frame_len = opus_encode(ctx->enc, ctx->audio_frame, OPUS_FRAME_SIZE,
                                       output_frame, frame_payload);
            
            if (frame_len <= 0) {
                return -1;
            }
            
            /* we did not exactly hit the destination size and are close to block size. pad packet */
            if (frame_payload - frame_len < OPUS_PACKET_PAD) {
                int target_length = frame_payload;
                int ret = opus_packet_pad(output_frame, frame_len, target_length);
                if (ret < 0) {
                    return -1;
                }
                frame_len = target_length;
            }
            
            // Update granule position
            ctx->ogg_granule_position += OPUS_FRAME_SIZE;
            
            // Create OGG packet
            ogg_packet op;
            op.packet = output_frame;
            op.bytes = frame_len;
            op.b_o_s = 0;
            op.e_o_s = 0;
            op.granulepos = ctx->ogg_granule_position;
            op.packetno = ctx->ogg_packet_count++;
            
            int ret = ogg_stream_packetin(&ctx->os, &op);
            if (ret != 0) {
            }
            
            // Write OGG pages
            ogg_page og;
            while (ogg_stream_pageout(&ctx->os, &og)) {
                buffer_write(ctx, og.header, og.header_len);
                buffer_write(ctx, og.body, og.body_len);
                ctx->taf_block_num++;
            }
            
            // Reset frame buffer
            ctx->audio_frame_used = 0;
        }
    }
    
    return 0;
}

/**
 * Add a new chapter marker
 * @param ctx Encoder context
 * @return 0 on success, -1 on error
 */
EMSCRIPTEN_KEEPALIVE
int taf_encoder_new_chapter(taf_encoder_t *ctx) {
    if (!ctx || ctx->taf.n_track_page_nums >= TONIEFILE_MAX_CHAPTERS - 1) {
        return -1;
    }
    
    ctx->taf.track_page_nums[ctx->taf.n_track_page_nums++] = ctx->taf_block_num;
    return 0;
}

/**
 * Finalize encoding and write TAF header
 * @param ctx Encoder context
 * @return 0 on success, -1 on error
 */
EMSCRIPTEN_KEEPALIVE
int taf_encoder_finalize(taf_encoder_t *ctx) {
    //printf("taf_encoder_finalize: ctx=%p\n", ctx);
    if (!ctx) {
        return -1;
    }
    
    // Flush any remaining OGG pages
    ogg_page og;
    while (ogg_stream_flush(&ctx->os, &og)) {
        buffer_write(ctx, og.header, og.header_len);
        buffer_write(ctx, og.body, og.body_len);
    }
    
    // Ensure total file size is NOT a multiple of 4096
    // If it is, add a silent OGG page. This matches 'teddy' behavior.
    if (ctx->output_size % 4096 == 0) {
        //printf("taf_encoder_finalize: Output aligned to 4096, adding silence page\n");
        int16_t silence[OPUS_FRAME_SIZE * OPUS_CHANNELS];
        memset(silence, 0, sizeof(silence));
        unsigned char output_frame[TONIEFILE_FRAME_SIZE];
        
        int frame_len = opus_encode(ctx->enc, silence, OPUS_FRAME_SIZE, output_frame, sizeof(output_frame));
        
        if (frame_len > 0) {
            ogg_packet op;
            op.packet = output_frame;
            op.bytes = frame_len;
            op.b_o_s = 0;
            op.e_o_s = 1; // Mark as EOS
            
            ctx->ogg_granule_position += OPUS_FRAME_SIZE;
            op.granulepos = ctx->ogg_granule_position;
            op.packetno = ctx->ogg_packet_count++;
            
            ogg_stream_packetin(&ctx->os, &op);
            
            while (ogg_stream_flush(&ctx->os, &og)) {
                buffer_write(ctx, og.header, og.header_len);
                buffer_write(ctx, og.body, og.body_len);
            }
        }
    }
    
    // Finalize SHA1 - use stack allocation
    uint8_t sha1_hash[SHA1_DIGEST_SIZE];
    sha1Final(&ctx->sha1, sha1_hash);
    
    // Update TAF header - point to stack buffer temporarily for encoding
    ctx->taf.sha1_hash.data = sha1_hash;
    ctx->taf.sha1_hash.len = SHA1_DIGEST_SIZE;
    ctx->taf.num_bytes = ctx->audio_length;
    ctx->taf.ogg_granule_position = ctx->ogg_granule_position;
    ctx->taf.ogg_packet_count = ctx->ogg_packet_count;
    ctx->taf.taf_block_num = ctx->taf_block_num;
    ctx->taf.pageno = ctx->os.pageno;
    ctx->taf.has_ogg_granule_position = true;
    ctx->taf.has_ogg_packet_count = true;
    ctx->taf.has_taf_block_num = true;
    ctx->taf.has_pageno = true;

    uint16_t proto_frame_size = TONIEFILE_FRAME_SIZE - 4;
    ctx->taf._fill.len = proto_frame_size;
    ctx->taf._fill.data = malloc(ctx->taf._fill.len);
    memset(ctx->taf._fill.data, 0, ctx->taf._fill.len);

    size_t data_size = toniebox_audio_file_header__get_packed_size(&ctx->taf);
    ctx->taf._fill.len = ctx->taf._fill.len  + (proto_frame_size - data_size);
    data_size = toniebox_audio_file_header__get_packed_size(&ctx->taf);
    if (data_size == proto_frame_size + 1) {
        ctx->taf._fill.len--;
    }
    
    // Encode TAF header
    uint8_t header_buffer[TONIEFILE_FRAME_SIZE];
    memset(header_buffer, 0, sizeof(header_buffer));
    uint32_t proto_size = (uint32_t)encode_taf_header(header_buffer, sizeof(header_buffer), &ctx->taf);
    
    // Clear the pointer after encoding (it was pointing to stack)
    ctx->taf.sha1_hash.data = NULL;
    ctx->taf.sha1_hash.len = 0;

    free(ctx->taf._fill.data);
    ctx->taf._fill.data = NULL;
    
    // Write header size (big-endian)
    uint8_t proto_be[4];
    proto_be[0] = proto_size >> 24;
    proto_be[1] = proto_size >> 16;
    proto_be[2] = proto_size >> 8;
    proto_be[3] = proto_size;
    
    buffer_write_at(ctx, 0, proto_be, sizeof(proto_be));
    buffer_write_at(ctx, 4, header_buffer, proto_size);
    
    //printf("taf_encoder_finalize: done\n");
    return 0;
}

/**
 * Get pointer to encoded TAF data
 * @param ctx Encoder context
 * @return Pointer to TAF data in WASM memory
 */
EMSCRIPTEN_KEEPALIVE
uint8_t *taf_encoder_get_buffer(taf_encoder_t *ctx) {
    return ctx ? ctx->output_buffer : NULL;
}

/**
 * Get size of encoded TAF data
 * @param ctx Encoder context
 * @return Size in bytes
 */
EMSCRIPTEN_KEEPALIVE
uint32_t taf_encoder_get_size(taf_encoder_t *ctx) {
    return ctx ? (uint32_t)ctx->output_size : 0;
}

/**
 * Free encoder and all resources
 * @param ctx Encoder context
 */
EMSCRIPTEN_KEEPALIVE
void taf_encoder_free(taf_encoder_t *ctx) {
    if (ctx) {
        //printf("taf_encoder_free: ctx=%p\n", ctx);
        if (ctx->enc) {
            //printf("taf_encoder_destroy: freeing enc\n");
            opus_encoder_destroy(ctx->enc);
        }
        //printf("taf_encoder_destroy: clearing os\n");
        ogg_stream_clear(&ctx->os);
        if (ctx->taf.track_page_nums) {
            //printf("taf_encoder_destroy: freeing taf.track_page_nums\n");
            free(ctx->taf.track_page_nums);
        }
        if (ctx->output_buffer) {
            //printf("taf_encoder_destroy: freeing output_buffer\n");
            free(ctx->output_buffer);
        }
        //printf("taf_encoder_destroy: freeing ctx\n");
        free(ctx);
        ctx = NULL;
    }
}
