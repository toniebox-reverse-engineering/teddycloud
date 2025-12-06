/**
 * @file toniefile_encoder.c
 * @brief WebAssembly wrapper for toniefile encoding
 * 
 * This file provides a JavaScript-callable interface to the toniefile
 * encoding functionality. It uses the fs_port_wasm.c wrapper to provide
 * memory-based file I/O.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <emscripten.h>

// Forward declarations from cyclone
typedef int error_t;
typedef int bool_t;
typedef char char_t;
typedef int int_t;
typedef unsigned int uint_t;

#define NO_ERROR 0
#define TRUE 1
#define FALSE 0

// FsFile structure definition (must match fs_port_wasm.c)
struct FsFile {
    uint8_t *buffer;
    size_t buffer_size;
    size_t buffer_capacity;
    size_t position;
    bool is_open;
    bool is_writable;
};
typedef struct FsFile FsFile;

// Forward declare toniefile_t (opaque pointer)
typedef struct toniefile_s toniefile_t;

// Declare only the functions we need from toniefile.c
toniefile_t *toniefile_create(const char *path, uint32_t audio_id, bool_t ogg_stream, uint32_t bitrate);
error_t toniefile_encode(toniefile_t *ctx, int16_t *sample_buffer, size_t samples_available);
error_t toniefile_new_chapter(toniefile_t *ctx);
error_t toniefile_close(toniefile_t *ctx);

// Global encoder context
static toniefile_t *g_encoder = NULL;
static FsFile *g_output_file = NULL;
static const char *WASM_OUTPUT_PATH = "/output.taf";

/**
 * Initialize the encoder
 * @param audio_id Audio ID for the TAF file (typically Unix timestamp - 0x50000000)
 * @return 0 on success, -1 on error
 */
EMSCRIPTEN_KEEPALIVE
int encoder_init(uint32_t audio_id) {
    if (g_encoder != NULL) {
        return -1; // Already initialized
    }
    
    // Create toniefile encoder
    // The path is ignored by our WASM fs wrapper, but we pass it for compatibility
    g_encoder = toniefile_create(WASM_OUTPUT_PATH, audio_id, false, 0);
    
    if (g_encoder == NULL) {
        return -1;
    }
    
    return 0;
}

/**
 * Add PCM samples to encode
 * @param pcm_data Pointer to PCM data (int16_t samples, interleaved stereo)
 * @param num_samples Number of sample frames (each frame = 2 channels)
 * @return 0 on success, -1 on error
 */
EMSCRIPTEN_KEEPALIVE
int encoder_add_samples(int16_t *pcm_data, uint32_t num_samples) {
    if (g_encoder == NULL) {
        return -1;
    }
    
    // Use existing toniefile_encode function
    error_t err = toniefile_encode(g_encoder, pcm_data, num_samples);
    
    return (err == NO_ERROR) ? 0 : -1;
}

/**
 * Start a new chapter
 * @return 0 on success, -1 on error
 */
EMSCRIPTEN_KEEPALIVE
int encoder_new_chapter() {
    if (g_encoder == NULL) {
        return -1;
    }
    
    error_t err = toniefile_new_chapter(g_encoder);
    
    return (err == NO_ERROR) ? 0 : -1;
}

/**
 * Finalize encoding
 * @return 0 on success, -1 on error
 */
EMSCRIPTEN_KEEPALIVE
int encoder_finalize() {
    if (g_encoder == NULL) {
        return -1;
    }
    
    // Close the toniefile (finalizes encoding)
    error_t err = toniefile_close(g_encoder);
    g_encoder = NULL;
    
    return (err == NO_ERROR) ? 0 : -1;
}

/**
 * Get pointer to the encoded TAF data
 * Must be called after encoder_finalize()
 * @return Pointer to TAF data buffer
 */
EMSCRIPTEN_KEEPALIVE
uint8_t* encoder_get_buffer() {
    if (g_output_file == NULL || !g_output_file->buffer) {
        return NULL;
    }
    
    return g_output_file->buffer;
}

/**
 * Get the size of the encoded TAF data
 * Must be called after encoder_finalize()
 * @return Size in bytes
 */
EMSCRIPTEN_KEEPALIVE
uint32_t encoder_get_size() {
    if (g_output_file == NULL) {
        return 0;
    }
    
    return (uint32_t)g_output_file->buffer_size;
}

/**
 * Free encoder resources
 * Call this after you've copied the buffer data
 */
EMSCRIPTEN_KEEPALIVE
void encoder_free() {
    if (g_output_file) {
        if (g_output_file->buffer) {
            free(g_output_file->buffer);
            g_output_file->buffer = NULL;
        }
        free(g_output_file);
        g_output_file = NULL;
    }
    
    g_encoder = NULL;
}

/**
 * Get the global output file (used internally by fs_port_wasm.c)
 * This is called by fsOpenFile to get the output buffer
 */
FsFile* _get_output_file() {
    if (g_output_file == NULL) {
        g_output_file = (FsFile*)malloc(sizeof(FsFile));
        if (g_output_file) {
            // Allocate initial buffer (10MB)
            g_output_file->buffer_capacity = 10 * 1024 * 1024;
            g_output_file->buffer = (uint8_t*)malloc(g_output_file->buffer_capacity);
            g_output_file->buffer_size = 0;
            g_output_file->position = 0;
            g_output_file->is_open = true;
            g_output_file->is_writable = true;
        }
    }
    return g_output_file;
}
