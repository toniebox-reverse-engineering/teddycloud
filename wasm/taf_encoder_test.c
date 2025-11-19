#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Forward declarations from taf_encoder_minimal.c
typedef struct taf_encoder_t taf_encoder_t;

taf_encoder_t* taf_encoder_create(uint32_t audio_id, int bitrate);
int taf_encoder_encode(taf_encoder_t *ctx, const int16_t *pcm, uint32_t samples);
int taf_encoder_new_chapter(taf_encoder_t *ctx);
int taf_encoder_finalize(taf_encoder_t *ctx);
uint8_t* taf_encoder_get_buffer(taf_encoder_t *ctx);
uint32_t taf_encoder_get_size(taf_encoder_t *ctx);
void taf_encoder_free(taf_encoder_t *ctx);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input.raw> <output.taf>\n", argv[0]);
        fprintf(stderr, "  input.raw: 16-bit signed PCM, 48kHz, mono\n");
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];

    // Open input file
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        return 1;
    }

    // Get file size
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    printf("Input file size: %ld bytes\n", file_size);

    // Create encoder
    printf("Creating encoder...\n");
    taf_encoder_t *encoder = taf_encoder_create(12345678, 96);
    if (!encoder) {
        fprintf(stderr, "Error: Failed to create encoder\n");
        fclose(in);
        return 1;
    }

    // Read and encode in chunks
    const size_t chunk_frames = 48000; // 1 second at 48kHz
    const size_t channels = 2;
    int16_t *buffer = (int16_t *)malloc(chunk_frames * channels * sizeof(int16_t));
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate buffer\n");
        taf_encoder_free(encoder);
        fclose(in);
        return 1;
    }

    size_t total_frames = 0;
    while (!feof(in)) {
        size_t items_read = fread(buffer, sizeof(int16_t), chunk_frames * channels, in);
        size_t frames_read = items_read / channels;
        
        if (frames_read == 0) {
            break;
        }

        //printf("Encoding %zu frames...\n", frames_read);
        if (taf_encoder_encode(encoder, buffer, frames_read) != 0) {
            fprintf(stderr, "Error: Encoding failed\n");
            free(buffer);
            taf_encoder_free(encoder);
            fclose(in);
            return 1;
        }

        total_frames += frames_read;
    }

    free(buffer);
    fclose(in);

    printf("Total frames encoded: %zu\n", total_frames);

    // Finalize
    printf("Finalizing...\n");
    if (taf_encoder_finalize(encoder) != 0) {
        fprintf(stderr, "Error: Finalization failed\n");
        taf_encoder_free(encoder);
        return 1;
    }

    // Get output
    uint8_t *output = taf_encoder_get_buffer(encoder);
    if (!output) {
        fprintf(stderr, "Error: Failed to get output\n");
        taf_encoder_free(encoder);
        return 1;
    }
    
    uint32_t output_size = taf_encoder_get_size(encoder);
    printf("Output size: %u bytes\n", output_size);

    // Write output file
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Error: Cannot open output file: %s\n", output_file);
        taf_encoder_free(encoder);
        return 1;
    }

    size_t written = fwrite(output, 1, output_size, out);
    fclose(out);

    if (written != output_size) {
        fprintf(stderr, "Error: Failed to write complete output\n");
        taf_encoder_free(encoder);
        return 1;
    }

    printf("Successfully wrote %zu bytes to %s\n", written, output_file);

    // Cleanup
    taf_encoder_free(encoder);

    return 0;
}
