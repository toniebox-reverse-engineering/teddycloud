
#include <stdint.h>

#include "fs_port.h"

#define OPUS_FRAME_SIZE_MS OPUS_FRAMESIZE_60_MS
#define OPUS_SAMPLING_RATE 48000
#define OPUS_BIT_RATE 96000
#define OPUS_FRAME_SIZE 2880 /* samples: 60ms at 48kHz */
#define OPUS_CHANNELS 2

#define TONIEFILE_FRAME_SIZE 4096

typedef struct toniefile_s toniefile_t;

toniefile_t *toniefile_create(const char *fullPath);
error_t toniefile_close(toniefile_t *ctx);
error_t toniefile_encode(toniefile_t *ctx, int16_t *sample_buffer, size_t samples_available);