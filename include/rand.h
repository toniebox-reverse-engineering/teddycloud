#pragma once

#include <stddef.h>

#include "rng/yarrow.h"

#include "error.h"

error_t rand_init();
error_t rand_deinit();

void *rand_get_context();
const PrngAlgo *rand_get_algo();
int rand_get_bytes(void *buf, size_t buflen);
