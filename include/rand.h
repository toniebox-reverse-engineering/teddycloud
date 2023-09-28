#pragma once

#include "rng/yarrow.h"

#include "error.h"

error_t rand_init();
error_t rand_deinit();

void *rand_get_context();
const PrngAlgo *rand_get_algo();
