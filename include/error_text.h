#pragma once

#include "error.h"

char *error2text(error_t error);
void error_text_init();
const char *httpstatus2text(error_t error);
