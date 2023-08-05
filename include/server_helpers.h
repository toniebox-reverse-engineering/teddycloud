#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

int urldecode(char *dest, const char *src);
bool queryGet(const char *query, const char *key, char *data, size_t data_len);
