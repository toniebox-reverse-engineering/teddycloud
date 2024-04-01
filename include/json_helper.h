#pragma once

#include "cJSON.h"
#include "debug.h"

char *jsonGetString(cJSON *jsonElement, char *name);
cJSON *jsonAddStringToObject(cJSON *const object, const char *const name, const char *const string);
uint8_t *jsonGetBytes(cJSON *jsonElement, char *name, size_t *length);
cJSON *jsonAddByteArrayToObject(cJSON *const object, const char *const name, uint8_t *bytes, size_t bytes_len);
bool_t jsonGetBool(cJSON *jsonElement, char *name);
uint32_t jsonGetUInt32(cJSON *jsonElement, char *name);
