#include "json_helper.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

static bool_t jsonParseUInt32String(const char *text, uint32_t *value)
{
    if (text == NULL || value == NULL)
    {
        return false;
    }

    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n')
    {
        text++;
    }

    if (*text == '\0' || *text == '-' || *text == '+')
    {
        return false;
    }

    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 10);
    if (end == text || errno == ERANGE || parsed > UINT32_MAX)
    {
        return false;
    }

    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
    {
        end++;
    }

    if (*end != '\0')
    {
        return false;
    }

    *value = (uint32_t)parsed;
    return true;
}

char *jsonGetString(cJSON *jsonElement, char *name)
{
    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsString(attr))
    {
        return strdup(attr->valuestring);
    }
    return strdup("");
}

cJSON *jsonAddStringToObject(cJSON *const object, const char *const name, const char *const string)
{
    if (string != NULL)
    {
        return cJSON_AddStringToObject(object, name, string);
    }
    return cJSON_AddStringToObject(object, name, "");
}

uint8_t *jsonGetBytes(cJSON *jsonElement, char *name, size_t *length)
{
    char *text = jsonGetString(jsonElement, name);
    uint8_t *bytes = NULL;
    size_t textLen = osStrlen(text);
    size_t byteLen = textLen / 2;

    *length = 0;
    if (byteLen > 0)
    {
        bytes = osAllocMem(byteLen);
        for (size_t i = 0; i < byteLen; i++)
        {
            sscanf(&text[i * 2], "%02hhx", &bytes[i]);
        }
        *length = byteLen;
    }

    osFreeMem(text);

    return bytes;
}

cJSON *jsonAddByteArrayToObject(cJSON *const object, const char *const name, uint8_t *bytes, size_t bytes_len)
{
    size_t string_len = bytes_len * 2 + 1;
    char *string = osAllocMem(string_len);
    string[string_len - 1] = '\0';

    for (size_t i = 0; i < bytes_len; i++)
    {
        sprintf(&string[i * 2], "%02hhx", bytes[i]);
    }

    // temporary object is needed, so we can free string, because of lack of RAII
    cJSON *tmpObject = cJSON_AddStringToObject(object, name, string);
    osFreeMem(string);
    return tmpObject;
}

bool_t jsonGetBool(cJSON *jsonElement, char *name)
{
    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsBool(attr))
    {
        return attr->valueint;
    }
    return false;
}

uint32_t jsonGetUInt32(cJSON *jsonElement, char *name)
{
    cJSON *attr = cJSON_GetObjectItemCaseSensitive(jsonElement, name);
    if (cJSON_IsNumber(attr))
    {
        return attr->valuedouble;
    }
    if (cJSON_IsString(attr))
    {
        uint32_t value;
        if (jsonParseUInt32String(attr->valuestring, &value))
        {
            return value;
        }
    }
    return 0;
}
