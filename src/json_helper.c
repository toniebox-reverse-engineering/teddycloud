#include "json_helper.h"

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

    return cJSON_AddStringToObject(object, name, string);
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
    return 0;
}
