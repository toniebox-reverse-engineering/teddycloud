#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "str_ext.h"

size_t hexEncode(const uint8_t *data, size_t len, char *output, size_t output_size)
{
    size_t i = 0;
    for (; i < len && (i + 1) * 2 < output_size; i++)
    {
        sprintf(&output[i * 2], "%02X", data[i]);
    }
    output[i * 2] = '\0';
    return i;
}

size_t escapeString(const char *input, size_t size, char *output, size_t output_size)
{
    // Replacement sequences for special characters
    const char *replacements[] = {
        "\"", "\"\"", // Double quote (")
        "\n", "\\n",  // Newline
        "\r", "\\r"   // Carriage return
    };
    const size_t num_replacements = sizeof(replacements) / sizeof(replacements[0]);

    size_t i = 0;
    size_t j = 0;
    // a character expands to at most 2 bytes
    for (; i < size && j + 2 < output_size; i++)
    {
        bool replaced = false;
        for (size_t k = 0; k < num_replacements; k += 2)
        {
            if (input[i] == replacements[k][0])
            {
                size_t len = strlen(replacements[k + 1]);
                memcpy(&output[j], replacements[k + 1], len);
                j += len;
                replaced = true;
                break;
            }
        }

        if (!replaced)
        {
            output[j++] = isalnum((unsigned char)input[i]) ? input[i] : '.';
        }
    }

    // Null-terminate the escaped string
    output[j] = '\0';
    return i;
}

bool split_url(const char *location, char *uri_base, char *uri_path, char *query_string, size_t buf_size)
{
    if (buf_size == 0)
    {
        return false;
    }

    const char *scheme_end = strstr(location, "://");
    if (!scheme_end)
    {
        return false;
    }
    // Move pointer to start after "://"
    scheme_end += 3;

    const char *path_start = strchr(scheme_end, '/');
    if (!path_start)
    {
        return false;
    }
    const char *query_start = strchr(path_start, '?');

    // Base URI without scheme
    size_t base_len = path_start - scheme_end;
    // Path runs up to the query string (if any) or the end of the location
    size_t path_len = query_start ? (size_t)(query_start - path_start) : strlen(path_start);
    // Query string follows the '?'
    size_t query_len = query_start ? strlen(query_start + 1) : 0;

    if (base_len >= buf_size || path_len >= buf_size || query_len >= buf_size)
    {
        return false;
    }

    memcpy(uri_base, scheme_end, base_len);
    uri_base[base_len] = '\0';

    memcpy(uri_path, path_start, path_len);
    uri_path[path_len] = '\0';

    if (query_len > 0)
    {
        memcpy(query_string, query_start + 1, query_len);
    }
    query_string[query_len] = '\0';

    return true;
}
