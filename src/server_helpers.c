
#include <string.h>
#include "os_port.h"
#include "server_helpers.h"

int urldecode(char *dest, const char *src)
{
    char a, b;
    while (*src)
    {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b)))
        {
            if (a >= 'a')
                a -= 'a' - 'A';
            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a' - 'A';
            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';
            *dest++ = 16 * a + b;
            src += 3;
        }
        else if (*src == '+')
        {
            *dest++ = ' ';
            src++;
        }
        else
        {
            *dest++ = *src++;
        }
    }
    *dest++ = '\0';
    return dest - src;
}

bool queryGet(const char *query, const char *key, char *data, size_t data_len)
{
    const char *q = query;
    size_t key_len = osStrlen(key);
    while ((q = strstr(q, key)))
    {
        if (q[key_len] == '=')
        {
            // Found the key, let's start copying the value
            q += key_len + 1;  // Skip past the key and the '='
            char buffer[1024]; // Temporary buffer for decoding
            char *b = buffer;
            while (*q && *q != '&')
            {
                if (b - buffer < sizeof(buffer) - 1)
                { // Prevent buffer overflow
                    *b++ = *q++;
                }
                else
                {
                    // The value is too long, truncate it
                    break;
                }
            }
            *b = '\0';               // Null-terminate the buffer
            urldecode(data, buffer); // Decode and copy the value
            return true;
        }
        q += key_len; // Skip past the key
    }
    return false; // Key not found
}
