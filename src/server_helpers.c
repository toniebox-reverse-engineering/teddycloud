
#include <string.h>
#include <stdarg.h>

#include "os_port.h"
#include "server_helpers.h"

char *custom_asprintf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    // Calculate the length of the final string
    va_list tmp_args;
    va_copy(tmp_args, args);
    int length = osVsnprintf(NULL, 0, fmt, tmp_args);
    va_end(tmp_args);

    if (length < 0)
    {
        return NULL;
    }

    // Allocate memory for the new string
    char *new_str = osAllocMem(length + 1); // Add 1 for the null terminator
    if (new_str == NULL)
    {
        return NULL;
    }

    // Format the new string
    osVsnprintf(new_str, length + 1, fmt, args);

    va_end(args);

    return new_str;
}

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

char_t *ipv4AddrToString(Ipv4Addr ipAddr, char_t *str)
{
    uint8_t *p;
    static char_t buffer[16];

    // If the NULL pointer is given as parameter, then the internal buffer is used
    if (str == NULL)
        str = buffer;

    // Cast the address to byte array
    p = (uint8_t *)&ipAddr;
    // Format IPv4 address
    osSprintf(str, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "", p[0], p[1], p[2], p[3]);

    // Return a pointer to the formatted string
    return str;
}

char_t *ipv6AddrToString(const Ipv6Addr *ipAddr, char_t *str)
{
    static char_t buffer[40];
    uint_t i;
    uint_t j;
    char_t *p;

    // Best run of zeroes
    uint_t zeroRunStart = 0;
    uint_t zeroRunEnd = 0;

    // If the NULL pointer is given as parameter, then the internal buffer is used
    if (str == NULL)
        str = buffer;

    // Find the longest run of zeros for "::" short-handing
    for (i = 0; i < 8; i++)
    {
        // Compute the length of the current sequence of zeroes
        for (j = i; j < 8 && !ipAddr->w[j]; j++)
            ;

        // Keep track of the longest one
        if ((j - i) > 1 && (j - i) > (zeroRunEnd - zeroRunStart))
        {
            // The symbol "::" should not be used to shorten just one zero field
            zeroRunStart = i;
            zeroRunEnd = j;
        }
    }

    // Format IPv6 address
    for (p = str, i = 0; i < 8; i++)
    {
        // Are we inside the best run of zeroes?
        if (i >= zeroRunStart && i < zeroRunEnd)
        {
            // Append a separator
            *(p++) = ':';
            // Skip the sequence of zeroes
            i = zeroRunEnd - 1;
        }
        else
        {
            // Add a separator between each 16-bit word
            if (i > 0)
                *(p++) = ':';

            // Convert the current 16-bit word to string
            p += osSprintf(p, "%" PRIx16, ntohs(ipAddr->w[i]));
        }
    }

    // A trailing run of zeroes has been found?
    if (zeroRunEnd == 8)
        *(p++) = ':';

    // Properly terminate the string
    *p = '\0';

    // Return a pointer to the formatted string
    return str;
}

char_t *ipAddrToString(const IpAddr *ipAddr, char_t *str)
{
#if (IPV4_SUPPORT == ENABLED)
    // IPv4 address?
    if (ipAddr->length == sizeof(Ipv4Addr))
    {
        // Convert IPv4 address to string representation
        return ipv4AddrToString(ipAddr->ipv4Addr, str);
    }
    else
#endif
#if (IPV6_SUPPORT == ENABLED)
        // IPv6 address?
        if (ipAddr->length == sizeof(Ipv6Addr))
        {
            // Convert IPv6 address to string representation
            return ipv6AddrToString(&ipAddr->ipv6Addr, str);
        }
        else
#endif
        // Invalid IP address?
        {
            static char_t c;

            // The last parameter is optional
            if (str == NULL)
            {
                str = &c;
            }

            // Properly terminate the string
            str[0] = '\0';

            // Return an empty string
            return str;
        }
}

void time_format(time_t time, char_t *buffer)
{
    DateTime dateTime;

    convertUnixTimeToDate(time, &dateTime);

    osSprintf(buffer, "%04" PRIu16 "-%02" PRIu8 "-%02" PRIu8 "T%02" PRIu8 ":%02" PRIu8 ":%02" PRIu8 "Z",
              dateTime.year, dateTime.month, dateTime.day, dateTime.hours, dateTime.minutes,
              dateTime.seconds);
}

void time_format_current(char_t *buffer)
{
    time_t time = getCurrentUnixTime();

    time_format(time, buffer);
}