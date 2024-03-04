
#include <string.h>
#include <stdarg.h>

#include "os_port.h"
#include "debug.h"
#include "server_helpers.h"
#include "http/http_server_misc.h"

typedef enum
{
    PARSE_HEADER,
    PARSE_FILENAME,
    PARSE_BODY
} eMultipartState;

/* multipart receive buffer */
#define DATA_SIZE 1024
#define SAVE_SIZE 80
#define BUFFER_SIZE (DATA_SIZE + SAVE_SIZE)

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
#include <ctype.h> // for isxdigit

int urldecode(char *dest, size_t dest_max, const char *src)
{
    char a, b;
    size_t dest_idx = 0;
    size_t src_idx = 0;

    while (src[src_idx] && dest_idx < dest_max - 1)
    {
        if ((src[src_idx] == '%') &&
            ((a = src[src_idx + 1]) && (b = src[src_idx + 2])) &&
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

            dest[dest_idx++] = 16 * a + b;
            src_idx += 3;
        }
        else if (src[src_idx] == '+')
        {
            dest[dest_idx++] = ' ';
            src_idx++;
        }
        else
        {
            dest[dest_idx++] = src[src_idx++];
        }
    }
    dest[dest_idx] = '\0';

    return dest_idx;
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
            *b = '\0';                         // Null-terminate the buffer
            urldecode(data, data_len, buffer); // Decode and copy the value
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

static int find_string(const void *haystack, size_t haystack_len, size_t haystack_start, const char *str)
{
    size_t str_len = osStrlen(str);

    if (str_len > haystack_len)
    {
        return -1;
    }

    for (size_t i = haystack_start; i <= haystack_len - str_len; i++)
    {
        if (osMemcmp((uint8_t *)haystack + i, str, str_len) == 0)
        {
            return i;
        }
    }

    return -1;
}

error_t multipart_get_field(const char *buffer, size_t buffer_size, const char *field, char *result, size_t result_max)
{
    char *start_match = custom_asprintf("%s=\"", field);

    int fn_start = find_string(buffer, buffer_size, 0, start_match);
    if (fn_start < 0)
    {
        osFreeMem(start_match);
        return ERROR_FAILURE;
    }

    fn_start += osStrlen(start_match);
    osFreeMem(start_match);

    int fn_end = find_string(buffer, buffer_size, fn_start, "\"");
    if (fn_end < 0)
    {
        return ERROR_FAILURE;
    }

    int inLen = fn_end - fn_start;
    int len = (inLen < result_max) ? inLen : (result_max - 1);
    osStrncpy(result, &buffer[fn_start], len);
    result[len] = '\0';

    return NO_ERROR;
}

error_t multipart_handle(HttpConnection *connection, multipart_cbr_t *cbr, void *multipart_ctx)
{
    char buffer[2 * BUFFER_SIZE];
    char form_name[256];
    char form_filename[256];
    eMultipartState state = PARSE_HEADER;
    char *boundary = connection->request.boundary;

    size_t leftover = 0;
    bool fetch = true;
    int save_start = 0;
    int save_end = 0;
    int payload_size = 0;

    do
    {
        if (!payload_size)
        {
            fetch = true;
        }

        payload_size = leftover;
        if (fetch)
        {
            size_t packet_size;
            error_t error = httpReceive(connection, &buffer[leftover], DATA_SIZE - leftover, &packet_size, SOCKET_FLAG_DONT_WAIT);
            if (error != NO_ERROR)
            {
                TRACE_ERROR("httpReceive failed with error %d\r\n", error);
                return error;
            }

            save_start = 0;
            payload_size = leftover + packet_size;
            save_end = payload_size;

            fetch = false;
        }

        switch (state)
        {
        case PARSE_HEADER:
        {
            /* when the payload starts with boundary, its a valid payload */
            int boundary_start = find_string(buffer, payload_size, 0, boundary);
            if (boundary_start < 0)
            {
                /* if not, check for newlines that preceed */
                int data_end = find_string(buffer, payload_size, 0, "\r\n");
                if (data_end >= 0)
                {
                    /* when found, start from there, after the newline */
                    save_start = data_end + 2;
                    save_end = payload_size;
                }
                else
                {
                    /* if not, drop most of the buffer, keeping the last few bytes */
                    save_start = (payload_size > SAVE_SIZE) ? payload_size - SAVE_SIZE : 0;
                    save_end = payload_size;
                }
            }
            else
            {
                save_start = boundary_start + osStrlen(boundary);
                save_end = payload_size;
                state = PARSE_FILENAME;
            }
            break;
        }

        case PARSE_FILENAME:
        {
            if (payload_size < 3)
            {
                save_start = 0;
                save_end = payload_size;
                fetch = true;
                break;
            }

            /* when the payload starts with --, then leave */
            if (!osMemcmp(buffer, "--", 2))
            {
                TRACE_DEBUG("Received multipart end\r\n");
                return NO_ERROR;
            }
            if (osMemcmp(buffer, "\r\n", 2))
            {
                TRACE_DEBUG("No valid multipart\r\n");
                return NO_ERROR;
            }

            if (multipart_get_field(buffer, payload_size, "name", form_name, sizeof(form_name)) != NO_ERROR)
            {
                TRACE_DEBUG("No name found, retrying\r\n");
                save_start = 0;
                save_end = payload_size;
                fetch = true;
                break;
            }
            if (multipart_get_field(buffer, payload_size, "filename", form_filename, sizeof(form_filename)) != NO_ERROR)
            {
                TRACE_DEBUG("No filename found, retrying\r\n");
                save_start = 0;
                save_end = payload_size;
                fetch = true;
                break;
            }

            save_start = find_string(buffer, payload_size, 0, "\r\n\r\n");
            if (save_start < 0)
            {
                TRACE_DEBUG("no newlines found, reading next block\r\n");
                save_start = 0;
                save_end = payload_size;
                fetch = true;
                break;
            }

            if (cbr->multipart_start(multipart_ctx, form_name, form_filename) != NO_ERROR)
            {
                TRACE_ERROR("multipart_start failed\r\n");
                return ERROR_INVALID_PATH;
            }

            state = PARSE_BODY;
            save_start += 4;
            save_end = payload_size;
            break;
        }

        case PARSE_BODY:
        {
            if (!payload_size)
            {
                fetch = true;
                break;
            }

            int data_end = find_string(buffer, payload_size, 0, boundary);

            if (data_end >= 0)
            {
                /* We've found a boundary, let's finish up the current file, but skip the "--\r\n" */
                if (cbr->multipart_add(multipart_ctx, (uint8_t *)buffer, data_end - 4) != NO_ERROR)
                {
                    TRACE_ERROR("multipart_add failed\r\n");
                    return ERROR_FAILURE;
                }
                cbr->multipart_end(multipart_ctx);

                TRACE_INFO("Received file '%s'\r\n", form_filename);

                /* Prepare for next file */
                state = PARSE_HEADER;
                save_start = data_end;
                save_end = payload_size;
            }
            else
            {
                /* there is no full bounday end in this block, save the end and fetch next */
                fetch = true;

                if (payload_size <= SAVE_SIZE)
                {
                    save_start = 0;
                    save_end = payload_size;
                }
                else
                {
                    save_start = payload_size - SAVE_SIZE;
                    save_end = payload_size;
                    if (cbr->multipart_add(multipart_ctx, buffer, payload_size - SAVE_SIZE) != NO_ERROR)
                    {
                        TRACE_ERROR("multipart_add failed\r\n");
                        return ERROR_FAILURE;
                    }
                }
            }
        }
        break;
        }

        leftover = save_end - save_start;
        if (leftover > 0)
        {
            memmove(buffer, &buffer[save_start], leftover);
        }
    } while (payload_size > 0);

    return NO_ERROR;
}

/**
 * @brief Convert a dot-decimal string to a binary IPv4 address
 * @param[in] str NULL-terminated string representing the IPv4 address
 * @param[out] ipAddr Binary representation of the IPv4 address
 * @return Error code
 **/

error_t ipv4StringToAddr(const char_t *str, Ipv4Addr *ipAddr)
{
    error_t error;
    int_t i = 0;
    int_t value = -1;

    // Parse input string
    while (1)
    {
        // Decimal digit found?
        if (osIsdigit(*str))
        {
            // First digit to be decoded?
            if (value < 0)
                value = 0;

            // Update the value of the current byte
            value = (value * 10) + (*str - '0');

            // The resulting value shall be in range 0 to 255
            if (value > 255)
            {
                // The conversion failed
                error = ERROR_INVALID_SYNTAX;
                break;
            }
        }
        // Dot separator found?
        else if (*str == '.' && i < 4)
        {
            // Each dot must be preceded by a valid number
            if (value < 0)
            {
                // The conversion failed
                error = ERROR_INVALID_SYNTAX;
                break;
            }

            // Save the current byte
            ((uint8_t *)ipAddr)[i++] = value;
            // Prepare to decode the next byte
            value = -1;
        }
        // End of string detected?
        else if (*str == '\0' && i == 3)
        {
            // The NULL character must be preceded by a valid number
            if (value < 0)
            {
                // The conversion failed
                error = ERROR_INVALID_SYNTAX;
            }
            else
            {
                // Save the last byte of the IPv4 address
                ((uint8_t *)ipAddr)[i] = value;
                // The conversion succeeded
                error = NO_ERROR;
            }

            // We are done
            break;
        }
        // Invalid character...
        else
        {
            // The conversion failed
            error = ERROR_INVALID_SYNTAX;
            break;
        }

        // Point to the next character
        str++;
    }

    // Return status code
    return error;
}

/**
 * @brief Convert a string representation of an IPv6 address to a binary IPv6 address
 * @param[in] str NULL-terminated string representing the IPv6 address
 * @param[out] ipAddr Binary representation of the IPv6 address
 * @return Error code
 **/

error_t ipv6StringToAddr(const char_t *str, Ipv6Addr *ipAddr)
{
    error_t error;
    int_t i = 0;
    int_t j = -1;
    int_t k = 0;
    int32_t value = -1;

    // Parse input string
    while (1)
    {
        // Hexadecimal digit found?
        if (isxdigit((uint8_t)*str))
        {
            // First digit to be decoded?
            if (value < 0)
                value = 0;

            // Update the value of the current 16-bit word
            if (osIsdigit(*str))
            {
                value = (value * 16) + (*str - '0');
            }
            else if (osIsupper(*str))
            {
                value = (value * 16) + (*str - 'A' + 10);
            }
            else
            {
                value = (value * 16) + (*str - 'a' + 10);
            }

            // Check resulting value
            if (value > 0xFFFF)
            {
                // The conversion failed
                error = ERROR_INVALID_SYNTAX;
                break;
            }
        }
        //"::" symbol found?
        else if (!osStrncmp(str, "::", 2))
        {
            // The "::" can only appear once in an IPv6 address
            if (j >= 0)
            {
                // The conversion failed
                error = ERROR_INVALID_SYNTAX;
                break;
            }

            // The "::" symbol is preceded by a number?
            if (value >= 0)
            {
                // Save the current 16-bit word
                ipAddr->w[i++] = htons(value);
                // Prepare to decode the next 16-bit word
                value = -1;
            }

            // Save the position of the "::" symbol
            j = i;
            // Point to the next character
            str++;
        }
        //":" symbol found?
        else if (*str == ':' && i < 8)
        {
            // Each ":" must be preceded by a valid number
            if (value < 0)
            {
                // The conversion failed
                error = ERROR_INVALID_SYNTAX;
                break;
            }

            // Save the current 16-bit word
            ipAddr->w[i++] = htons(value);
            // Prepare to decode the next 16-bit word
            value = -1;
        }
        // End of string detected?
        else if (*str == '\0' && i == 7 && j < 0)
        {
            // The NULL character must be preceded by a valid number
            if (value < 0)
            {
                // The conversion failed
                error = ERROR_INVALID_SYNTAX;
            }
            else
            {
                // Save the last 16-bit word of the IPv6 address
                ipAddr->w[i] = htons(value);
                // The conversion succeeded
                error = NO_ERROR;
            }

            // We are done
            break;
        }
        else if (*str == '\0' && i < 7 && j >= 0)
        {
            // Save the last 16-bit word of the IPv6 address
            if (value >= 0)
                ipAddr->w[i++] = htons(value);

            // Move the part of the address that follows the "::" symbol
            for (k = 0; k < (i - j); k++)
            {
                ipAddr->w[7 - k] = ipAddr->w[i - 1 - k];
            }

            // A sequence of zeroes can now be written in place of "::"
            for (k = 0; k < (8 - i); k++)
            {
                ipAddr->w[j + k] = 0;
            }

            // The conversion succeeded
            error = NO_ERROR;
            break;
        }
        // Invalid character...
        else
        {
            // The conversion failed
            error = ERROR_INVALID_SYNTAX;
            break;
        }

        // Point to the next character
        str++;
    }

    // Return status code
    return error;
}

/**
 * @brief Convert a string representation of an IP address to a binary IP address
 * @param[in] str NULL-terminated string representing the IP address
 * @param[out] ipAddr Binary representation of the IP address
 * @return Error code
 **/

error_t ipStringToAddr(const char_t *str, IpAddr *ipAddr)
{
    error_t error;

#if (IPV6_SUPPORT == ENABLED)
    // IPv6 address?
    if (osStrchr(str, ':') != NULL)
    {
        // IPv6 addresses are 16-byte long
        ipAddr->length = sizeof(Ipv6Addr);
        // Convert the string to IPv6 address
        error = ipv6StringToAddr(str, &ipAddr->ipv6Addr);
    }
    else
#endif
#if (IPV4_SUPPORT == ENABLED)
        // IPv4 address?
        if (osStrchr(str, '.') != NULL)
        {
            // IPv4 addresses are 4-byte long
            ipAddr->length = sizeof(Ipv4Addr);
            // Convert the string to IPv4 address
            error = ipv4StringToAddr(str, &ipAddr->ipv4Addr);
        }
        else
#endif
        // Invalid IP address?
        {
            // Report an error
            error = ERROR_FAILURE;
        }

    // Return status code
    return error;
}


error_t httpServerUriNotFoundCallback(HttpConnection *connection, const char_t *uri)
{
    error_t error = NO_ERROR;

    error = httpSendErrorResponse(connection, 404,
                                  "The requested page could not be found");

    /*
    char_t *newUri = custom_asprintf("%s/404.html", get_settings()->core.wwwdir);
    error = httpSendResponse(connection, newUri);
    free(newUri);
    */

    return error;
}