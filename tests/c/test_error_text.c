#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "error_text.h"
#include "tests.h"

void test_error_text(void)
{
    error_text_init();

    assert(strcmp(error2text(NO_ERROR), "Success [0]") == 0);
    assert(strcmp(error2text(ERROR_OUT_OF_MEMORY), "Out of memory [100]") == 0);

    /* the number in the text comes from the enum, so the texts stay right when Cyclone renumbers codes */
    static const error_t samples[] = {ERROR_FAILURE, ERROR_ABORTED, ERROR_OUT_OF_MEMORY, ERROR_INVALID_ELLIPTIC_CURVE,
                                      ERROR_CERTIFICATE_EXPIRED, ERROR_PARTIAL_MATCH};
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++)
    {
        char suffix[16];
        snprintf(suffix, sizeof(suffix), "[%d]", (int)samples[i]);
        const char *text = error2text(samples[i]);
        assert(strlen(text) > strlen(suffix));
        assert(strcmp(text + strlen(text) - strlen(suffix), suffix) == 0);
    }

    /* unknown and out-of-range codes give an empty string instead of reading out of bounds */
    assert(strcmp(error2text((error_t)-1), "") == 0);
    assert(strcmp(error2text((error_t)100000), "") == 0);

    assert(strcmp(httpstatus2text(206), "Partial Content") == 0);
    assert(strcmp(httpstatus2text(404), "Not Found") == 0);
    assert(strcmp(httpstatus2text(999), "Unknown HTTP Status Code") == 0);
}
