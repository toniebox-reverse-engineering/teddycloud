#include <assert.h>
#include <string.h>

#include "error_text.h"
#include "tests.h"

void test_error_text(void)
{
    error_text_init();

    assert(strcmp(error2text(NO_ERROR), "Success [0]") == 0);
    assert(strcmp(error2text(ERROR_OUT_OF_MEMORY), "Out of memory [100]") == 0);

    /* unknown and out-of-range codes give an empty string instead of reading out of bounds */
    assert(strcmp(error2text((error_t)-1), "") == 0);
    assert(strcmp(error2text((error_t)100000), "") == 0);

    assert(strcmp(httpstatus2text(206), "Partial Content") == 0);
    assert(strcmp(httpstatus2text(404), "Not Found") == 0);
    assert(strcmp(httpstatus2text(999), "Unknown HTTP Status Code") == 0);
}
