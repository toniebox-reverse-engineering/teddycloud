#include <errno.h>

#ifndef WIN32
#include <sys/random.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "rng/yarrow.h"
#include "error.h"
#include "debug.h"
#include "rand.h"

YarrowContext yarrowContext;
bool rand_initialized = false;

void *rand_get_context()
{
    if (!rand_initialized)
    {
        rand_init();
        rand_initialized = true;
    }
    return &yarrowContext;
}

const PrngAlgo *rand_get_algo()
{
    return YARROW_PRNG_ALGO;
}

int rand_get_bytes(void *buf, size_t buflen)
{
#ifndef WIN32
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1)
    {
        TRACE_ERROR("Failed to open /dev/urandom");
        return -1;
    }

    ssize_t bytes_read = read(urandom_fd, buf, buflen);
    if (bytes_read == -1)
    {
        TRACE_ERROR("Failed to read from /dev/urandom");
        close(urandom_fd);
        return -1;
    }

    close(urandom_fd);
    return 0;
#else
    return -1;
#endif
}

error_t rand_init()
{
    uint8_t seed[32];

    int ret = getrandom(seed, sizeof(seed), 0);
    if (ret < 0)
    {
        if (errno == 38)
        {
            // Linux Kernel < 3.17
            TRACE_WARNING("Syscall getrandom not available, fallback to /dev/urandom (%d)\r\n", errno);
            ret = rand_get_bytes(seed, sizeof(seed));
            if (ret < 0)
            {
                TRACE_ERROR("Error: Failed to generate random data (%d)\r\n", errno);
                return ERROR_FAILURE;
            }
        }
        else
        {
            TRACE_ERROR("Error: Failed to generate random data (%d)\r\n", errno);
            return ERROR_FAILURE;
        }
    }

    error_t error = yarrowInit(&yarrowContext);
    if (error)
    {
        TRACE_ERROR("Error: PRNG initialization failed (%s)\r\n", error2text(error));
        return ERROR_FAILURE;
    }

    error = yarrowSeed(&yarrowContext, seed, sizeof(seed));
    if (error)
    {
        TRACE_ERROR("Error: Failed to seed PRNG (%s)\r\n", error2text(error));
        return error;
    }
    return NO_ERROR;
}

error_t rand_deinit()
{
    // Release PRNG context
    yarrowRelease(&yarrowContext);

    return NO_ERROR;
}
