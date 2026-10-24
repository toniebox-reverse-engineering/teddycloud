/*
 * teddycloud wrapper around Cyclone's debug.h: runtime log level, colored
 * prefixes with file:line and the *_RESUME variants. Found before Cyclone's
 * copy via -Iinclude, the original is pulled in unchanged.
 */
#ifndef TC_DEBUG_H
#define TC_DEBUG_H

#include <stdbool.h>
#include <string.h>

#include "../cyclone/common/debug.h"

/* 32 bit builds with a 64 bit time_t, see BUILD_PRIuTIME_LLU in the Makefile */
#if (defined(BUILD_PRIuTIME_LLU) && (BUILD_PRIuTIME_LLU == 1))
#undef PRIuTIME
#define PRIuTIME "llu"
#endif

/* implemented in settings.c, declared here to not pull settings.h into every file */
int tc_log_level(void);
bool tc_log_color(void);

#ifdef TRACE_NOPATH_FILE
#define __FILENAME__ (strrchr("/" __FILE__, '/') + 1)
#else
#define __FILENAME__ __FILE__
#endif

#define TRACE_PRINTF_NOSYNC(...) fprintf(stderr, __VA_ARGS__);
#define TRACE_PRINTF_RESUME(...) fprintf(stderr, __VA_ARGS__), tc_log_unlock();
#define TRACE_PRINTF_PREFIX(colorPrefix, level)                                                                       \
    tc_log_lock();                                                                                              \
    if (tc_log_color())                                                                                               \
    {                                                                                                                 \
        TRACE_PRINTF_NOSYNC("%s%-5s\x1b[0m|\x1b[90m%s:%04d:%s()\x1b[0m| ", colorPrefix, level, __FILENAME__, __LINE__, __func__) \
    }                                                                                                                 \
    else                                                                                                              \
    {                                                                                                                 \
        TRACE_PRINTF_NOSYNC("%-5s|%s:%04d:%s| ", level, __FILENAME__, __LINE__, __func__)                             \
    }

#define TC_TRACE(lvl, colorPrefix, level, ...)         \
    do                                                 \
    {                                                  \
        if (tc_log_level() >= (lvl))                   \
        {                                              \
            TRACE_PRINTF_PREFIX(colorPrefix, level)    \
            TRACE_PRINTF_RESUME(__VA_ARGS__)           \
        }                                              \
    } while (0)

/* continues a line started by an earlier TRACE_*, so it takes the lock itself */
#define TC_TRACE_RESUME(lvl, ...)                      \
    do                                                 \
    {                                                  \
        if (tc_log_level() >= (lvl))                   \
        {                                              \
            tc_log_lock();                             \
            TRACE_PRINTF_RESUME(__VA_ARGS__)           \
        }                                              \
    } while (0)

#undef TRACE_FATAL
#undef TRACE_ERROR
#undef TRACE_WARNING
#undef TRACE_INFO
#undef TRACE_DEBUG
#undef TRACE_VERBOSE

#if (TRACE_LEVEL >= TRACE_LEVEL_FATAL)
#define TRACE_FATAL(...) TC_TRACE(TRACE_LEVEL_FATAL, "\x1b[35m", "FATAL", __VA_ARGS__)
#define TRACE_FATAL_RESUME(...) TC_TRACE_RESUME(TRACE_LEVEL_FATAL, __VA_ARGS__)
#else
#define TRACE_FATAL(...)
#define TRACE_FATAL_RESUME(...)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_ERROR)
#define TRACE_ERROR(...) TC_TRACE(TRACE_LEVEL_ERROR, "\x1b[31m", "ERROR", __VA_ARGS__)
#define TRACE_ERROR_RESUME(...) TC_TRACE_RESUME(TRACE_LEVEL_ERROR, __VA_ARGS__)
#else
#define TRACE_ERROR(...)
#define TRACE_ERROR_RESUME(...)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_WARNING)
#define TRACE_WARNING(...) TC_TRACE(TRACE_LEVEL_WARNING, "\x1b[33m", "WARN", __VA_ARGS__)
#define TRACE_WARNING_RESUME(...) TC_TRACE_RESUME(TRACE_LEVEL_WARNING, __VA_ARGS__)
#else
#define TRACE_WARNING(...)
#define TRACE_WARNING_RESUME(...)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_INFO)
#define TRACE_INFO(...) TC_TRACE(TRACE_LEVEL_INFO, "\x1b[32m", "INFO", __VA_ARGS__)
#define TRACE_INFO_RESUME(...) TC_TRACE_RESUME(TRACE_LEVEL_INFO, __VA_ARGS__)
#else
#define TRACE_INFO(...)
#define TRACE_INFO_RESUME(...)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
#define TRACE_DEBUG(...) TC_TRACE(TRACE_LEVEL_DEBUG, "\x1b[36m", "DEBUG", __VA_ARGS__)
#define TRACE_DEBUG_RESUME(...) TC_TRACE_RESUME(TRACE_LEVEL_DEBUG, __VA_ARGS__)
#else
#define TRACE_DEBUG(...)
#define TRACE_DEBUG_RESUME(...)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_VERBOSE)
#define TRACE_VERBOSE(...) TC_TRACE(TRACE_LEVEL_VERBOSE, "\x1b[94m", "TRACE", __VA_ARGS__)
#define TRACE_VERBOSE_RESUME(...) TC_TRACE_RESUME(TRACE_LEVEL_VERBOSE, __VA_ARGS__)
#else
#define TRACE_VERBOSE(...)
#define TRACE_VERBOSE_RESUME(...)
#endif

#endif
