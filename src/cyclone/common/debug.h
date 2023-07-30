/**
 * @file debug.h
 * @brief Debugging facilities
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

#ifndef _DEBUG_H
#define _DEBUG_H

// Dependencies
#include <stdio.h>
#include "os_port.h"
#include "settings.h"

// Trace level definitions
#define TRACE_LEVEL_OFF 0
#define TRACE_LEVEL_FATAL 1
#define TRACE_LEVEL_ERROR 2
#define TRACE_LEVEL_WARNING 3
#define TRACE_LEVEL_INFO 4
#define TRACE_LEVEL_DEBUG 5
#define TRACE_LEVEL_VERBOSE 6

// Default trace level
#ifndef TRACE_LEVEL
#define TRACE_LEVEL TRACE_LEVEL_DEBUG
#endif

#ifdef TRACE_NOPATH_FILE
#define __FILENAME__ (strrchr("/" __FILE__, '/') + 1)
#else
#define __FILENAME__ __FILE__
#endif
// Trace output redirection
#ifndef TRACE_PRINTF
#define TRACE_PRINTF(...) osSuspendAllTasks(), fprintf(stderr, __VA_ARGS__), osResumeAllTasks()
#endif
#ifndef TRACE_PRINTF_NOSYNC
#define TRACE_PRINTF_NOSYNC(...) fprintf(stderr, __VA_ARGS__);
#endif
#ifndef TRACE_PRINTF_RESUME
#define TRACE_PRINTF_RESUME(...) fprintf(stderr, __VA_ARGS__), osResumeAllTasks();
#endif
#ifndef TRACE_PRINTF_PREFIX
#define TRACE_PRINTF_PREFIX(colorPrefix, level)                                                                                \
   osSuspendAllTasks();                                                                                                        \
   if (get_settings()->log.color)                                                                                              \
   {                                                                                                                           \
      TRACE_PRINTF_NOSYNC("%s%-5s\x1b[0m|\x1b[90m%s:%04d:%s()\x1b[0m| ", colorPrefix, level, __FILENAME__, __LINE__, __func__) \
   }                                                                                                                           \
   else                                                                                                                        \
   {                                                                                                                           \
      TRACE_PRINTF_NOSYNC("%-5s|%s:%04d:%s| ", level, __FILENAME__, __LINE__, __func__)                                        \
   }
#endif

#ifndef TRACE_ARRAY
#define TRACE_ARRAY(p, a, n) osSuspendAllTasks(), debugDisplayArray(stderr, p, a, n), osResumeAllTasks()
#endif

#ifndef TRACE_MPI
#define TRACE_MPI(p, a) osSuspendAllTasks(), mpiDump(stderr, p, a), osResumeAllTasks()
#endif

// Debugging macros
#if (TRACE_LEVEL >= TRACE_LEVEL_FATAL)
#define TRACE_FATAL(...)                               \
   if (get_settings()->log.level >= TRACE_LEVEL_FATAL) \
   {                                                   \
      TRACE_PRINTF_PREFIX("\x1b[35m", "FATAL")         \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                 \
   }
#define TRACE_FATAL_RESUME(...)                        \
   if (get_settings()->log.level >= TRACE_LEVEL_FATAL) \
   {                                                   \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                 \
   }
#define TRACE_FATAL_ARRAY(p, a, n) TRACE_ARRAY(p, a, n)
#define TRACE_FATAL_MPI(p, a) TRACE_MPI(p, a)
#else
#define TRACE_FATAL(...)
#define TRACE_FATAL_RESUME(...)
#define TRACE_FATAL_ARRAY(p, a, n)
#define TRACE_FATAL_MPI(p, a)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_ERROR)
#define TRACE_ERROR(...)                               \
   if (get_settings()->log.level >= TRACE_LEVEL_ERROR) \
   {                                                   \
      TRACE_PRINTF_PREFIX("\x1b[31m", "ERROR")         \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                 \
   }
#define TRACE_ERROR_RESUME(...)                        \
   if (get_settings()->log.level >= TRACE_LEVEL_ERROR) \
   {                                                   \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                 \
   }
#define TRACE_ERROR_ARRAY(p, a, n) TRACE_ARRAY(p, a, n)
#define TRACE_ERROR_MPI(p, a) TRACE_MPI(p, a)
#else
#define TRACE_ERROR(...)
#define TRACE_ERROR_RESUME(...)
#define TRACE_ERROR_ARRAY(p, a, n)
#define TRACE_ERROR_MPI(p, a)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_WARNING)
#define TRACE_WARNING(...)                               \
   if (get_settings()->log.level >= TRACE_LEVEL_WARNING) \
   {                                                     \
      TRACE_PRINTF_PREFIX("\x1b[33m", "WARN")            \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                   \
   }
#define TRACE_WARNING_RESUME(...)                        \
   if (get_settings()->log.level >= TRACE_LEVEL_WARNING) \
   {                                                     \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                   \
   }
#define TRACE_WARNING_ARRAY(p, a, n) TRACE_ARRAY(p, a, n)
#define TRACE_WARNING_MPI(p, a) TRACE_MPI(p, a)
#else
#define TRACE_WARNING(...)
#define TRACE_WARNING_RESUME(...)
#define TRACE_WARNING_ARRAY(p, a, n)
#define TRACE_WARNING_MPI(p, a)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_INFO)
#define TRACE_INFO(...)                               \
   if (get_settings()->log.level >= TRACE_LEVEL_INFO) \
   {                                                  \
      TRACE_PRINTF_PREFIX("\x1b[32m", "INFO")         \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                \
   }
#define TRACE_INFO_RESUME(...)                        \
   if (get_settings()->log.level >= TRACE_LEVEL_INFO) \
   {                                                  \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                \
   }
#define TRACE_INFO_ARRAY(p, a, n) TRACE_ARRAY(p, a, n)
#define TRACE_INFO_NET_BUFFER(p, b, o, n)
#define TRACE_INFO_MPI(p, a) TRACE_MPI(p, a)
#else
#define TRACE_INFO(...)
#define TRACE_INFO_RESUME
#define TRACE_INFO_ARRAY(p, a, n)
#define TRACE_INFO_NET_BUFFER(p, b, o, n)
#define TRACE_INFO_MPI(p, a)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
#define TRACE_DEBUG(...)                               \
   if (get_settings()->log.level >= TRACE_LEVEL_DEBUG) \
   {                                                   \
      TRACE_PRINTF_PREFIX("\x1b[36m", "DEBUG")         \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                 \
   }
#define TRACE_DEBUG_RESUME(...)                        \
   if (get_settings()->log.level >= TRACE_LEVEL_DEBUG) \
   {                                                   \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                 \
   }
#define TRACE_DEBUG_ARRAY(p, a, n) TRACE_ARRAY(p, a, n)
#define TRACE_DEBUG_NET_BUFFER(p, b, o, n)
#define TRACE_DEBUG_MPI(p, a) TRACE_MPI(p, a)
#else
#define TRACE_DEBUG(...)
#define TRACE_DEBUG_RESUME(...)
#define TRACE_DEBUG_ARRAY(p, a, n)
#define TRACE_DEBUG_NET_BUFFER(p, b, o, n)
#define TRACE_DEBUG_MPI(p, a)
#endif

#if (TRACE_LEVEL >= TRACE_LEVEL_VERBOSE)
#define TRACE_VERBOSE(...)                               \
   if (get_settings()->log.level >= TRACE_LEVEL_VERBOSE) \
   {                                                     \
      TRACE_PRINTF_PREFIX("\x1b[94m", "TRACE")           \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                   \
   }
#define TRACE_VERBOSE_RESUME(...)                        \
   if (get_settings()->log.level >= TRACE_LEVEL_VERBOSE) \
   {                                                     \
      TRACE_PRINTF_RESUME(__VA_ARGS__)                   \
   }
#define TRACE_VERBOSE_ARRAY(p, a, n) TRACE_ARRAY(p, a, n)
#define TRACE_VERBOSE_NET_BUFFER(p, b, o, n)
#define TRACE_VERBOSE_MPI(p, a) TRACE_MPI(p, a)
#else
#define TRACE_VERBOSE(...)
#define TRACE_VERBOSE_RESUME(...)
#define TRACE_VERBOSE_ARRAY(p, a, n)
#define TRACE_VERBOSE_NET_BUFFER(p, b, o, n)
#define TRACE_VERBOSE_MPI(p, a)
#endif

// C++ guard
#ifdef __cplusplus
extern "C"
{
#endif

   // Debug related functions
   void debugInit(uint32_t baudrate);

   void debugDisplayArray(FILE *stream,
                          const char_t *prepend, const void *data, size_t length);

// Deprecated definitions
#define TRACE_LEVEL_NO_TRACE TRACE_LEVEL_OFF

// C++ guard
#ifdef __cplusplus
}
#endif

#endif
