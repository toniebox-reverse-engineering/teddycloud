/**
 * @file fs_port.h
 * @brief File system abstraction layer
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

#ifndef _FS_PORT_H
#define _FS_PORT_H

//Dependencies
#include "fs_port_config.h"
#include "os_port.h"
#include "date_time.h"
#include "error.h"

//Maximum filename length
#ifndef FS_MAX_NAME_LEN
   #define FS_MAX_NAME_LEN 127
#elif (FS_MAX_NAME_LEN < 11)
   #error FS_MAX_NAME_LEN parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief File attributes
 **/

typedef enum
{
   FS_FILE_ATTR_READ_ONLY   = 0x01,
   FS_FILE_ATTR_HIDDEN      = 0x02,
   FS_FILE_ATTR_SYSTEM      = 0x04,
   FS_FILE_ATTR_VOLUME_NAME = 0x08,
   FS_FILE_ATTR_DIRECTORY   = 0x10,
   FS_FILE_ATTR_ARCHIVE     = 0x20
} FsFileAttributes;


/**
 * @brief File access mode
 **/

typedef enum
{
   FS_FILE_MODE_READ   = 1,
   FS_FILE_MODE_WRITE  = 2,
   FS_FILE_MODE_CREATE = 4,
   FS_FILE_MODE_TRUNC  = 8
} FsFileMode;


/**
 * @brief File seek origin
 **/

typedef enum
{
   FS_SEEK_SET = 0,
   FS_SEEK_CUR = 1,
   FS_SEEK_END = 2
} FsSeekOrigin;


/**
 * @brief File status
 **/

typedef struct
{
   uint32_t attributes;
   uint32_t size;
   DateTime modified;
} FsFileStat;


/**
 * @brief Directory entry
 **/

typedef struct
{
   uint32_t attributes;
   uint32_t size;
   DateTime modified;
   char_t name[FS_MAX_NAME_LEN + 1];
} FsDirEntry;


//FatFs port?
#if defined(USE_FATFS)
   #include "fs_port_fatfs.h"
//RL-FlashFS port?
#elif defined(USE_RL_FS)
   #include "fs_port_rl_fs.h"
//SPIFFS port?
#elif defined(USE_SPIFFS)
   #include "fs_port_spiffs.h"
//Windows port?
#elif defined(_WIN32)
   #include "fs_port_posix.h"
//POSIX port?
#elif defined(__linux__) || defined(__FreeBSD__)
   #include "fs_port_posix.h"
//Custom port?
#elif defined(USE_CUSTOM_FS)
   #include "fs_port_custom.h"
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
