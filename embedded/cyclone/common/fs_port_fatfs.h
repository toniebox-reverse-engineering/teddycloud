/**
 * @file fs_port_fatfs.h
 * @brief File system abstraction layer (FatFs)
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

#ifndef _FS_PORT_FATFS_H
#define _FS_PORT_FATFS_H

//Dependencies
#include "os_port.h"
#include "ff.h"

//Number of files that can be opened simultaneously
#ifndef FS_MAX_FILES
   #define FS_MAX_FILES 8
#elif (FS_MAX_FILES < 1)
   #error FS_MAX_FILES parameter is not valid
#endif

//Number of directories that can be opened simultaneously
#ifndef FS_MAX_DIRS
   #define FS_MAX_DIRS 8
#elif (FS_MAX_DIRS < 1)
   #error FS_MAX_DIRS parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief File descriptor
 **/

typedef void FsFile;


/**
 * @brief Directory descriptor
 **/

typedef void FsDir;


//File system abstraction layer
error_t fsInit(void);

bool_t fsFileExists(const char_t *path);
error_t fsGetFileSize(const char_t *path, uint32_t *size);
error_t fsGetFileStat(const char_t *path, FsFileStat *fileStat);
error_t fsRenameFile(const char_t *oldPath, const char_t *newPath);
error_t fsDeleteFile(const char_t *path);

FsFile *fsOpenFile(const char_t *path, uint_t mode);
error_t fsSeekFile(FsFile *file, int_t offset, uint_t origin);
error_t fsWriteFile(FsFile *file, void *data, size_t length);
error_t fsReadFile(FsFile *file, void *data, size_t size, size_t *length);
void fsCloseFile(FsFile *file);

bool_t fsDirExists(const char_t *path);
error_t fsCreateDir(const char_t *path);
error_t fsRemoveDir(const char_t *path);

FsDir *fsOpenDir(const char_t *path);
error_t fsReadDir(FsDir *dir, FsDirEntry *dirEntry);
void fsCloseDir(FsDir *dir);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
