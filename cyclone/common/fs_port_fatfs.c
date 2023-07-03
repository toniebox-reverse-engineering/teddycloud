/**
 * @file fs_port_fatfs.c
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

//Dependencies
#include <string.h>
#include "fs_port.h"
#include "fs_port_fatfs.h"
#include "error.h"
#include "debug.h"

//FatFs revision
#define FATFS_R(major, minor, patch) ((major << 16) | (minor << 8) | (0x ## patch))

//Check revision ID
#if (_FATFS == 124)
   #define FATFS_REVISON FATFS_R(0, 7, c)
#elif (_FATFS == 126)
   #define FATFS_REVISON FATFS_R(0, 7, e)
#elif (_FATFS == 8085)
   #define FATFS_REVISON FATFS_R(0, 8, 0)
#elif (_FATFS == 8255)
   #define FATFS_REVISON FATFS_R(0, 8, a)
#elif (_FATFS == 8237)
   #define FATFS_REVISON FATFS_R(0, 8, b)
#elif (_FATFS == 6502)
   #define FATFS_REVISON FATFS_R(0, 9, 0)
#elif (_FATFS == 4004)
   #define FATFS_REVISON FATFS_R(0, 9, a)
#elif (_FATFS == 82786)
   #define FATFS_REVISON FATFS_R(0, 9, b)
#elif (_FATFS == 80960)
   #define FATFS_REVISON FATFS_R(0, 10, 0)
#elif (_FATFS == 29000)
   #define FATFS_REVISON FATFS_R(0, 10, a)
#elif (_FATFS == 8051)
   #define FATFS_REVISON FATFS_R(0, 10, b)
#elif (_FATFS == 80376)
   #define FATFS_REVISON FATFS_R(0, 10, c)
#elif (_FATFS == 32020)
   #define FATFS_REVISON FATFS_R(0, 11, 0)
#elif (_FATFS == 64180)
   #define FATFS_REVISON FATFS_R(0, 11, a)
#elif (_FATFS == 88100)
   #define FATFS_REVISON FATFS_R(0, 12, 0)
#elif (_FATFS == 80186)
   #define FATFS_REVISON FATFS_R(0, 12, a)
#elif (_FATFS == 68020)
   #define FATFS_REVISON FATFS_R(0, 12, b)
#elif (_FATFS == 68300)
   #define FATFS_REVISON FATFS_R(0, 12, c)
#elif (FF_DEFINED == 87030)
   #define FATFS_REVISON FATFS_R(0, 13, 0)
#elif (FF_DEFINED == 89352)
   #define FATFS_REVISON FATFS_R(0, 13, a)
#elif (FF_DEFINED == 63463)
   #define FATFS_REVISON FATFS_R(0, 13, b)
#elif (FF_DEFINED == 86604)
   #define FATFS_REVISON FATFS_R(0, 13, c)
#else
   #define FATFS_REVISON FATFS_R(0, 0, 0)
#endif

//File system objects
static FATFS fs;
static FIL fileTable[FS_MAX_FILES];
static DIR dirTable[FS_MAX_DIRS];

//Mutex that protects critical sections
static OsMutex fsMutex;


/**
 * @brief File system initialization
 * @return Error code
 **/

error_t fsInit(void)
{
   FRESULT res;

   //Clear file system objects
   osMemset(fileTable, 0, sizeof(fileTable));
   osMemset(dirTable, 0, sizeof(dirTable));

   //Create a mutex to protect critical sections
   if(!osCreateMutex(&fsMutex))
   {
      //Failed to create mutex
      return ERROR_OUT_OF_RESOURCES;
   }

   //Mount file system
#if (FATFS_REVISON <= FATFS_R(0, 9, b))
   res = f_mount(0, &fs);
#else
   res = f_mount(&fs, "", 1);
#endif

   //Failed to mount file system?
   if(res != FR_OK)
   {
      //Clean up side effects
      osDeleteMutex(&fsMutex);
      //Report an error
      return ERROR_FAILURE;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Check whether a file exists
 * @param[in] path NULL-terminated string specifying the filename
 * @return The function returns TRUE if the file exists. Otherwise FALSE is returned
 **/

bool_t fsFileExists(const char_t *path)
{
   FRESULT res;
   FILINFO fno;

#if (FATFS_REVISON <= FATFS_R(0, 11, a) && _USE_LFN != 0)
   fno.lfname = NULL;
   fno.lfsize = 0;
#endif

   //Make sure the pathname is valid
   if(path == NULL)
      return FALSE;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Check whether the file exists
   res = f_stat(path, &fno);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return FALSE;

   //Valid file?
   if(fno.fattrib & AM_DIR)
      return FALSE;
   else
      return TRUE;
}


/**
 * @brief Retrieve the size of the specified file
 * @param[in] path NULL-terminated string specifying the filename
 * @param[out] size Size of the file in bytes
 * @return Error code
 **/

error_t fsGetFileSize(const char_t *path, uint32_t *size)
{
   FRESULT res;
   FILINFO fno;

#if (FATFS_REVISON <= FATFS_R(0, 11, a) && _USE_LFN != 0)
   fno.lfname = NULL;
   fno.lfsize = 0;
#endif

   //Check parameters
   if(path == NULL || size == NULL)
      return ERROR_INVALID_PARAMETER;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Retrieve information about the specified file
   res = f_stat(path, &fno);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //Valid file?
   if(fno.fattrib & AM_DIR)
      return ERROR_FAILURE;

   //Return the size of the file
   *size = fno.fsize;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve the attributes of the specified file
 * @param[in] path NULL-terminated string specifying the filename
 * @param[out] fileStat File attributes
 * @return Error code
 **/

error_t fsGetFileStat(const char_t *path, FsFileStat *fileStat)
{
   FRESULT res;
   FILINFO fno;

#if (FATFS_REVISON <= FATFS_R(0, 11, a) && _USE_LFN != 0)
   fno.lfname = NULL;
   fno.lfsize = 0;
#endif

   //Check parameters
   if(path == NULL || fileStat == NULL)
      return ERROR_INVALID_PARAMETER;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Retrieve information about the specified file
   res = f_stat(path, &fno);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //Clear file attributes
   osMemset(fileStat, 0, sizeof(FsFileStat));

   //File attributes
   fileStat->attributes = fno.fattrib;
   //File size
   fileStat->size = fno.fsize;

   //Time of last modification
   fileStat->modified.year = 1980 + ((fno.fdate >> 9) & 0x7F);
   fileStat->modified.month = (fno.fdate >> 5) & 0x0F;
   fileStat->modified.day = fno.fdate & 0x1F;
   fileStat->modified.dayOfWeek = 0;
   fileStat->modified.hours = (fno.ftime >> 11) & 0x1F;
   fileStat->modified.minutes = (fno.ftime >> 5) & 0x3F;
   fileStat->modified.seconds = (fno.ftime & 0x1F) * 2;
   fileStat->modified.milliseconds = 0;

   //Make sure the date is valid
   fileStat->modified.month = MAX(fileStat->modified.month, 1);
   fileStat->modified.month = MIN(fileStat->modified.month, 12);
   fileStat->modified.day = MAX(fileStat->modified.day, 1);
   fileStat->modified.day = MIN(fileStat->modified.day, 31);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Rename the specified file
 * @param[in] oldPath NULL-terminated string specifying the pathname of the file to be renamed
 * @param[in] newPath NULL-terminated string specifying the new filename
 * @return Error code
 **/

error_t fsRenameFile(const char_t *oldPath, const char_t *newPath)
{
#if (_FS_READONLY == 1 || FF_FS_READONLY ==1)
   //Read-only configuration
   return ERROR_READ_ONLY_ACCESS;
#else
   FRESULT res;

   //Check parameters
   if(oldPath == NULL || newPath == NULL)
      return ERROR_INVALID_PARAMETER;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Rename the specified file
   res = f_rename(oldPath, newPath);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //Successful processing
   return NO_ERROR;
#endif
}


/**
 * @brief Delete a file
 * @param[in] path NULL-terminated string specifying the filename
 * @return Error code
 **/

error_t fsDeleteFile(const char_t *path)
{
#if (_FS_READONLY == 1 || FF_FS_READONLY ==1)
   //Read-only configuration
   return ERROR_READ_ONLY_ACCESS;
#else
   FRESULT res;

   //Make sure the pathname is valid
   if(path == NULL)
      return ERROR_INVALID_PARAMETER;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Delete the specified file
   res = f_unlink(path);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //Successful processing
   return NO_ERROR;
#endif
}


/**
 * @brief Open the specified file for reading or writing
 * @param[in] path NULL-terminated string specifying the filename
 * @param[in] mode Type of access permitted (FS_FILE_MODE_READ,
 *   FS_FILE_MODE_WRITE or FS_FILE_MODE_CREATE)
 * @return File handle
 **/

FsFile *fsOpenFile(const char_t *path, uint_t mode)
{
   uint_t i;
   uint_t flags;
   FRESULT res;

   //File pointer
   FsFile *file = NULL;

   //Make sure the pathname is valid
   if(path == NULL)
      return NULL;

   //Enter critical section
   osAcquireMutex(&fsMutex);

   //Loop through the file objects
   for(i = 0; i < FS_MAX_FILES; i++)
   {
      //Unused file object found?
#if (FATFS_REVISON <= FATFS_R(0, 11, a))
      if(fileTable[i].fs == NULL)
#else
      if(fileTable[i].obj.fs == NULL)
#endif
      {
         //Default access mode
         flags = 0;

         //Check access mode
         if(mode & FS_FILE_MODE_READ)
            flags |= FA_READ;

         if(mode & FS_FILE_MODE_WRITE)
            flags |= FA_WRITE;

         if(mode & FS_FILE_MODE_CREATE)
            flags |= FA_OPEN_ALWAYS;

         if(mode & FS_FILE_MODE_TRUNC)
            flags |= FA_CREATE_ALWAYS;

         //Open the specified file
         res = f_open(&fileTable[i], path, flags);

         //Check status code
         if(res == FR_OK)
            file = &fileTable[i];

         //Stop immediately
         break;
      }
   }

   //Leave critical section
   osReleaseMutex(&fsMutex);
   //Return a handle to the file
   return file;
}


/**
 * @brief Move to specified position in file
 * @param[in] file Handle that identifies the file
 * @param[in] offset Number of bytes to move from origin
 * @param[in] origin Position used as reference for the offset (FS_SEEK_SET,
 *   FS_SEEK_CUR or FS_SEEK_END)
 * @return Error code
 **/

error_t fsSeekFile(FsFile *file, int_t offset, uint_t origin)
{
   FRESULT res;

   //Make sure the file pointer is valid
   if(file == NULL)
      return ERROR_INVALID_PARAMETER;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //The origin is used as reference for the offset
   if(origin == FS_SEEK_CUR)
   {
      //The offset is relative to the current file pointer
      offset += f_tell((FIL *) file);
   }
   else if(origin == FS_SEEK_END)
   {
      //The offset is relative to the end of the file
      offset += f_size((FIL *) file);
   }
   else
   {
      //The offset is absolute
   }

   //Move read/write pointer
   res = f_lseek((FIL *) file, offset);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Write data to the specified file
 * @param[in] file Handle that identifies the file to be written
 * @param[in] data Pointer to a buffer containing the data to be written
 * @param[in] length Number of data bytes to write
 * @return Error code
 **/

error_t fsWriteFile(FsFile *file, void *data, size_t length)
{
#if (_FS_READONLY == 1 || FF_FS_READONLY ==1)
   //Read-only configuration
   return ERROR_READ_ONLY_ACCESS;
#else
   UINT n;
   FRESULT res;

   //Make sure the file pointer is valid
   if(file == NULL)
      return ERROR_INVALID_PARAMETER;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Write data
   res = f_write((FIL *) file, data, length, &n);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //Sanity check
   if(n != length)
      return ERROR_FAILURE;

   //Successful processing
   return NO_ERROR;
#endif
}


/**
 * @brief Read data from the specified file
 * @param[in] file Handle that identifies the file to be read
 * @param[in] data Pointer to the buffer where to copy the data
 * @param[in] size Size of the buffer, in bytes
 * @param[out] length Number of data bytes that have been read
 * @return Error code
 **/

error_t fsReadFile(FsFile *file, void *data, size_t size, size_t *length)
{
   UINT n;
   FRESULT res;

   //Check parameters
   if(file == NULL || length == NULL)
      return ERROR_INVALID_PARAMETER;

   //No data has been read yet
   *length = 0;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Read data
   res = f_read((FIL *) file, data, size, &n);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //End of file?
   if(!n)
      return ERROR_END_OF_FILE;

   //Total number of data that have been read
   *length = n;
   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Close a file
 * @param[in] file Handle that identifies the file to be closed
 **/

void fsCloseFile(FsFile *file)
{
   //Make sure the file pointer is valid
   if(file != NULL)
   {
      //Enter critical section
      osAcquireMutex(&fsMutex);

      //Close the specified file
      f_close((FIL *) file);

      //Mark the corresponding entry as free
#if (FATFS_REVISON <= FATFS_R(0, 11, a))
      ((FIL *) file)->fs = NULL;
#else
      ((FIL *) file)->obj.fs = NULL;
#endif

      //Leave critical section
      osReleaseMutex(&fsMutex);
   }
}


/**
 * @brief Check whether a directory exists
 * @param[in] path NULL-terminated string specifying the directory path
 * @return The function returns TRUE if the directory exists. Otherwise FALSE is returned
 **/

bool_t fsDirExists(const char_t *path)
{
   FRESULT res;
   FILINFO fno;

#if (FATFS_REVISON <= FATFS_R(0, 11, a) && _USE_LFN != 0)
   fno.lfname = NULL;
   fno.lfsize = 0;
#endif

   //Make sure the pathname is valid
   if(path == NULL)
      return FALSE;

   //Root directory?
   if(!osStrcmp(path, "/"))
      return TRUE;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Check whether the file exists
   res = f_stat(path, &fno);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return FALSE;

   //Valid directory?
   if(fno.fattrib & AM_DIR)
      return TRUE;
   else
      return FALSE;
}


/**
 * @brief Create a directory
 * @param[in] path NULL-terminated string specifying the directory path
 * @return Error code
 **/

error_t fsCreateDir(const char_t *path)
{
#if (_FS_READONLY == 1 || FF_FS_READONLY ==1)
   //Read-only configuration
   return ERROR_READ_ONLY_ACCESS;
#else
   FRESULT res;

   //Make sure the pathname is valid
   if(path == NULL)
      return ERROR_INVALID_PARAMETER;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Create a new directory
   res = f_mkdir(path);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //Successful processing
   return NO_ERROR;
#endif
}


/**
 * @brief Remove a directory
 * @param[in] path NULL-terminated string specifying the directory path
 * @return Error code
 **/

error_t fsRemoveDir(const char_t *path)
{
#if (_FS_READONLY == 1 || FF_FS_READONLY ==1)
   //Read-only configuration
   return ERROR_READ_ONLY_ACCESS;
#else
   FRESULT res;

   //Make sure the pathname is valid
   if(path == NULL)
      return ERROR_INVALID_PARAMETER;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Remove the specified directory
   res = f_unlink(path);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //Successful processing
   return NO_ERROR;
#endif
}


/**
 * @brief Open a directory stream
 * @param[in] path NULL-terminated string specifying the directory path
 * @return Directory handle
 **/

FsDir *fsOpenDir(const char_t *path)
{
   uint_t i;
   FRESULT res;

   //Directory pointer
   FsDir *dir = NULL;

   //Make sure the pathname is valid
   if(path == NULL)
      return NULL;

   //Enter critical section
   osAcquireMutex(&fsMutex);

   //Loop through the directory objects
   for(i = 0; i < FS_MAX_DIRS; i++)
   {
      //Unused directory object found?
#if (FATFS_REVISON <= FATFS_R(0, 11, a))
      if(dirTable[i].fs == NULL)
#else
      if(dirTable[i].obj.fs == NULL)
#endif
      {
         //Open the specified directory
         res = f_opendir(&dirTable[i], path);

         //Check status code
         if(res == FR_OK)
            dir = &dirTable[i];

         //Stop immediately
         break;
      }
   }

   //Leave critical section
   osReleaseMutex(&fsMutex);
   //Return a handle to the directory
   return dir;
}


/**
 * @brief Read an entry from the specified directory stream
 * @param[in] dir Handle that identifies the directory
 * @param[out] dirEntry Pointer to a directory entry
 * @return Error code
 **/

error_t fsReadDir(FsDir *dir, FsDirEntry *dirEntry)
{
   FRESULT res;
   FILINFO fno;
   char_t *fn;
   size_t n;

#if (FATFS_REVISON <= FATFS_R(0, 11, a) && _USE_LFN != 0)
   char_t lfn[_MAX_LFN + 1];
   fno.lfname = lfn;
   fno.lfsize = sizeof(lfn);
#endif

   //Make sure the directory pointer is valid
   if(dir == NULL)
      return ERROR_INVALID_PARAMETER;

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Enter critical section
   osAcquireMutex(&fsMutex);
#endif

   //Read the specified directory
   res = f_readdir((DIR *) dir, &fno);

#if ((FATFS_REVISON <= FATFS_R(0, 12, c) && _FS_REENTRANT == 0) || \
   (FATFS_REVISON >= FATFS_R(0, 13, 0) && FF_FS_REENTRANT == 0))
   //Leave critical section
   osReleaseMutex(&fsMutex);
#endif

   //Any error to report?
   if(res != FR_OK)
      return ERROR_FAILURE;

   //End of the directory stream?
   if(fno.fname[0] == '\0')
      return ERROR_END_OF_STREAM;

   //Point to the long filename
#if (FATFS_REVISON <= FATFS_R(0, 11, a) && _USE_LFN != 0)
   fn = (*fno.lfname != '\0') ? fno.lfname : fno.fname;
#else
   fn = fno.fname;
#endif

   //File attributes
   dirEntry->attributes = fno.fattrib;
   //File size
   dirEntry->size = fno.fsize;

   //Time of last modification
   dirEntry->modified.year = 1980 + ((fno.fdate >> 9) & 0x7F);
   dirEntry->modified.month = (fno.fdate >> 5) & 0x0F;
   dirEntry->modified.day = fno.fdate & 0x1F;
   dirEntry->modified.dayOfWeek = 0;
   dirEntry->modified.hours = (fno.ftime >> 11) & 0x1F;
   dirEntry->modified.minutes = (fno.ftime >> 5) & 0x3F;
   dirEntry->modified.seconds = (fno.ftime & 0x1F) * 2;
   dirEntry->modified.milliseconds = 0;

   //Make sure the date is valid
   dirEntry->modified.month = MAX(dirEntry->modified.month, 1);
   dirEntry->modified.month = MIN(dirEntry->modified.month, 12);
   dirEntry->modified.day = MAX(dirEntry->modified.day, 1);
   dirEntry->modified.day = MIN(dirEntry->modified.day, 31);

   //Retrieve the length of the file name
   n = osStrlen(fn);
   //Limit the number of characters to be copied
   n = MIN(n, FS_MAX_NAME_LEN);

   //Copy file name
   osStrncpy(dirEntry->name, fn, n);
   //Properly terminate the string with a NULL character
   dirEntry->name[n] = '\0';

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Close a directory stream
 * @param[in] dir Handle that identifies the directory to be closed
 **/

void fsCloseDir(FsDir *dir)
{
   //Make sure the directory pointer is valid
   if(dir != NULL)
   {
      //Enter critical section
      osAcquireMutex(&fsMutex);

#if (FATFS_REVISON >= FATFS_R(0, 10, 0))
      //Close the specified directory
      f_closedir((DIR *) dir);
#endif

      //Mark the corresponding entry as free
#if (FATFS_REVISON <= FATFS_R(0, 11, a))
      ((DIR *) dir)->fs = NULL;
#else
      ((DIR *) dir)->obj.fs = NULL;
#endif

      //Leave critical section
      osReleaseMutex(&fsMutex);
   }
}
