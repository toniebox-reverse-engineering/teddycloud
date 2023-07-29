/**
 * @file fs_port_posix.c
 * @brief File system abstraction layer (POSIX)
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

/* prevents conflicts due to multiple definitions */
#define _WINERROR_

// Dependencies
#include <windows.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "fs_port.h"
#include "fs_port_posix.h"
#include "str.h"
#include "path.h"
#include "error.h"
#include "debug.h"

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/**
 * @brief File system initialization
 * @return Error code
 **/

error_t fsInit(void)
{
   // Successful processing
   return NO_ERROR;
}

/**
 * @brief Check whether a file exists
 * @param[in] path NULL-terminated string specifying the filename
 * @return The function returns TRUE if the file exists. Otherwise FALSE is returned
 **/

bool_t fsFileExists(const char_t *path)
{
   error_t error;
   bool_t found;
   FsFileStat fileStat;

   // Clear flag
   found = FALSE;

   // Make sure the pathname is valid
   if (path != NULL)
   {
      // Retrieve the attributes of the specified file
      error = fsGetFileStat(path, &fileStat);

      // Check whether the file exists
      if (!error)
      {
         // Valid file?
         if ((fileStat.attributes & FS_FILE_ATTR_DIRECTORY) == 0)
         {
            found = TRUE;
         }
      }
   }

   // The function returns TRUE if the file exists
   return found;
}

/**
 * @brief Retrieve the size of the specified file
 * @param[in] path NULL-terminated string specifying the filename
 * @param[out] size Size of the file in bytes
 * @return Error code
 **/

error_t fsGetFileSize(const char_t *path, uint32_t *size)
{
   error_t error;
   FsFileStat fileStat;

   // Check parameters
   if (path == NULL || size == NULL)
      return ERROR_INVALID_PARAMETER;

   // Retrieve the attributes of the specified file
   error = fsGetFileStat(path, &fileStat);

   // Check whether the file exists
   if (!error)
   {
      // Return the size of the file
      *size = fileStat.size;
   }

   // Return status code
   return error;
}

/**
 * @brief Retrieve the attributes of the specified file
 * @param[in] path NULL-terminated string specifying the filename
 * @param[out] fileStat File attributes
 * @return Error code
 **/
error_t fsGetFileStat(const char_t *path, FsFileStat *fileStat)
{
   error_t error = NO_ERROR;

   WIN32_FILE_ATTRIBUTE_DATA fad;
   if (!GetFileAttributesEx(path, GetFileExInfoStandard, &fad))
   {
      error = GetLastError();
      return error;
   }

   fileStat->attributes = fad.dwFileAttributes;
   fileStat->size = fad.nFileSizeLow | ((uint64_t)fad.nFileSizeHigh << 32);

   FILETIME ft;
   FileTimeToLocalFileTime(&fad.ftLastWriteTime, &ft);

   SYSTEMTIME st;
   FileTimeToSystemTime(&ft, &st);

   fileStat->modified.year = st.wYear;
   fileStat->modified.month = st.wMonth;
   fileStat->modified.day = st.wDay;
   fileStat->modified.dayOfWeek = st.wDayOfWeek;
   fileStat->modified.hours = st.wHour;
   fileStat->modified.minutes = st.wMinute;
   fileStat->modified.seconds = st.wSecond;
   fileStat->modified.milliseconds = st.wMilliseconds;

   return error;
}

/**
 * @brief Rename the specified file
 * @param[in] oldPath NULL-terminated string specifying the pathname of the file to be renamed
 * @param[in] newPath NULL-terminated string specifying the new filename
 * @return Error code
 **/

error_t fsRenameFile(const char_t *oldPath, const char_t *newPath)
{
   error_t error;
   int_t ret;

   // Check parameters
   if (oldPath == NULL || newPath == NULL)
      return ERROR_INVALID_PARAMETER;

   // Rename the specified file
   ret = rename(oldPath, newPath);

   // On success, zero is returned
   if (ret == 0)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   // Return status code
   return error;
}

/**
 * @brief Delete a file
 * @param[in] path NULL-terminated string specifying the filename
 * @return Error code
 **/

error_t fsDeleteFile(const char_t *path)
{
   error_t error;
   int_t ret;

   // Make sure the pathname is valid
   if (path == NULL)
      return ERROR_INVALID_PARAMETER;

   // Delete the specified file
   ret = remove(path);

   // On success, zero is returned
   if (ret == 0)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   // Return status code
   return error;
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
   char_t s[4];

   // File pointer
   FILE *fp = NULL;

   // Make sure the pathname is valid
   if (path == NULL)
      return NULL;

   // Check file access mode
   if (mode & FS_FILE_MODE_WRITE)
   {
      osStrcpy(s, "wb");
   }
   else
   {
      osStrcpy(s, "rb");
   }

   // Open the specified file
   fp = fopen(path, s);

   // Return a handle to the file
   return fp;
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
   error_t error;
   int_t ret;

   // Make sure the file pointer is valid
   if (file == NULL)
      return ERROR_INVALID_PARAMETER;

   // The origin is used as reference for the offset
   if (origin == FS_SEEK_CUR)
   {
      // The offset is relative to the current file pointer
      origin = SEEK_CUR;
   }
   else if (origin == FS_SEEK_END)
   {
      // The offset is relative to the end of the file
      origin = SEEK_END;
   }
   else
   {
      // The offset is absolute
      origin = SEEK_SET;
   }

   // Move read/write pointer
   ret = fseek(file, offset, origin);

   // On success, zero is returned
   if (ret == 0)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   // Return status code
   return error;
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
   error_t error;
   int_t n;

   // Make sure the file pointer is valid
   if (file == NULL)
      return ERROR_INVALID_PARAMETER;

   // Write data
   n = fwrite(data, sizeof(uint8_t), length, file);

   // The total number of elements successfully written is returned. If this
   // number differs from the count parameter, a writing error prevented the
   // function from completing
   if (n == length)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   // Return status code
   return error;
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
   error_t error;
   int_t n;

   // Check parameters
   if (file == NULL || length == NULL)
      return ERROR_INVALID_PARAMETER;

   // No data has been read yet
   *length = 0;

   // Read data
   n = fread(data, sizeof(uint8_t), size, file);

   // The total number of elements successfully read is returned. If this
   // number differs from the count parameter, either a reading error occurred
   // or the end-of-file was reached while reading
   if (n != 0)
   {
      // Total number of data that have been read
      *length = n;

      // Successful processing
      error = NO_ERROR;
   }
   else
   {
      // Report an error
      error = ERROR_END_OF_FILE;
   }

   // Return status code
   return error;
}

/**
 * @brief Close a file
 * @param[in] file Handle that identifies the file to be closed
 **/

void fsCloseFile(FsFile *file)
{
   // Make sure the file pointer is valid
   if (file != NULL)
   {
      // Close the specified file
      fclose(file);
   }
}

/**
 * @brief Check whether a directory exists
 * @param[in] path NULL-terminated string specifying the directory path
 * @return The function returns TRUE if the directory exists. Otherwise FALSE is returned
 **/

bool_t fsDirExists(const char_t *path)
{
   error_t error;
   bool_t found;
   FsFileStat fileStat;

   // Clear flag
   found = FALSE;

   // Retrieve the attributes of the specified file
   error = fsGetFileStat(path, &fileStat);

   // Check whether the file exists
   if (!error)
   {
      // Valid directory?
      if ((fileStat.attributes & FS_FILE_ATTR_DIRECTORY) != 0)
      {
         found = TRUE;
      }
   }

   // The function returns TRUE if the directory exists
   return found;
}

/**
 * @brief Create a directory
 * @param[in] path NULL-terminated string specifying the directory path
 * @return Error code
 **/

error_t fsCreateDir(const char_t *path)
{
   error_t error;
   int_t ret;

   // Make sure the pathname is valid
   if (path == NULL)
      return ERROR_INVALID_PARAMETER;

      // Create a new directory
#ifdef _WIN32
   ret = _mkdir(path);
#else
   ret = mkdir(path, 0777);
#endif

   // On success, zero is returned
   if (ret == 0)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   // Return status code
   return error;
}

/**
 * @brief Remove a directory
 * @param[in] path NULL-terminated string specifying the directory path
 * @return Error code
 **/

error_t fsRemoveDir(const char_t *path)
{
   error_t error;
   int_t ret;

   // Make sure the pathname is valid
   if (path == NULL)
      return ERROR_INVALID_PARAMETER;

      // Remove the specified directory
#ifdef _WIN32
   ret = _rmdir(path);
#else
   ret = rmdir(path);
#endif

   // On success, zero is returned
   if (ret == 0)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   // Return status code
   return error;
}

/**
 * @brief Open a directory stream
 * @param[in] path NULL-terminated string specifying the directory path
 * @return Directory handle
 **/

FsDir *fsOpenDir(const char_t *path)
{
   FsDir *dir;

   dir = (FsDir *)malloc(sizeof(FsDir));
   strSafeCopy(dir->path, path, FS_MAX_PATH_LEN);
   pathCanonicalize(dir->path);
   dir->handle = NULL;

   // Return a handle to the directory
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
   error_t error;
   int_t ret;
   struct dirent *entry;
   struct stat fileStat;
   char_t path[FS_MAX_PATH_LEN + 1];

   // Check parameters
   if (dir == NULL || dirEntry == NULL)
      return ERROR_INVALID_PARAMETER;

   // Clear directory entry
   osMemset(dirEntry, 0, sizeof(FsDirEntry));

   WIN32_FIND_DATA FindFileData;
   bool success = false;

   strSafeCopy(path, dir->path, FS_MAX_PATH_LEN);
   strcat(path, "*");

   if (dir->handle == NULL)
   {
      if ((dir->handle = FindFirstFile(path, &FindFileData)) == INVALID_HANDLE_VALUE)
      {
         return ERROR_END_OF_STREAM;
      }
   }
   else
   {
      if (!FindNextFile(dir->handle, &FindFileData))
      {
         return ERROR_END_OF_STREAM;
      }
   }

   // Copy the file name component
   strSafeCopy(dirEntry->name, FindFileData.cFileName, FS_MAX_NAME_LEN);

   // Check file attributes
   if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
   {
      dirEntry->attributes |= FS_FILE_ATTR_DIRECTORY;
   }

   // Get the pathname of the directory being listed
   strSafeCopy(path, dir->path, FS_MAX_PATH_LEN);

   // Retrieve the full pathname
   pathCombine(path, dirEntry->name, FS_MAX_PATH_LEN);
   pathCanonicalize(path);

   // Get file status
   ret = stat(path, &fileStat);

   // On success, zero is returned
   if (ret == 0)
   {
      // File size
      dirEntry->size = fileStat.st_size;

      // Time of last modification
      convertUnixTimeToDate(fileStat.st_mtime, &dirEntry->modified);
   }
   else
   {
      // File size
      dirEntry->size = 0;

      // Time of last modification
      dirEntry->modified.year = 1970;
      dirEntry->modified.month = 1;
      dirEntry->modified.day = 1;
      dirEntry->modified.dayOfWeek = 0;
      dirEntry->modified.hours = 0;
      dirEntry->modified.minutes = 0;
      dirEntry->modified.seconds = 0;
      dirEntry->modified.milliseconds = 0;
   }

   // Successful processing
   error = NO_ERROR;
   return error;
}

/**
 * @brief Close a directory stream
 * @param[in] dir Handle that identifies the directory to be closed
 **/

void fsCloseDir(FsDir *dir)
{
   // Make sure the directory pointer is valid
   if (dir != NULL)
   {
      // Close the specified directory
      FindClose(dir->handle);

      // Release directory descriptor
      osFreeMem(dir);
   }
}
