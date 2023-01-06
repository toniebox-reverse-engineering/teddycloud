/**
 * @file fs_port_rl_fs.c
 * @brief File system abstraction layer (RL-FlashFS)
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
#include "fs_port_rl_fs.h"
#include "str.h"
#include "path.h"
#include "error.h"
#include "debug.h"


/**
 * @brief File system initialization
 * @return Error code
 **/

__weak_func error_t fsInit(void)
{
   error_t error;
   fsStatus status;

   //Initialize file system
   status = finit ("M0:");

   //Check status code
   if(status == fsOK)
   {
      //Mount drive
      status = fmount("M0:");
   }

   //On success, fsOK is returned
   if(status == fsOK)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether a file exists
 * @param[in] path NULL-terminated string specifying the filename
 * @return The function returns TRUE if the file exists. Otherwise FALSE is returned
 **/

bool_t fsFileExists(const char_t *path)
{
   fsStatus status;
   fsFileInfo fileInfo;
   bool_t found;

   //Initialize flag
   found = FALSE;

   //Make sure the pathname is valid
   if(path != NULL)
   {
      //The fileID field must be initialized to zero
      fileInfo.fileID = 0;
      //Find the specified path name
      status = ffind(path, &fileInfo);

      //Check status code
      if(status == fsOK)
      {
         //Valid file?
         if((fileInfo.attrib & FS_FAT_ATTR_DIRECTORY) == 0)
         {
            found = TRUE;
         }
      }
   }

   //The function returns TRUE if the file exists
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
   fsStatus status;
   fsFileInfo fileInfo;

   //Check parameters
   if(path == NULL || size == NULL)
      return ERROR_INVALID_PARAMETER;

   //The fileID field must be initialized to zero
   fileInfo.fileID = 0;
   //Find the specified path name
   status = ffind(path, &fileInfo);

   //Any error to report?
   if(status != fsOK)
      return ERROR_FAILURE;

   //Valid file?
   if((fileInfo.attrib & FS_FAT_ATTR_DIRECTORY) != 0)
      return ERROR_FAILURE;

   //Return the size of the file
   *size = fileInfo.size;

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
   fsStatus status;
   fsFileInfo fileInfo;

   //Check parameters
   if(path == NULL || fileStat == NULL)
      return ERROR_INVALID_PARAMETER;

   //The fileID field must be initialized to zero
   fileInfo.fileID = 0;
   //Find the specified path name
   status = ffind(path, &fileInfo);

   //Any error to report?
   if(status != fsOK)
      return ERROR_FAILURE;

   //Clear file attributes
   osMemset(fileStat, 0, sizeof(FsFileStat));

   //File attributes
   fileStat->attributes = fileInfo.attrib;
   //File size
   fileStat->size = fileInfo.size;

   //Time of last modification
   fileStat->modified.year = fileInfo.time.year;
   fileStat->modified.month = fileInfo.time.mon;
   fileStat->modified.day = fileInfo.time.day;
   fileStat->modified.hours = fileInfo.time.hr;
   fileStat->modified.minutes = fileInfo.time.min;
   fileStat->modified.seconds = fileInfo.time.sec;
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
   error_t error;
   fsStatus status;
   const char_t *newName;

   //Check parameters
   if(oldPath == NULL || newPath == NULL)
      return ERROR_INVALID_PARAMETER;

   //Get new file name
   newName = pathGetFilename(newPath);

   //Rename the specified file
   status = frename(oldPath, newName);

   //On success, fsOK is returned
   if(status == fsOK)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   //Return status code
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
   fsStatus status;

   //Make sure the pathname is valid
   if(path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Delete the specified file
   status = fdelete(path, "");

   //On success, fsOK is returned
   if(status == fsOK)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   //Return status code
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

   //File pointer
   FILE *fp = NULL;

   //Make sure the pathname is valid
   if(path == NULL)
      return NULL;

   //Check file access mode
   if(mode & FS_FILE_MODE_WRITE)
   {
      osStrcpy(s, "wb");
   }
   else
   {
      osStrcpy(s, "rb");
   }

   //Open the specified file
   fp = fopen(path, s);

   //Return a handle to the file
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

   //Make sure the file pointer is valid
   if(file == NULL)
      return ERROR_INVALID_PARAMETER;

   //The origin is used as reference for the offset
   if(origin == FS_SEEK_CUR)
   {
      //The offset is relative to the current file pointer
      origin = SEEK_CUR;
   }
   else if(origin == FS_SEEK_END)
   {
      //The offset is relative to the end of the file
      origin = SEEK_END;
   }
   else
   {
      //The offset is absolute
      origin = SEEK_SET;
   }

   //Move read/write pointer
   ret = fseek(file, offset, origin);

   //On success, zero is returned
   if(ret == 0)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   //Return status code
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

   //Make sure the file pointer is valid
   if(file == NULL)
      return ERROR_INVALID_PARAMETER;

   //Write data
   n = fwrite(data, sizeof(uint8_t), length, file);

   //The total number of elements successfully written is returned. If this
   //number differs from the count parameter, a writing error prevented the
   //function from completing
   if(n == length)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   //Return status code
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

   //Check parameters
   if(file == NULL || length == NULL)
      return ERROR_INVALID_PARAMETER;

   //No data has been read yet
   *length = 0;

   //Read data
   n = fread(data, sizeof(uint8_t), size, file);

   //The total number of elements successfully read is returned. If this
   //number differs from the count parameter, either a reading error occurred
   //or the end-of-file was reached while reading
   if(n != 0)
   {
      //Total number of data that have been read
      *length = n;

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Report an error
      error = ERROR_END_OF_FILE;
   }

   //Return status code
   return error;
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
      //Close the specified file
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
   fsStatus status;
   fsFileInfo fileInfo;
   bool_t found;

   //Initialize flag
   found = FALSE;

   //Make sure the pathname is valid
   if(path != NULL)
   {
      //Root directory?
      if(!osStrcmp(path, "/") || !osStrcmp(path, "\\"))
      {
         //The root directory always exists
         found = TRUE;
      }
      else
      {
         //The fileID field must be initialized to zero
         fileInfo.fileID = 0;
         //Find the specified path name
         status = ffind(path, &fileInfo);

         //Check status code
         if(status == fsOK)
         {
            //Valid directory?
            if((fileInfo.attrib & FS_FAT_ATTR_DIRECTORY) != 0)
            {
               found = TRUE;
            }
         }
      }
   }

   //The function returns TRUE if the directory exists
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
   fsStatus status;

   //Make sure the pathname is valid
   if(path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Create a new directory
   status = fmkdir(path);

   //On success, fsOK is returned
   if(status == fsOK)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   //Return status code
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
   fsStatus status;

   //Make sure the pathname is valid
   if(path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Remove the specified directory
   status = frmdir(path, "");

   //On success, fsOK is returned
   if(status == fsOK)
   {
      error = NO_ERROR;
   }
   else
   {
      error = ERROR_FAILURE;
   }

   //Return status code
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

   //Valid directory path?
   if(path != NULL)
   {
      //Check whether the directory exists
      if(fsDirExists(path))
      {
         //Allocate a memory buffer to hold the directory descriptor
         dir = osAllocMem(sizeof(FsDir));

         //Successful memory allocation?
         if(dir != NULL)
         {
            //Initialize the directory descriptor
            osMemset(dir, 0, sizeof(FsDir));

            //Specify the search pattern
            strSafeCopy(dir->pattern, path, FS_MAX_PATH_LEN);
            pathCanonicalize(dir->pattern);
            pathCombine(dir->pattern, "*", FS_MAX_PATH_LEN);

            //Start a new search
            dir->fileInfo.fileID = 0;
         }
      }
      else
      {
         //The specified directory does not exist
         dir = NULL;
      }
   }
   else
   {
      //Invalid parameter
      dir = NULL;
   }

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
   error_t error;
   fsStatus status;

   //Check parameters
   if(dir == NULL || dirEntry == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear directory entry
   osMemset(dirEntry, 0, sizeof(FsDirEntry));

   //Read the specified directory
   status = ffind(dir->pattern, &dir->fileInfo);

   //Valid directory entry?
   if(status == fsOK)
   {
      //Copy the file name component
      strSafeCopy(dirEntry->name, dir->fileInfo.name, FS_MAX_NAME_LEN);

      //File attributes
      dirEntry->attributes = dir->fileInfo.attrib;
      //File size
      dirEntry->size = dir->fileInfo.size;

      //Time of last modification
      dirEntry->modified.year = dir->fileInfo.time.year;
      dirEntry->modified.month = dir->fileInfo.time.mon;
      dirEntry->modified.day = dir->fileInfo.time.day;
      dirEntry->modified.hours = dir->fileInfo.time.hr;
      dirEntry->modified.minutes = dir->fileInfo.time.min;
      dirEntry->modified.seconds = dir->fileInfo.time.sec;
      dirEntry->modified.milliseconds = 0;

      //Make sure the date is valid
      dirEntry->modified.month = MAX(dirEntry->modified.month, 1);
      dirEntry->modified.month = MIN(dirEntry->modified.month, 12);
      dirEntry->modified.day = MAX(dirEntry->modified.day, 1);
      dirEntry->modified.day = MIN(dirEntry->modified.day, 31);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //End of the directory stream
      error = ERROR_END_OF_STREAM;
   }

   //Return status code
   return error;
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
      //Release directory descriptor
      osFreeMem(dir);
   }
}
