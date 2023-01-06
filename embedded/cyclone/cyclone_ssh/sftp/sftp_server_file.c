/**
 * @file sftp_server_file.c
 * @brief File operations
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSH Open.
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SFTP_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "sftp/sftp_server.h"
#include "sftp/sftp_server_file.h"
#include "sftp/sftp_server_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SFTP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Canonicalize a given path name to an absolute path
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Path name to be canonicalized
 * @param[out] name Name in canonical form
 * @return Error code
 **/

error_t sftpServerGetRealPath(SftpServerSession *session,
   const SshString *path, SftpName *name)
{
   error_t error;
   const char_t *p;
   SftpServerContext *context;

   //Point to the SFTP server context
   context = session->context;

   //Clear file attributes
   osMemset(name, 0, sizeof(SftpName));

   //Retrieve the full pathname
   error = sftpServerGetPath(session, path, context->path,
      SFTP_SERVER_MAX_PATH_LEN);
   //Any error to report?
   if(error)
      return error;

   //Strip the root directory from the pathname
   p = sftpServerStripRootDir(session, context->path);

   //The name structure contains the name in canonical form
   name->filename.value = p;
   name->filename.length = osStrlen(p);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve file attributes
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Path name of the file for which status is to be returned
 * @param[out] attributes File attributes
 * @return Error code
 **/

error_t sftpServerGetFileStat(SftpServerSession *session,
   const SshString *path, SftpFileAttrs *attributes)
{
   error_t error;
   uint_t perm;
   FsFileStat fileStat;
   SftpServerContext *context;

   //Point to the SFTP server context
   context = session->context;

   //Clear file attributes
   osMemset(attributes, 0, sizeof(SftpFileAttrs));

   //Retrieve the full pathname
   error = sftpServerGetPath(session, path, context->path,
      SFTP_SERVER_MAX_PATH_LEN);
   //Any error to report?
   if(error)
      return error;

   //Retrieve permissions for the specified file
   perm = sftpServerGetFilePermissions(session, context->path);
   //Insufficient access rights?
   if((perm & SFTP_FILE_PERM_READ) == 0)
      return ERROR_ACCESS_DENIED;

   //Retrieve the attributes of the specified file
   error = fsGetFileStat(context->path, &fileStat);
   //Any error to report?
   if(error)
      return error;

   //File type
   if((fileStat.attributes & FS_FILE_ATTR_DIRECTORY) != 0)
   {
      attributes->type = SSH_FILEXFER_TYPE_DIRECTORY;
   }
   else
   {
      attributes->type = SSH_FILEXFER_TYPE_REGULAR;
   }

   //Size of the file
   attributes->size = fileStat.size;

   //File permissions
   if((fileStat.attributes & FS_FILE_ATTR_READ_ONLY) != 0)
   {
      attributes->permissions = SFTP_MODE_IRUSR;
   }
   else
   {
      attributes->permissions = SFTP_MODE_IRUSR | SFTP_MODE_IWUSR;
   }

   //Modification time
   attributes->mtime = fileStat.modified;
   attributes->atime = fileStat.modified;

   //Attribute bits
   if((fileStat.attributes & FS_FILE_ATTR_READ_ONLY) != 0)
   {
      attributes->bits |= SSH_FILEXFER_ATTR_FLAGS_READONLY;
   }

   if((fileStat.attributes & FS_FILE_ATTR_SYSTEM) != 0)
   {
      attributes->bits |= SSH_FILEXFER_ATTR_FLAGS_SYSTEM;
   }

   if((fileStat.attributes & FS_FILE_ATTR_HIDDEN) != 0)
   {
      attributes->bits |= SSH_FILEXFER_ATTR_FLAGS_HIDDEN;
   }

   if((fileStat.attributes & FS_FILE_ATTR_ARCHIVE) != 0)
   {
      attributes->bits |= SSH_FILEXFER_ATTR_FLAGS_ARCHIVE;
   }

   //Specify which of the attribute fields are present
   attributes->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS |
      SSH_FILEXFER_ATTR_ACMODTIME;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve file attributes
 * @param[in] session Handle referencing an SFTP session
 * @param[in] handle Opaque value that identifies the file
 * @param[out] attributes File attributes
 * @return Error code
 **/

error_t sftpServerGetFileStatEx(SftpServerSession *session,
   const SshBinaryString *handle, SftpFileAttrs *attributes)
{
   error_t error;
   SshString path;
   SftpFileObject *fileObject;

   //The SSH_FXP_OPEN request returns a handle which may be used to access
   //the file later
   fileObject = sftpServerFindFile(session, handle);

   //Valid handle?
   if(fileObject != NULL)
   {
      //Get full path name
      path.value = sftpServerStripRootDir(session, fileObject->path);
      path.length = osStrlen(path.value);

      //Retrieve the attributes of the specified file
      error = sftpServerGetFileStat(session, &path, attributes);
   }
   else
   {
      //The supplied handle is not valid
      error = ERROR_INVALID_HANDLE;
   }

   //Return status code
   return error;
}


/**
 * @brief Modify file attributes
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Path name of the file
 * @param[in] attributes File attributes
 * @return Error code
 **/

error_t sftpServerSetFileStat(SftpServerSession *session,
   const SshString *path, const SftpFileAttrs *attributes)
{
   error_t error;
   uint_t perm;
   SftpServerContext *context;

   //Point to the SFTP server context
   context = session->context;

   //Retrieve the full pathname
   error = sftpServerGetPath(session, path, context->path,
      SFTP_SERVER_MAX_PATH_LEN);
   //Any error to report?
   if(error)
      return error;

   //Retrieve permissions for the specified file
   perm = sftpServerGetFilePermissions(session, context->path);
   //Insufficient access rights?
   if((perm & SFTP_FILE_PERM_READ) == 0)
      return ERROR_ACCESS_DENIED;

   //Modify file attributes
   return NO_ERROR;
}


/**
 * @brief Modify file attributes
 * @param[in] session Handle referencing an SFTP session
 * @param[in] handle Opaque value that identifies the file
 * @param[in] attributes File attributes
 * @return Error code
 **/

error_t sftpServerSetFileStatEx(SftpServerSession *session,
   const SshBinaryString *handle, const SftpFileAttrs *attributes)
{
   error_t error;
   SftpFileObject *fileObject;

   //The SSH_FXP_OPEN request returns a handle which may be used to access
   //the file later
   fileObject = sftpServerFindFile(session, handle);

   //Valid handle?
   if(fileObject != NULL)
   {
      //Modify file attributes
      error = NO_ERROR;
   }
   else
   {
      //The supplied handle is not valid
      error = ERROR_INVALID_HANDLE;
   }

   //Return status code
   return error;
}


/**
 * @brief Rename the specified file
 * @param[in] session Handle referencing an SFTP session
 * @param[in] oldPath Pathname of the file to be renamed
 * @param[in] newPath New filename
 * @return Error code
 **/

error_t sftpServerRenameFile(SftpServerSession *session,
   const SshString *oldPath, const SshString *newPath)
{
   error_t error;
   uint_t perm;
   char_t *path;
   SftpServerContext *context;

   //Point to the SFTP server context
   context = session->context;
   //Point to the scratch buffer
   path = (char_t *) session->buffer;

   //Retrieve the full pathname of the file to be renamed
   error = sftpServerGetPath(session, oldPath, context->path,
      SFTP_SERVER_MAX_PATH_LEN);
   //Any error to report?
   if(error)
      return error;

   //Retrieve permissions for the specified file
   perm = sftpServerGetFilePermissions(session, context->path);
   //Insufficient access rights?
   if((perm & SFTP_FILE_PERM_WRITE) == 0)
      return ERROR_ACCESS_DENIED;

   //Retrieve the full pathname of the new filename
   error = sftpServerGetPath(session, newPath, path,
      SFTP_SERVER_BUFFER_SIZE);
   //Any error to report?
   if(error)
      return error;

   //Retrieve permissions for the specified file
   perm = sftpServerGetFilePermissions(session, path);
   //Insufficient access rights?
   if((perm & SFTP_FILE_PERM_WRITE) == 0)
      return ERROR_ACCESS_DENIED;

   //Rename the specified file
   error = fsRenameFile(context->path, path);

   //Return status code
   return error;
}


/**
 * @brief Remove a file
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Pathname of the file to be removed
 * @return Error code
 **/

error_t sftpServerRemoveFile(SftpServerSession *session,
   const SshString *path)
{
   error_t error;
   uint_t perm;
   SftpServerContext *context;

   //Point to the SFTP server context
   context = session->context;

   //Retrieve the full pathname
   error = sftpServerGetPath(session, path, context->path,
      SFTP_SERVER_MAX_PATH_LEN);
   //Any error to report?
   if(error)
      return error;

   //Retrieve permissions for the specified file
   perm = sftpServerGetFilePermissions(session, context->path);
   //Insufficient access rights?
   if((perm & SFTP_FILE_PERM_WRITE) == 0)
      return ERROR_ACCESS_DENIED;

   //Delete the specified file
   error = fsDeleteFile(context->path);

   //Return status code
   return error;
}


/**
 * @brief Open a file
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Path name of the file
 * @param[in] pflags Bitmask that specifies the desired access mode
 * @param[in] attributes Initial attributes for the file
 * @param[out] handle Opaque value that identifies the file
 * @return Error code
 **/

error_t sftpServerOpenFile(SftpServerSession *session, const SshString *path,
   uint32_t pflags, const SftpFileAttrs *attributes, uint32_t *handle)
{
   error_t error;
   uint_t i;
   uint_t perm;
   uint_t mode;
   SftpServerContext *context;
   SftpFileObject *fileObject;
   FsFileStat fileStat;

   //Point to the SFTP server context
   context = session->context;

   //Retrieve the full pathname
   error = sftpServerGetPath(session, path, context->path,
      SFTP_SERVER_MAX_PATH_LEN);
   //Any error to report?
   if(error)
      return error;

   //Retrieve permissions for the specified file
   perm = sftpServerGetFilePermissions(session, context->path);

   //Check if the file is opened for reading or writing
   if((pflags & SSH_FXF_WRITE) != 0)
   {
      //Insufficient access rights?
      if((perm & SFTP_FILE_PERM_WRITE) == 0)
         return ERROR_ACCESS_DENIED;

      //Just for sanity
      fileStat.size = 0;
   }
   else
   {
      //Insufficient access rights?
      if((perm & SFTP_FILE_PERM_READ) == 0)
         return ERROR_ACCESS_DENIED;

      //Retrieve the attributes of the specified file
      error = fsGetFileStat(context->path, &fileStat);
      //Any error to report?
      if(error)
         return error;

      //Check file type
      if((fileStat.attributes & FS_FILE_ATTR_DIRECTORY) != 0)
         return ERROR_FILE_NOT_FOUND;
   }

   //Loop through file objects
   for(i = 0; i < context->numFileObjects; i++)
   {
      //Point to the current file object
      fileObject = &context->fileObjects[i];

      //Unused file object?
      if(fileObject->type == SSH_FILEXFER_TYPE_INVALID)
      {
         break;
      }
   }

   //Any file object available for use?
   if(i < context->numFileObjects)
   {
      //The 'pflags' field is a bitmask that specifies the desired access mode
      if((pflags & SSH_FXF_WRITE) != 0)
      {
         mode = FS_FILE_MODE_WRITE;
      }
      else
      {
         mode = FS_FILE_MODE_READ;
      }

      if((pflags & SSH_FXF_CREAT) != 0)
      {
         mode |= FS_FILE_MODE_CREATE;
      }

      if((pflags & SSH_FXF_TRUNC) != 0)
      {
         mode |= FS_FILE_MODE_TRUNC;
      }

      //Open the specified file
      fileObject->file = fsOpenFile(context->path, mode);

      //Valid handle?
      if(fileObject->file != NULL)
      {
         //Initialize file object
         fileObject->type = SSH_FILEXFER_TYPE_REGULAR;
         fileObject->session = session;
         fileObject->size = fileStat.size;
         fileObject->offset = 0;
         fileObject->dir = NULL;

         //Save path name
         osStrcpy(fileObject->path, context->path);

         //Generate a unique handle
         fileObject->handle = sftpServerGenerateHandle(session);

         //Check if the file is opened for appending
         if((pflags & SSH_FXF_APPEND) != 0)
         {
            //Move file pointer position to the end of the file
            error = fsSeekFile(fileObject->file, 0, FS_SEEK_END);
         }
         else
         {
            //Move file pointer position to the beginning of the file
            error = NO_ERROR;
         }

         //Check status code
         if(!error)
         {
            //The SSH_FXP_OPEN request returns a handle which may be used to
            //access the file later
            *handle = fileObject->handle;
         }
         else
         {
            //Clean up side effects
            fsCloseFile(fileObject->file);
            fileObject->file = NULL;

            //Mark the entry as free
            fileObject->type = SSH_FILEXFER_TYPE_INVALID;
         }
      }
      else
      {
         //The specified path name does not exist
         error = ERROR_OPEN_FAILED;
      }
   }
   else
   {
      //The file object table runs out of space
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Return status code
   return error;
}


/**
 * @brief Write the specified file
 * @param[in] session Handle referencing an SFTP session
 * @param[in] handle Opaque value that identifies the file
 * @param[in] offset Offset from the beginning of the file where to start
 *   writing
 * @param[in] data Data to be written
 * @param[in] fragLen Number of bytes available on hand
 * @param[in] totalLen Total length of the data, in bytes
 * @return Error code
 **/

error_t sftpServerWriteFile(SftpServerSession *session,
   const SshBinaryString *handle, uint64_t offset, const uint8_t *data,
   uint32_t fragLen, uint32_t totalLen)
{
   error_t error;
   SftpFileObject *fileObject;

   //Initialize status code
   error = NO_ERROR;

   //Save the length of the payload data
   session->dataLen = totalLen;
   session->bufferLen = MIN(totalLen, SFTP_SERVER_BUFFER_SIZE);
   session->bufferPos = fragLen;

   //The SSH_FXP_OPEN request returns a handle which may be used to access
   //the file later
   fileObject = sftpServerFindFile(session, handle);

   //Valid handle?
   if(fileObject != NULL)
   {
      //Check file offset
      if(offset != fileObject->offset)
      {
         //Move the file pointer position to the specified offset
         error = fsSeekFile(fileObject->file, (int_t) offset, FS_SEEK_SET);
      }

      //Check status code
      if(!error)
      {
         //Set up data transfer
         session->file = fileObject->file;
         fileObject->offset = offset + session->dataLen;
      }
   }
   else
   {
      //The supplied handle is not valid
      error = ERROR_INVALID_HANDLE;
   }

   //Move the data to the beginning of the buffer
   osMemmove(session->buffer, data, fragLen);

   //Save the status of the write operation
   session->requestStatus = error;
   //Consume the payload data before returning the SSH_FXP_STATUS response
   session->state = SFTP_SERVER_SESSION_STATE_RECEIVING_DATA;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Write data to the specified file
 * @param[in] session Handle referencing an SFTP session
 * @return Error code
 **/

error_t sftpServerWriteData(SftpServerSession *session)
{
   //Any data pending in the buffer?
   if(session->bufferLen > 0)
   {
      //Check the status of the write operation
      if(session->requestStatus == NO_ERROR)
      {
         //Write data to the specified file
         session->requestStatus = fsWriteFile(session->file, session->buffer,
            session->bufferLen);
      }

      //Number of bytes left to process
      session->dataLen -= session->bufferLen;

      //Set up next data transfer
      session->bufferLen = MIN(session->dataLen, SFTP_SERVER_BUFFER_SIZE);
      session->bufferPos = 0;
   }

   //Consume the payload data before returning the SSH_FXP_STATUS response
   return NO_ERROR;
}


/**
 * @brief Read the specified file
 * @param[in] session Handle referencing an SFTP session
 * @param[in] handle Opaque value that identifies the file
 * @param[in] offset Offset relative to the beginning of the file from where
 *   to start reading
 * @param[in,out] length Maximum number of bytes to read (input value) and
 *   actual length of the data (output value)
 * @return Error code
 **/

error_t sftpServerReadFile(SftpServerSession *session,
   const SshBinaryString *handle, uint64_t offset, uint32_t *length)
{
   error_t error;
   uint64_t n;
   SftpFileObject *fileObject;

   //Initialize status code
   error = NO_ERROR;

   //The SSH_FXP_OPEN request returns a handle which may be used to access
   //the file later
   fileObject = sftpServerFindFile(session, handle);

   //Valid handle?
   if(fileObject != NULL)
   {
      //Sanity check
      if(offset < fileObject->size)
      {
         //Check file offset
         if(offset != fileObject->offset)
         {
            //Move the file pointer position to the specified offset
            error = fsSeekFile(fileObject->file, (int_t) offset, FS_SEEK_SET);
         }

         //Check status code
         if(!error)
         {
            //The server reads as many bytes as it can from the file, up to
            //the specified length
            n = MIN(*length, fileObject->size - offset);

            //Set up data transfer
            session->file = fileObject->file;
            session->dataLen = (size_t) n;
            fileObject->offset = offset + session->dataLen;

            //Return the actual length of the payload data
            *length = session->dataLen;
         }
         else
         {
            //Terminate the data transfer
            error = ERROR_END_OF_STREAM;
         }
      }
      else
      {
         //The supplied offset is not valid
         error = ERROR_END_OF_STREAM;
      }
   }
   else
   {
      //The supplied handle is not valid
      error = ERROR_INVALID_HANDLE;
   }

   //Return status code
   return error;
}


/**
 * @brief Read data from the specified file
 * @param[in] session Handle referencing an SFTP session
 * @return error
 **/

error_t sftpServerReadData(SftpServerSession *session)
{
   error_t error;
   size_t n;
   size_t length;

   //Read an integral number of blocks
   length = SFTP_SERVER_BUFFER_SIZE - session->bufferLen;
   length = length - (length % 512);

   //Limit the number of bytes to read at a time
   length = MIN(length, session->dataLen);

   //Read data from the specified file
   error = fsReadFile(session->file, session->buffer + session->bufferLen,
      length, &n);

   //Check status code
   if(!error)
   {
      //Sanity check
      if(n == length)
      {
         //Number of bytes left to process
         session->dataLen -= n;

         //Update the length of the buffer
         session->bufferLen += n;
         session->bufferPos = 0;
      }
      else
      {
         //Report an error
         error = ERROR_READ_FAILED;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Close a file
 * @param[in] session Handle referencing an SFTP session
 * @param[in] handle File handle returned by SSH_FXP_OPEN
 * @return Error code
 **/

error_t sftpServerCloseFile(SftpServerSession *session,
   const SshBinaryString *handle)
{
   error_t error;
   SftpFileObject *fileObject;

   //The SSH_FXP_OPEN request returns a handle which may be used to access
   //the file later
   fileObject = sftpServerFindFile(session, handle);

   //Any matching directory?
   if(fileObject != NULL)
   {
      //Close file
      fsCloseFile(fileObject->file);
      fileObject->file = NULL;

      //Mark the entry as free
      fileObject->type = SSH_FILEXFER_TYPE_INVALID;

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //The supplied handle is not valid
      error = ERROR_INVALID_HANDLE;
   }

   //Return status code
   return error;
}


/**
 * @brief Find the file that matches a given handle
 * @param[in] session Handle referencing an SFTP session
 * @param[in] handle Opaque variable-length string
 * @return Pointer to the matching file object
 **/

SftpFileObject *sftpServerFindFile(SftpServerSession *session,
   const SshBinaryString *handle)
{
   uint_t i;
   SftpServerContext *context;
   SftpFileObject *fileObject;

   //Point to the SFTP server context
   context = session->context;

   //Valid handle?
   if(handle->length == sizeof(uint32_t))
   {
      //Loop through file objects
      for(i = 0; i < context->numFileObjects; i++)
      {
         //Point to the current file object
         fileObject = &context->fileObjects[i];

         //The handle can identify a file or a directory
         if(fileObject->type == SSH_FILEXFER_TYPE_REGULAR &&
            fileObject->session == session &&
            fileObject->handle == LOAD32BE(handle->value))
         {
            //The handle matches the current file object
            return fileObject;
         }
      }
   }

   //The handle does not match any active file object
   return NULL;
}

#endif
