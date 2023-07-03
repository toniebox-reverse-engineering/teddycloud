/**
 * @file sftp_server_directory.c
 * @brief Directory operations
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
#include "sftp/sftp_server_directory.h"
#include "sftp/sftp_server_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SFTP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Create a directory
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Directory path
 * @param[in] attributes Modifications to be made to its attributes
 * @return Error code
 **/

error_t sftpServerCreateDir(SftpServerSession *session,
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

   //Retrieve permissions for the specified directory
   perm = sftpServerGetFilePermissions(session, context->path);
   //Insufficient access rights?
   if((perm & SFTP_FILE_PERM_WRITE) == 0)
      return ERROR_ACCESS_DENIED;

   //Create the specified directory
   error = fsCreateDir(context->path);

   //Return status code
   return error;
}


/**
 * @brief Remove a directory
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Directory path
 * @return Error code
 **/

error_t sftpServerRemoveDir(SftpServerSession *session,
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

   //Retrieve permissions for the specified directory
   perm = sftpServerGetFilePermissions(session, context->path);
   //Insufficient access rights?
   if((perm & SFTP_FILE_PERM_WRITE) == 0)
      return ERROR_ACCESS_DENIED;

   //Remove the specified directory
   error = fsRemoveDir(context->path);

   //Return status code
   return error;
}


/**
 * @brief Open a directory
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Path name of the directory to be listed
 * @param[out] handle Opaque value that identifies the directory
 * @return Error code
 **/

error_t sftpServerOpenDir(SftpServerSession *session,
   const SshString *path, uint32_t *handle)
{
   error_t error;
   uint_t i;
   uint_t perm;
   SftpServerContext *context;
   SftpFileObject *fileObject;

   //Point to the SFTP server context
   context = session->context;

   //Retrieve the full pathname
   error = sftpServerGetPath(session, path, context->path,
      SFTP_SERVER_MAX_PATH_LEN);
   //Any error to report?
   if(error)
      return error;

   //Retrieve permissions for the specified directory
   perm = sftpServerGetFilePermissions(session, context->path);
   //Insufficient access rights?
   if((perm & SFTP_FILE_PERM_READ) == 0)
      return ERROR_ACCESS_DENIED;

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
      //Open the specified directory
      fileObject->dir = fsOpenDir(context->path);

      //Valid handle?
      if(fileObject->dir != NULL)
      {
         //Initialize file object
         fileObject->type = SSH_FILEXFER_TYPE_DIRECTORY;
         fileObject->session = session;
         fileObject->size = 0;
         fileObject->offset = 0;
         fileObject->file = NULL;

         //Save path name
         osStrcpy(fileObject->path, context->path);

         //Generate a unique handle
         fileObject->handle = sftpServerGenerateHandle(session);

         //The SSH_FXP_OPENDIR request returns a handle which may be used to
         //access the directory later
         *handle = fileObject->handle;

         //The directory was successfully opened
         error = NO_ERROR;
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
 * @brief Read an entry from the specified directory
 * @param[in] session Handle referencing an SFTP session
 * @param[in] handle Opaque value that identifies the directory
 * @param[out] name File name being returned
 * @return Error code
 **/

error_t sftpServerReadDir(SftpServerSession *session,
   const SshBinaryString *handle, SftpName *name)
{
   error_t error;
   uint_t perm;
   FsDirEntry dirEntry;
   SftpServerContext *context;
   SftpFileObject *fileObject;

   //Initialize status code
   error = NO_ERROR;

   //Point to the SFTP server context
   context = session->context;

   //Clear name structure
   osMemset(name, 0, sizeof(SftpName));

   //The SSH_FXP_OPENDIR request returns a handle which may be used to
   //access the directory later
   fileObject = sftpServerFindDir(session, handle);
   //Invalid handle?
   if(fileObject == NULL)
      return ERROR_INVALID_HANDLE;

   //Loop through the directory
   while(!error)
   {
      //Read a new entry from the directory
      error = fsReadDir(fileObject->dir, &dirEntry);

      //Check status code
      if(!error)
      {
         //Retrieve the full pathname
         pathCopy(context->path, fileObject->path, SFTP_SERVER_MAX_PATH_LEN);
         pathCombine(context->path, dirEntry.name, SFTP_SERVER_MAX_PATH_LEN);
         pathCanonicalize(context->path);

         //Retrieve permissions for the specified file
         perm = sftpServerGetFilePermissions(session, context->path);

         //Check access rights?
         if((perm & SFTP_FILE_PERM_READ) != 0)
         {
            //Copy the file name
            osStrcpy(context->path, dirEntry.name);

            //File name
            name->filename.value = context->path;
            name->filename.length = osStrlen(context->path);

            //File type
            if((dirEntry.attributes & FS_FILE_ATTR_DIRECTORY) != 0)
            {
               name->attributes.type = SSH_FILEXFER_TYPE_DIRECTORY;
            }
            else
            {
               name->attributes.type = SSH_FILEXFER_TYPE_REGULAR;
            }

            //Size of the file
            name->attributes.size = dirEntry.size;

            //File permissions
            if((dirEntry.attributes & FS_FILE_ATTR_READ_ONLY) != 0)
            {
               name->attributes.permissions = SFTP_MODE_IRUSR;
            }
            else
            {
               name->attributes.permissions = SFTP_MODE_IRUSR | SFTP_MODE_IWUSR;
            }

            //Modification time
            name->attributes.mtime = dirEntry.modified;
            name->attributes.atime = dirEntry.modified;

            //Attribute bits
            if((dirEntry.attributes & FS_FILE_ATTR_READ_ONLY) != 0)
            {
               name->attributes.bits |= SSH_FILEXFER_ATTR_FLAGS_READONLY;
            }

            if((dirEntry.attributes & FS_FILE_ATTR_SYSTEM) != 0)
            {
               name->attributes.bits |= SSH_FILEXFER_ATTR_FLAGS_SYSTEM;
            }

            if((dirEntry.attributes & FS_FILE_ATTR_HIDDEN) != 0)
            {
               name->attributes.bits |= SSH_FILEXFER_ATTR_FLAGS_HIDDEN;
            }

            if((dirEntry.attributes & FS_FILE_ATTR_ARCHIVE) != 0)
            {
               name->attributes.bits |= SSH_FILEXFER_ATTR_FLAGS_ARCHIVE;
            }

            //Specify which of the attribute fields are present
            name->attributes.flags = SSH_FILEXFER_ATTR_SIZE |
               SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;

            //Successful processing
            break;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Close a directory
 * @param[in] session Handle referencing an SFTP session
 * @param[in] handle Opaque value that identifies the directory
 * @return Error code
 **/

error_t sftpServerCloseDir(SftpServerSession *session,
   const SshBinaryString *handle)
{
   error_t error;
   SftpFileObject *fileObject;

   //The SSH_FXP_OPENDIR request returns a handle which may be used to
   //access the directory later
   fileObject = sftpServerFindDir(session, handle);

   //Any matching directory?
   if(fileObject != NULL)
   {
      //Close directory
      fsCloseDir(fileObject->dir);
      fileObject->dir = NULL;

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
 * @brief Find the directory object that matches a given handle
 * @param[in] session Handle referencing an SFTP session
 * @param[in] handle Opaque variable-length string
 * @return Pointer to the matching directory object
 **/

SftpFileObject *sftpServerFindDir(SftpServerSession *session,
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
         if(fileObject->type == SSH_FILEXFER_TYPE_DIRECTORY &&
            fileObject->session == session &&
            fileObject->handle == LOAD32BE(handle->value))
         {
            //The handle matches the current directory object
            return fileObject;
         }
      }
   }

   //The handle does not match any active directory object
   return NULL;
}

#endif
