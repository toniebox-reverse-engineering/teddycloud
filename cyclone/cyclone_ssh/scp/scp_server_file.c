/**
 * @file scp_server_file.c
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
#define TRACE_LEVEL SCP_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "scp/scp_server.h"
#include "scp/scp_server_file.h"
#include "scp/scp_server_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SCP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Open a file for writing
 * @param[in] session Handle referencing an SCP session
 * @param[in] filename NULL-terminating string that contains the filename
 * @param[in] mode File access rights
 * @param[in] size Size of the file, in bytes
 * @return Error code
 **/

error_t scpServerOpenFileForWriting(ScpServerSession *session,
   const char_t *filename, uint32_t mode, uint64_t size)
{
   error_t error;
   uint_t perm;
   ScpServerContext *context;

   //Point to the SCP server context
   context = session->context;

   //The SCP command line can specify either a file or a directory
   if(fsDirExists(session->path) || session->recursive)
   {
      //Retrieve the full pathname
      pathCopy(context->path, session->path, SCP_SERVER_MAX_PATH_LEN);
      pathCombine(context->path, filename, SCP_SERVER_MAX_PATH_LEN);
      pathCanonicalize(context->path);
   }
   else
   {
      //Copy the full pathname
      pathCopy(context->path, session->path, SCP_SERVER_MAX_PATH_LEN);
   }

   //Retrieve permissions for the specified file
   perm = scpServerGetFilePermissions(session, context->path);

   //Check access rights
   if((perm & SCP_FILE_PERM_WRITE) != 0)
   {
      //Open the file for writing
      session->file = fsOpenFile(context->path, FS_FILE_MODE_WRITE |
         FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);

      //Valid file pointer?
      if(session->file != NULL)
      {
         //Save the size of the file
         session->fileSize = size;
         session->fileOffset = 0;

         //Successful processing
         error = NO_ERROR;
      }
      else
      {
         //Failed to open the file
         error = ERROR_FILE_NOT_FOUND;
      }
   }
   else
   {
      //Insufficient access rights
      error = ERROR_ACCESS_DENIED;
   }

   //Return status code
   return error;
}


/**
 * @brief Open a file for reading
 * @param[in] session Handle referencing an SCP session
 * @return Error code
 **/

error_t scpServerOpenFileForReading(ScpServerSession *session)
{
   error_t error;
   uint_t perm;
   FsFileStat fileStat;

   //Retrieve the attributes of the specified file
   error = fsGetFileStat(session->path, &fileStat);

   //Check status code
   if(!error)
   {
      //Check file type
      if((fileStat.attributes & FS_FILE_ATTR_DIRECTORY) == 0)
      {
         //Retrieve permissions for the specified file
         perm = scpServerGetFilePermissions(session, session->path);

         //Check access rights
         if((perm & SCP_FILE_PERM_READ) != 0)
         {
            //Open the file for reading
            session->file = fsOpenFile(session->path, FS_FILE_MODE_READ);

            //Valid file pointer?
            if(session->file != NULL)
            {
               //Save the size of the file
               session->fileSize = fileStat.size;
               session->fileOffset = 0;

               //The mode bits determine what actions the owner of the file
               //can perform on the file
               if((fileStat.attributes & FS_FILE_ATTR_READ_ONLY) != 0)
               {
                  session->fileMode = SCP_MODE_IRUSR | SCP_MODE_IRGRP |
                     SCP_MODE_IROTH;
               }
               else
               {
                  session->fileMode = SCP_MODE_IRUSR | SCP_MODE_IWUSR |
                     SCP_MODE_IRGRP | SCP_MODE_IWGRP | SCP_MODE_IROTH |
                     SCP_MODE_IWOTH;
               }

               //Successful processing
               error = NO_ERROR;
            }
            else
            {
               //Failed to open the file
               error = ERROR_FILE_NOT_FOUND;
            }
         }
         else
         {
            //Insufficient access rights
            error = ERROR_ACCESS_DENIED;
         }
      }
      else
      {
         //The path name does references a file but a directory
         error = ERROR_FILE_NOT_FOUND;
      }
   }
   else
   {
      //The specified file does not exist
      error = ERROR_FILE_NOT_FOUND;
   }

   //Return status code
   return error;
}


/**
 * @brief Write data to the specified file
 * @param[in] session Handle referencing an SCP session
 * @return Error code
 **/

error_t scpServerWriteData(ScpServerSession *session)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Receive file content from the SCP client
   if(session->bufferPos < session->bufferLen)
   {
      //Receive more data
      error = sshReadChannel(session->channel,
         session->buffer + session->bufferPos,
         session->bufferLen - session->bufferPos, &n, 0);

      //Check status code
      if(!error)
      {
         //Advance data pointer
         session->bufferPos += n;
      }
   }
   else if(session->fileOffset < session->fileSize)
   {
      //Any data pending in the buffer?
      if(session->bufferLen > 0)
      {
         //Check the status of the write operation
         if(session->statusCode == NO_ERROR)
         {
            //Write data to the specified file
            session->statusCode = fsWriteFile(session->file, session->buffer,
               session->bufferLen);
         }

         //Increment file offset
         session->fileOffset += session->bufferLen;
      }

      //Limit the number of bytes to copy at a time
      if((session->fileSize - session->fileOffset) < SCP_SERVER_BUFFER_SIZE)
      {
         n = (size_t) (session->fileSize - session->fileOffset);
      }
      else
      {
         n = SCP_SERVER_BUFFER_SIZE;
      }

      //Set up next data transfer
      session->bufferLen = n;
      session->bufferPos = 0;
   }
   else
   {
      //Close file
      fsCloseFile(session->file);
      session->file = NULL;

      //Flush receive buffer
      session->bufferLen = 0;
      session->bufferPos = 0;

      //Update SCP session state
      if(session->statusCode == NO_ERROR)
      {
         session->state = SCP_SERVER_SESSION_STATE_WRITE_STATUS;
      }
      else
      {
         session->state = SCP_SERVER_SESSION_STATE_ERROR;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Read data from the specified file
 * @param[in] session Handle referencing an SCP session
 * @return error
 **/

error_t scpServerReadData(ScpServerSession *session)
{
   error_t error;
   size_t n;
   size_t length;

   //Initialize status code
   error = NO_ERROR;

   //Send file content to the SCP client
   if(session->bufferPos < session->bufferLen)
   {
      //Send more data
      error = sshWriteChannel(session->channel,
         session->buffer + session->bufferPos,
         session->bufferLen - session->bufferPos, &n, 0);

      //Check status code
      if(error == NO_ERROR || error == ERROR_TIMEOUT)
      {
         //Advance data pointer
         session->bufferPos += n;
      }
   }
   else if(session->fileOffset < session->fileSize)
   {
      //Limit the number of bytes to copy at a time
      if((session->fileSize - session->fileOffset) < SCP_SERVER_BUFFER_SIZE)
      {
         length = (size_t) (session->fileSize - session->fileOffset);
      }
      else
      {
         length = SCP_SERVER_BUFFER_SIZE;
      }

      //Read data from the specified file
      error = fsReadFile(session->file, session->buffer, length, &n);

      //Check status code
      if(!error)
      {
         //Sanity check
         if(n == length)
         {
            //Increment file offset
            session->fileOffset += n;

            //Set up next data transfer
            session->bufferLen = n;
            session->bufferPos = 0;
         }
         else
         {
            //Report an error
            error = ERROR_READ_FAILED;
         }
      }
   }
   else
   {
      //Close file
      fsCloseFile(session->file);
      session->file = NULL;

      //Recursive copy?
      if(session->recursive)
      {
         //Remove the file name from the path
         pathRemoveFilename(session->path);
         pathRemoveSlash(session->path);
      }

      //Flush transmit buffer
      session->bufferLen = 0;
      session->bufferPos = 0;

      //Update SCP session state
      session->state = SCP_SERVER_SESSION_STATE_READ_STATUS;
   }

   //Return status code
   return error;
}

#endif
