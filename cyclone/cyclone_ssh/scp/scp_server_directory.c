/**
 * @file scp_server_directory.c
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
#define TRACE_LEVEL SCP_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "scp/scp_server.h"
#include "scp/scp_server_file.h"
#include "scp/scp_server_directory.h"
#include "scp/scp_server_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SCP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Create a directory
 * @param[in] session Handle referencing an SCP session
 * @param[in] name Directory name
 * @return Error code
 **/

error_t scpServerCreateDir(ScpServerSession *session, const char_t *name)
{
   error_t error;
   uint_t perm;

   //Change current directory
   pathCombine(session->path, name, SCP_SERVER_MAX_PATH_LEN);
   pathCanonicalize(session->path);
   pathRemoveSlash(session->path);

   //Check whether the directory exists or not
   if(!fsDirExists(session->path))
   {
      //Retrieve permissions for the specified directory
      perm = scpServerGetFilePermissions(session, session->path);

      //Check access rights
      if((perm & SCP_FILE_PERM_WRITE) != 0)
      {
         //Create a new directory
         error = fsCreateDir(session->path);

         //Failed to create directory?
         if(error)
         {
            //Report an error
            error = ERROR_DIRECTORY_NOT_FOUND;
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
      //The directory already exists
      error = NO_ERROR;
   }

   //Check status code
   if(!error)
   {
      //Increment recursion level
      session->dirLevel++;
   }

   //Return status code
   return error;
}


/**
 * @brief Open a directory
 * @param[in] session Handle referencing an SCP session
 * @return Error code
 **/

error_t scpServerOpenDir(ScpServerSession *session)
{
   error_t error;
   uint_t perm;

   //Retrieve permissions for the specified directory
   perm = scpServerGetFilePermissions(session, session->path);

   //Check access rights
   if((perm & SCP_FILE_PERM_READ) != 0)
   {
      //Open the specified directory
      session->dir[session->dirLevel] = fsOpenDir(session->path);

      //Valid directory pointer?
      if(session->dir[session->dirLevel] != NULL)
      {
         //The mode bits determine what actions the owner of the file can
         //perform on the file
         session->fileMode = SCP_MODE_IRWXU | SCP_MODE_IRWXG | SCP_MODE_IRWXO;

         //Successful processing
         error = NO_ERROR;
      }
      else
      {
         //Failed to open the directory
         error = ERROR_DIRECTORY_NOT_FOUND;
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
 * @brief Fetch the next entry from the directory
 * @param[in] session Handle referencing an SCP session
 **/

void scpServerGetNextDirEntry(ScpServerSession *session)
{
   error_t error;
   uint_t perm;
   FsDirEntry dirEntry;

   //Loop through the directory
   while(1)
   {
      //Read a new entry from the directory
      error = fsReadDir(session->dir[session->dirLevel], &dirEntry);

      //Check status code
      if(!error)
      {
         //Check file name
         if(!osStrcmp(dirEntry.name, ".") || !osStrcmp(dirEntry.name, ".."))
         {
            //Discard "." and ".." entries
         }
         else
         {
            //Retrieve the full path name
            pathCombine(session->path, dirEntry.name, SCP_SERVER_MAX_PATH_LEN);
            pathCanonicalize(session->path);

            //Retrieve permissions for the specified file
            perm = scpServerGetFilePermissions(session, session->path);

            //Check access rights
            if((perm & SCP_FILE_PERM_LIST) != 0)
            {
               //Check file type
               if((dirEntry.attributes & FS_FILE_ATTR_DIRECTORY) != 0)
               {
                  //Ensure the maximum recursion depth is not exceeded
                  if((session->dirLevel + 1) < SCP_SERVER_MAX_RECURSION_LEVEL)
                  {
                     //Increment recursion level
                     session->dirLevel++;

                     //Process the directory recursively
                     error = scpServerOpenDir(session);

                     //Failed to open directory?
                     if(error)
                     {
                        //Clean up side effects
                        session->dirLevel--;
                     }
                  }
                  else
                  {
                     //Maximum recursion depth exceeded
                     error = ERROR_OPEN_FAILED;
                  }
               }
               else
               {
                  //Open the file for reading
                  error = scpServerOpenFileForReading(session);
               }

               //Valid directory entry?
               if(!error)
               {
                  break;
               }
            }

            //Remove the file name from the path
            pathRemoveFilename(session->path);
            pathRemoveSlash(session->path);
         }
      }
      else
      {
         //The end of the directory has been reached
         break;
      }
   }

   //End of the directory?
   if(error)
   {
      //Close directory
      fsCloseDir(session->dir[session->dirLevel]);
      session->dir[session->dirLevel] = NULL;

      //Change to the parent directory
      if(session->dirLevel > 0)
      {
         pathRemoveFilename(session->path);
         pathRemoveSlash(session->path);
      }
   }

   //The source side feeds the commands and the target side consumes them
   session->state = SCP_SERVER_SESSION_STATE_READ_COMMAND;
}

#endif
