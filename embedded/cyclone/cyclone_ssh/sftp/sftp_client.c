/**
 * @file sftp_client.c
 * @brief SFTP client
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
#include "ssh/ssh_transport.h"
#include "sftp/sftp_client.h"
#include "sftp/sftp_client_packet.h"
#include "sftp/sftp_client_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SFTP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Initialize SFTP client context
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientInit(SftpClientContext *context)
{
   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear SFTP client context
   osMemset(context, 0, sizeof(SftpClientContext));

   //Initialize SFTP client state
   context->state = SFTP_CLIENT_STATE_DISCONNECTED;
   //Default timeout
   context->timeout = SFTP_CLIENT_DEFAULT_TIMEOUT;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register SSH initialization callback function
 * @param[in] context Pointer to the SFTP client context
 * @param[in] callback SSH initialization callback function
 * @return Error code
 **/

error_t sftpClientRegisterSshInitCallback(SftpClientContext *context,
   SftpClientSshInitCallback callback)
{
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->sshInitCallback = callback;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set communication timeout
 * @param[in] context Pointer to the SFTP client context
 * @param[in] timeout Timeout value, in milliseconds
 * @return Error code
 **/

error_t sftpClientSetTimeout(SftpClientContext *context, systime_t timeout)
{
   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Bind the SFTP client to a particular network interface
 * @param[in] context Pointer to the SFTP client context
 * @param[in] interface Network interface to be used
 * @return Error code
 **/

error_t sftpClientBindToInterface(SftpClientContext *context,
   NetInterface *interface)
{
   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Explicitly associate the SFTP client with the specified interface
   context->interface = interface;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Establish a connection with the specified SFTP server
 * @param[in] context Pointer to the SFTP client context
 * @param[in] serverIpAddr IP address of the SFTP server to connect to
 * @param[in] serverPort Port number
 * @return Error code
 **/

error_t sftpClientConnect(SftpClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort)
{
   error_t error;
   size_t n;
   SftpName name;

   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Establish connection with the SFTP server
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_DISCONNECTED)
      {
         //Open network connection
         error = sftpClientOpenConnection(context);

         //Check status code
         if(!error)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTING);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_CONNECTING)
      {
         //Establish network connection
         error = socketConnect(context->sshConnection.socket, serverIpAddr,
            serverPort);

         //Check status code
         if(error == NO_ERROR)
         {
            //Force the socket to operate in non-blocking mode
            socketSetTimeout(context->sshConnection.socket, 0);

            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CHANNEL_OPEN);
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Check whether the timeout has elapsed
            error = sftpClientCheckTimeout(context);
         }
         else
         {
            //Communication error
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_CHANNEL_OPEN ||
         context->state == SFTP_CLIENT_STATE_CHANNEL_OPEN_REPLY ||
         context->state == SFTP_CLIENT_STATE_CHANNEL_REQUEST ||
         context->state == SFTP_CLIENT_STATE_CHANNEL_REPLY)
      {
         //Establish SSH connection
         error = sftpClientEstablishConnection(context);
      }
      else if(context->state == SFTP_CLIENT_STATE_CHANNEL_DATA)
      {
         //Format SSH_FXP_INIT packet
         error = sftpClientFormatFxpInit(context, SFTP_CLIENT_MAX_VERSION);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_INIT request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_INIT request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(!error)
         {
            //Format SSH_FXP_REALPATH packet
            error = sftpClientFormatFxpRealPath(context, ".");
         }

         //Check status code
         if(!error)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_2);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_2)
      {
         //Send the SSH_FXP_REALPATH request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(!error)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_RECEIVING_NAME);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_RECEIVING_NAME)
      {
         //The server will respond to an SSH_FXP_REALPATH request with an
         //SSH_FXP_NAME packet containing only one name and dummy attributes
         error = sftpParseName(context->version, &name, context->buffer,
            context->responseLen, &n);

         //Check status code
         if(!error)
         {
            //Retrieve the length of the home directory
            n = name.filename.length;

            //Check the length of the pathname
            if(n <= SFTP_CLIENT_MAX_PATH_LEN)
            {
               //Save the home directory
               osStrncpy(context->currentDir, name.filename.value, n);
               //Properly terminate the string with a NULL character
               context->currentDir[n] = '\0';
            }
            else
            {
               //Use default home directory
               osStrcpy(context->currentDir, "");
            }

            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //The SFTP client is connected
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to establish connection with the SFTP server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Clean up side effects
      sftpClientCloseConnection(context);
      //Update SFTP client state
      sftpClientChangeState(context, SFTP_CLIENT_STATE_DISCONNECTED);
   }

   //Return status code
   return error;
}


/**
 * @brief Get current working directory
 * @param[in] context Pointer to the SFTP client context
 * @return Path of the current directory
 **/

const char_t *sftpClientGetWorkingDir(SftpClientContext *context)
{
   char_t *path;
   static char_t *defaultPath = "/";

   //Retrieve the path of the current directory
   if(context != NULL)
   {
      path = context->currentDir;
   }
   else
   {
      path = defaultPath;
   }

   //Return the pathname
   return path;
}


/**
 * @brief Change working directory
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path New current working directory
 * @return Error code
 **/

error_t sftpClientChangeWorkingDir(SftpClientContext *context,
   const char_t *path)
{
   error_t error;

   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Format SSH_FXP_OPENDIR packet
         error = sftpClientFormatFxpOpenDir(context, path);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_OPENDIR request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_OPENDIR request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR)
         {
            //Format SSH_FXP_CLOSE packet
            error = sftpClientFormatFxpClose(context, context->handle,
               context->handleLen);

            //Check status code
            if(!error)
            {
               //Send the SSH_FXP_CLOSE request and wait for the server's response
               sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_2);
            }
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_2)
      {
         //Send the SSH_FXP_CLOSE request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR)
         {
            //Get the path of the new working directory
            sftpGetAbsolutePath(context, path, (char_t *) context->buffer);
            //Save the resulting pathname
            osStrcpy(context->currentDir, (char_t *) context->buffer);

            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_UNEXPECTED_RESPONSE)
   {
      //Update SFTP client state
      sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
      //The specified directory does not exist
      error = ERROR_INVALID_DIRECTORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Change to parent directory
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientChangeToParentDir(SftpClientContext *context)
{
   //Change to the parent directory
   return sftpClientChangeWorkingDir(context, "..");
}


/**
 * @brief Open a directory
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Path to the directory to be be opened
 * @return Directory handle
 **/

error_t sftpClientOpenDir(SftpClientContext *context, const char_t *path)
{
   error_t error;

   //Check parameters
   if(context == NULL || path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Format SSH_FXP_OPENDIR packet
         error = sftpClientFormatFxpOpenDir(context, path);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_OPENDIR request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_OPENDIR request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR || error == ERROR_UNEXPECTED_RESPONSE)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Read an entry from the directory
 * @param[in] context Pointer to the SFTP client context
 * @param[out] dirEntry Pointer to a directory entry
 * @return Error code
 **/

error_t sftpClientReadDir(SftpClientContext *context, SftpDirEntry *dirEntry)
{
   error_t error;
   size_t n;
   SftpName name;

   //Check parameters
   if(context == NULL || dirEntry == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Format SSH_FXP_READDIR packet
         error = sftpClientFormatFxpReadDir(context, context->handle,
            context->handleLen);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_READDIR request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_READDIR request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_RECEIVING_NAME);
         }
         else if(error == ERROR_UNEXPECTED_RESPONSE)
         {
            //If there are no more names available to be read, the server
            //responds with an SSH_FX_EOF error code
            if(context->statusCode == SSH_FX_EOF)
            {
               //No more directory entries to return
               error = ERROR_END_OF_STREAM;
            }

            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
         }
         else
         {
            //Just for sanity
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_RECEIVING_NAME)
      {
         //Any data residue?
         if(context->responsePos > 0)
         {
            //Move the remaining data bytes to the start of the buffer
            osMemmove(context->buffer, context->buffer + context->responsePos,
               context->responseLen - context->responsePos);

            //Rewind to the beginning of the buffer
            context->dataLen -= context->responsePos;
            context->responseLen -= context->responsePos;
            context->responsePos = 0;
         }

         //Limit the number of bytes to read at a time
         n = MIN(context->dataLen, SFTP_CLIENT_BUFFER_SIZE);

         //Check whether there is any data left to read
         if(n == 0)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
         }
         else if(context->responseLen < n)
         {
            //Receive more data
            error = sshReadChannel(&context->sshChannel, context->buffer +
               context->responseLen, n - context->responseLen, &n, 0);

            //Check status code
            if(!error)
            {
               //Advance data pointer
               context->responseLen += n;
               //Save current time
               context->timestamp = osGetSystemTime();
            }

            //Check status code
            if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
            {
               //Process SSH connection events
               error = sftpClientProcessEvents(context);
            }
         }
         else
         {
            //One or more names may be returned at a time
            error = sftpParseName(context->version, &name,
               context->buffer + context->responsePos,
               context->responseLen - context->responsePos, &n);

            //Check status code
            if(!error)
            {
               //Advance data pointer
               context->responsePos += n;

               //Retrieve the length of the filename
               n = MIN(name.filename.length, SFTP_CLIENT_MAX_FILENAME_LEN);

               //Copy the filename
               osStrncpy(dirEntry->name, name.filename.value, n);
               //Properly terminate the string with a NULL character
               dirEntry->name[n] = '\0';

               //Save file attributes
               dirEntry->type = name.attributes.type;
               dirEntry->size = name.attributes.size;
               dirEntry->permissions = name.attributes.permissions;
               dirEntry->modified = name.attributes.mtime;
            }

            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Close directory
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientCloseDir(SftpClientContext *context)
{
   error_t error;

   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Format SSH_FXP_CLOSE packet
         error = sftpClientFormatFxpClose(context, context->handle,
            context->handleLen);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_CLOSE request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_CLOSE request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR || error == ERROR_UNEXPECTED_RESPONSE)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Create a new directory
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Name of the new directory
 * @return Error code
 **/

error_t sftpClientCreateDir(SftpClientContext *context, const char_t *path)
{
   error_t error;

   //Check parameters
   if(context == NULL || path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Format SSH_FXP_MKDIR packet
         error = sftpClientFormatFxpMkDir(context, path);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_MKDIR request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_MKDIR request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR || error == ERROR_UNEXPECTED_RESPONSE)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Remove a directory
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Path to the directory to be removed
 * @return Error code
 **/

error_t sftpClientDeleteDir(SftpClientContext *context, const char_t *path)
{
   error_t error;

   //Check parameters
   if(context == NULL || path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Format SSH_FXP_RMDIR packet
         error = sftpClientFormatFxpRmDir(context, path);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_RMDIR request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_RMDIR request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR || error == ERROR_UNEXPECTED_RESPONSE)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Open a file for reading, writing, or appending
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Path to the file to be be opened
 * @param[in] mode File access mode
 * @return Error code
 **/

error_t sftpClientOpenFile(SftpClientContext *context, const char_t *path,
   uint_t mode)
{
   error_t error;

   //Check parameters
   if(context == NULL || path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Rewind to the beginning of the file
         context->fileOffset = 0;

         //Format SSH_FXP_OPEN packet
         error = sftpClientFormatFxpOpen(context, path, mode);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_OPEN request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_OPEN request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR || error == ERROR_UNEXPECTED_RESPONSE)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Write to a remote file
 * @param[in] context Pointer to the SFTP client context
 * @param[in] data Pointer to a buffer containing the data to be written
 * @param[in] length Number of data bytes to write
 * @param[in] written Number of bytes that have been written (optional parameter)
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t sftpClientWriteFile(SftpClientContext *context, const void *data,
   size_t length, size_t *written, uint_t flags)
{
   error_t error;
   size_t n;
   size_t totalLength;

   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;
   //Actual number of bytes written
   totalLength = 0;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Send as much data as possible
         if(totalLength < length)
         {
            //The maximum size of packets is determined by the client
            n = MIN(length - totalLength, SFTP_CLIENT_MAX_PACKET_SIZE);

            //Format SSH_FXP_WRITE packet
            error = sftpClientFormatFxpWrite(context, context->handle,
               context->handleLen, context->fileOffset, n);

            //Check status code
            if(!error)
            {
               //Send the SSH_FXP_WRITE request
               sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_DATA);
            }
         }
         else
         {
            //We are done
            break;
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_DATA)
      {
         //Send the SSH_FXP_WRITE request
         if(context->requestPos < context->requestLen)
         {
            //Send more data
            error = sshWriteChannel(&context->sshChannel,
               context->buffer + context->requestPos,
               context->requestLen - context->requestPos, &n, flags);

            //Check status code
            if(error == NO_ERROR || error == ERROR_TIMEOUT)
            {
               //Any data transmitted?
               if(n > 0)
               {
                  //Advance data pointer
                  context->requestPos += n;
                  //Save current time
                  context->timestamp = osGetSystemTime();
               }
            }
         }
         else
         {
            //The length of the payload shall not exceed the length of the
            //'data' field specified in the SSH_FXP_WRITE packet
            n = MIN(length - totalLength, context->dataLen);

            //Check whether there is any data left to write
            if(n > 0)
            {
               //Send more data
               error = sshWriteChannel(&context->sshChannel,
                  (uint8_t *) data + totalLength, n, &n, flags);

               //Check status code
               if(error == NO_ERROR || error == ERROR_TIMEOUT)
               {
                  //Any data transmitted?
                  if(n > 0)
                  {
                     //Advance data pointer
                     totalLength += n;
                     context->dataLen -= n;

                     //Increment file offset
                     context->fileOffset += n;

                     //Save current time
                     context->timestamp = osGetSystemTime();
                  }
               }
            }
            else
            {
               //The total number of data written will be returned to the user
               //after the SSH_FXP_STATUS response has been received
               context->dataLen = totalLength;
               totalLength = 0;

               //Wait for the server's SSH_FXP_STATUS response
               sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
            }
         }

         //Check status code
         if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = sftpClientProcessEvents(context);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR || error == ERROR_UNEXPECTED_RESPONSE)
         {
            //Retrieve the total number of data written
            totalLength = context->dataLen;
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Total number of data that have been written
   if(written != NULL)
   {
      *written = totalLength;
   }

   //Check status code
   if(error == ERROR_WOULD_BLOCK)
   {
      //Any data written?
      if(totalLength > 0)
      {
         error = NO_ERROR;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Read from a remote file
 * @param[in] context Pointer to the SFTP client context
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be read
 * @param[out] received Actual number of bytes that have been read
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t sftpClientReadFile(SftpClientContext *context, void *data, size_t size,
   size_t *received, uint_t flags)
{
   error_t error;
   size_t n;

   //Check parameters
   if(context == NULL || data == NULL || received == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;
   //No data has been read yet
   *received = 0;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Read as much data as possible
         if(*received < size)
         {
            //The maximum size of packets is determined by the client
            n = MIN(size - *received, SFTP_CLIENT_MAX_PACKET_SIZE);

            //Format SSH_FXP_READ packet
            error = sftpClientFormatFxpRead(context, context->handle,
               context->handleLen, context->fileOffset, n);

            //Check status code
            if(!error)
            {
               //Send the SSH_FXP_READ request and wait for the server's response
               sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
            }
         }
         else
         {
            //We are done
            break;
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_READ request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_RECEIVING_DATA);
         }
         else if(error == ERROR_UNEXPECTED_RESPONSE)
         {
            //If there are no more data is available in the file, the server
            //responds with an SSH_FX_EOF error code
            if(context->statusCode == SSH_FX_EOF)
            {
               //The user must be satisfied with data already on hand
               if(*received > 0)
               {
                  //Some data are pending in the receive buffer
                  error = NO_ERROR;
                  break;
               }
               else
               {
                  //The SSH_FX_EOF error code indicates end-of-file condition
                  error = ERROR_END_OF_STREAM;
               }
            }

            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
         }
         else
         {
            //Just for sanity
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_RECEIVING_DATA)
      {
         //The length of the payload shall not exceed the length of the
         //'data' field specified in the SSH_FXP_WRITE packet
         n = MIN(size - *received, context->dataLen);

         //Check whether there is any data left to read
         if(n > 0)
         {
            //Receive more data
            error = sshReadChannel(&context->sshChannel, data, n, &n, flags);

            //Check status code
            if(!error)
            {
               //Advance data pointer
               data = (uint8_t *) data + n;
               *received += n;
               context->dataLen -= n;

               //Increment file offset
               context->fileOffset += n;

               //Save current time
               context->timestamp = osGetSystemTime();
            }

            //Check status code
            if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
            {
               //Process SSH connection events
               error = sftpClientProcessEvents(context);
            }
         }
         else
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_WOULD_BLOCK)
   {
      //The user must be satisfied with data already on hand
      if(*received > 0)
      {
         error = NO_ERROR;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Close file
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientCloseFile(SftpClientContext *context)
{
   error_t error;

   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Format SSH_FXP_CLOSE packet
         error = sftpClientFormatFxpClose(context, context->handle,
            context->handleLen);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_CLOSE request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_CLOSE request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR || error == ERROR_UNEXPECTED_RESPONSE)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Rename a file
 * @param[in] context Pointer to the SFTP client context
 * @param[in] oldPath Name of an existing file or directory
 * @param[in] newPath New name for the file or directory
 * @return Error code
 **/

error_t sftpClientRenameFile(SftpClientContext *context, const char_t *oldPath,
   const char_t *newPath)
{
   error_t error;

   //Check parameters
   if(context == NULL || oldPath == NULL || newPath == NULL)
      return ERROR_INVALID_PARAMETER;

   //The SSH_FXP_RENAME message was added in version 2
   if(context->version < SFTP_VERSION_2)
      return ERROR_INVALID_VERSION;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Format SSH_FXP_RENAME packet
         error = sftpClientFormatFxpRename(context, oldPath, newPath);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_RENAME request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_RENAME request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR || error == ERROR_UNEXPECTED_RESPONSE)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Delete a file
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Path to the file to be be deleted
 * @return Error code
 **/

error_t sftpClientDeleteFile(SftpClientContext *context, const char_t *path)
{
   error_t error;

   //Check parameters
   if(context == NULL || path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute SFTP command
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Format SSH_FXP_REMOVE packet
         error = sftpClientFormatFxpRemove(context, path);

         //Check status code
         if(!error)
         {
            //Send the SSH_FXP_REMOVE request and wait for the server's response
            sftpClientChangeState(context, SFTP_CLIENT_STATE_SENDING_COMMAND_1);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_SENDING_COMMAND_1)
      {
         //Send the SSH_FXP_REMOVE request and wait for the server's response
         error = sftpClientSendCommand(context);

         //Check status code
         if(error == NO_ERROR || error == ERROR_UNEXPECTED_RESPONSE)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CONNECTED);
            //We are done
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Retrieve SFTP status code
 * @param[in] context Pointer to the SFTP client context
 * @return SFTP status code
 **/

SftpStatusCode sftpClientGetStatusCode(SftpClientContext *context)
{
   SftpStatusCode statusCode;

   //Make sure the SFTP client context is valid
   if(context != NULL)
   {
      //Get SFTP status code
      statusCode = (SftpStatusCode) context->statusCode;
   }
   else
   {
      //The SFTP client context is not valid
      statusCode = SSH_FX_FAILURE;
   }

   //Return SFTP status code
   return statusCode;
}


/**
 * @brief Gracefully disconnect from the SFTP server
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientDisconnect(SftpClientContext *context)
{
   error_t error;

   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Gracefully disconnect from the SFTP server
   while(!error)
   {
      //Check current state
      if(context->state == SFTP_CLIENT_STATE_CONNECTED)
      {
         //Update SFTP client state
         sftpClientChangeState(context, SFTP_CLIENT_STATE_DISCONNECTING_1);
      }
      else if(context->state == SFTP_CLIENT_STATE_DISCONNECTING_1)
      {
         //When either party wishes to terminate the channel, it sends an
         //SSH_MSG_CHANNEL_CLOSE message
         error = sshCloseChannel(&context->sshChannel);

         //Check status code
         if(error == NO_ERROR)
         {
            //Send an SSH_MSG_DISCONNECT message
            error = sshSendDisconnect(&context->sshConnection,
               SSH_DISCONNECT_BY_APPLICATION, "Connection closed by user");

            //Check status code
            if(!error)
            {
               //Update SFTP client state
               sftpClientChangeState(context, SFTP_CLIENT_STATE_DISCONNECTING_2);
            }
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = sftpClientProcessEvents(context);
         }
         else
         {
            //Just for sanity
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_DISCONNECTING_2)
      {
         //Wait for the SSH_MSG_DISCONNECT message to be transmitted
         error = sftpClientProcessEvents(context);

         //Check status code
         if(error == ERROR_CONNECTION_CLOSING)
         {
            //Catch exception
            error = NO_ERROR;
            //Set timeout
            socketSetTimeout(context->sshConnection.socket, context->timeout);
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_DISCONNECTING_3);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_DISCONNECTING_3)
      {
         //Shutdown TCP connection
         error = socketShutdown(context->sshConnection.socket, SOCKET_SD_BOTH);

         //Check status code
         if(error == NO_ERROR)
         {
            //Close network connection
            sftpClientCloseConnection(context);
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_DISCONNECTED);
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Check whether the timeout has elapsed
            error = sftpClientCheckTimeout(context);
         }
         else
         {
            //A communication error has occurred
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_DISCONNECTED)
      {
         //We are done
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to gracefully disconnect from the SFTP server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Close network connection
      sftpClientCloseConnection(context);
      //Update SFTP client state
      sftpClientChangeState(context, SFTP_CLIENT_STATE_DISCONNECTED);
   }

   //Return status code
   return error;
}


/**
 * @brief Close the connection with the SFTP server
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientClose(SftpClientContext *context)
{
   //Make sure the SFTP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Close network connection
   sftpClientCloseConnection(context);
   //Update SFTP client state
   sftpClientChangeState(context, SFTP_CLIENT_STATE_DISCONNECTED);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release SFTP client context
 * @param[in] context Pointer to the SFTP client context
 **/

void sftpClientDeinit(SftpClientContext *context)
{
   //Make sure the SFTP client context is valid
   if(context != NULL)
   {
      //Close network connection
      sftpClientCloseConnection(context);

      //Clear SFTP client context
      osMemset(context, 0, sizeof(SftpClientContext));
   }
}

#endif
