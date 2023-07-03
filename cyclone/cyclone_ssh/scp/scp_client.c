/**
 * @file scp_client.c
 * @brief SCP client
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
#include "ssh/ssh_connection.h"
#include "ssh/ssh_transport.h"
#include "ssh/ssh_request.h"
#include "scp/scp_client.h"
#include "scp/scp_client_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SCP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Initialize SCP client context
 * @param[in] context Pointer to the SCP client context
 * @return Error code
 **/

error_t scpClientInit(ScpClientContext *context)
{
   //Make sure the SCP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear SCP client context
   osMemset(context, 0, sizeof(ScpClientContext));

   //Initialize SCP client state
   context->state = SCP_CLIENT_STATE_DISCONNECTED;
   //Default timeout
   context->timeout = SCP_CLIENT_DEFAULT_TIMEOUT;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register SSH initialization callback function
 * @param[in] context Pointer to the SCP client context
 * @param[in] callback SSH initialization callback function
 * @return Error code
 **/

error_t scpClientRegisterSshInitCallback(ScpClientContext *context,
   ScpClientSshInitCallback callback)
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
 * @param[in] context Pointer to the SCP client context
 * @param[in] timeout Timeout value, in milliseconds
 * @return Error code
 **/

error_t scpClientSetTimeout(ScpClientContext *context, systime_t timeout)
{
   //Make sure the SCP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Bind the SCP client to a particular network interface
 * @param[in] context Pointer to the SCP client context
 * @param[in] interface Network interface to be used
 * @return Error code
 **/

error_t scpClientBindToInterface(ScpClientContext *context,
   NetInterface *interface)
{
   //Make sure the SCP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Explicitly associate the SCP client with the specified interface
   context->interface = interface;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Establish a connection with the specified SCP server
 * @param[in] context Pointer to the SCP client context
 * @param[in] serverIpAddr IP address of the SCP server to connect to
 * @param[in] serverPort Port number
 * @return Error code
 **/

error_t scpClientConnect(ScpClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort)
{
   error_t error;

   //Make sure the SCP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Establish connection with the SCP server
   while(!error)
   {
      //Check current state
      if(context->state == SCP_CLIENT_STATE_DISCONNECTED)
      {
         //Open network connection
         error = scpClientOpenConnection(context);

         //Check status code
         if(!error)
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_CONNECTING_1);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CONNECTING_1)
      {
         //Establish network connection
         error = socketConnect(context->sshConnection.socket, serverIpAddr,
            serverPort);

         //Check status code
         if(error == NO_ERROR)
         {
            //Force the socket to operate in non-blocking mode
            socketSetTimeout(context->sshConnection.socket, 0);

            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_CONNECTING_2);
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Check whether the timeout has elapsed
            error = scpClientCheckTimeout(context);
         }
         else
         {
            //Communication error
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CONNECTING_2)
      {
         //Establish SSH connection
         error = scpClientEstablishConnection(context);
      }
      else if(context->state == SCP_CLIENT_STATE_CONNECTED)
      {
         //The SCP client is connected
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to establish connection with the SCP server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Clean up side effects
      scpClientCloseConnection(context);
      //Update SCP client state
      scpClientChangeState(context, SCP_CLIENT_STATE_DISCONNECTED);
   }

   //Return status code
   return error;
}


/**
 * @brief Open a file for writing
 * @param[in] context Pointer to the SCP client context
 * @param[in] path Path to the file to be be opened
 * @param[in] mode File permissions
 * @param[in] size Size of the file, in bytes
 * @return Error code
 **/

error_t scpClientOpenFileForWriting(ScpClientContext *context,
   const char_t *path, uint_t mode, uint64_t size)
{
   error_t error;
   ScpDirective directive;
   SshConnection *connection;
   SshChannel *channel;

   //Check parameters
   if(context == NULL || path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize SCP directive
   osMemset(&directive, 0, sizeof(ScpDirective));

   //Point to the SSH connection
   connection = &context->sshConnection;
   //Point to the SSH channel
   channel = &context->sshChannel;

   //Initialize status code
   error = NO_ERROR;

   //Open the specified file for writing
   while(!error)
   {
      //Check the state of the SCP client
      if(context->state == SCP_CLIENT_STATE_CONNECTED)
      {
         //Allocate a new SSH channel
         channel = sshCreateChannel(connection);

         //Valid channel handle?
         if(channel != NULL)
         {
            //Force the channel to operate in non-blocking mode
            error = sshSetChannelTimeout(channel, 0);

            //Check status code
            if(!error)
            {
               //The client sends an SSH_MSG_CHANNEL_OPEN message to the server
               //in order to open a new channel
               error = sshSendChannelOpen(channel, "session", NULL);
            }

            //Check status code
            if(!error)
            {
               //Update SCP client state
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_OPEN);
            }
         }
         else
         {
            //Report an error
            error = ERROR_OPEN_FAILED;
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CHANNEL_OPEN)
      {
         //Wait for server's response
         error = scpClientProcessEvents(context);

         //Check status code
         if(!error)
         {
            //Check the state of the channel
            if(channel->state == SSH_CHANNEL_STATE_RESERVED)
            {
               //Continue processing
            }
            else if(channel->state == SSH_CHANNEL_STATE_OPEN)
            {
               //An SSH_MSG_CHANNEL_OPEN_CONFIRMATION message has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_REQUEST);
            }
            else if(channel->state == SSH_CHANNEL_STATE_CLOSED)
            {
               //Release SSH channel
               sshDeleteChannel(&context->sshChannel);
               //Update SCP client state
               scpClientChangeState(context, SCP_CLIENT_STATE_CONNECTED);
               //An SSH_MSG_CHANNEL_OPEN_FAILURE message has been received
               error = ERROR_OPEN_FAILED;
            }
            else
            {
               //Invalid state
               error = ERROR_WRONG_STATE;
            }
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CHANNEL_REQUEST)
      {
         SshExecParams requestParams;

         //Format SCP command line
         sprintf(context->buffer, "scp -t %s", path);

         //Set "exec" request parameters
         requestParams.command.value = context->buffer;
         requestParams.command.length = osStrlen(context->buffer);

         //Send an SSH_MSG_CHANNEL_REQUEST message to the server
         error = sshSendChannelRequest(channel, "exec", &requestParams, TRUE);

         //Check status code
         if(!error)
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_REPLY);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CHANNEL_REPLY)
      {
         //Wait for server's response
         error = scpClientProcessEvents(context);

         //Check status code
         if(!error)
         {
            //Check the state of the channel request
            if(channel->requestState == SSH_REQUEST_STATE_PENDING)
            {
               //Continue processing
            }
            else if(channel->requestState == SSH_REQUEST_STATE_SUCCESS)
            {
               //An SSH_MSG_CHANNEL_SUCCESS message has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_WRITE_INIT);
            }
            else if(channel->requestState == SSH_REQUEST_STATE_FAILURE)
            {
               //An SSH_MSG_CHANNEL_FAILURE message has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_CLOSE);
            }
            else
            {
               //Invalid state
               error = ERROR_WRONG_STATE;
            }
         }
      }
      else if(context->state == SCP_CLIENT_STATE_WRITE_INIT)
      {
         //Wait for a status directive from the SCP server
         error = scpClientReceiveDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Check directive opcode
            if(directive.opcode == SCP_OPCODE_OK)
            {
               //A success directive has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_WRITE_COMMAND);
            }
            else
            {
               //A warning or an error message has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_CLOSE);
            }
         }
      }
      else if(context->state == SCP_CLIENT_STATE_WRITE_COMMAND)
      {
         //The 'C' directive indicates the next file to be transferred
         directive.opcode = SCP_OPCODE_FILE;
         directive.filename = pathGetFilename(path);
         directive.mode = mode;
         directive.size = size;

         //Send the directive to the SCP server
         error = scpClientSendDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Save the size of the file
            context->fileSize = size;
            context->fileOffset = 0;

            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_WRITE_ACK);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_WRITE_ACK)
      {
         //Wait for a status directive from the SCP server
         error = scpClientReceiveDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Check directive opcode
            if(directive.opcode == SCP_OPCODE_OK)
            {
               //A success directive has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_WRITE_DATA);
               //We are done
               break;
            }
            else
            {
               //A warning or an error message has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_CLOSE);
            }
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CHANNEL_CLOSE)
      {
         //When either party wishes to terminate the channel, it sends an
         //SSH_MSG_CHANNEL_CLOSE message
         error = sshCloseChannel(&context->sshChannel);

         //Check status code
         if(error == NO_ERROR)
         {
            //Wait for the SSH_MSG_CHANNEL_CLOSE message to be transmitted
            if(context->sshConnection.txBufferLen > 0)
            {
               //Flush pending data
               error = scpClientProcessEvents(context);
            }
            else
            {
               //Release SSH channel
               sshDeleteChannel(&context->sshChannel);
               //Update SCP client state
               scpClientChangeState(context, SCP_CLIENT_STATE_CONNECTED);
               //Report an error
               error = ERROR_UNEXPECTED_RESPONSE;
            }
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = scpClientProcessEvents(context);
         }
         else
         {
            //Just for sanity
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
 * @brief Open a file for reading
 * @param[in] context Pointer to the SCP client context
 * @param[in] path Path to the file to be be opened
 * @param[out] size Size of the file, in bytes (optional parameter)
 * @return Error code
 **/

error_t scpClientOpenFileForReading(ScpClientContext *context,
   const char_t *path, uint64_t *size)
{
   error_t error;
   ScpDirective directive;
   SshConnection *connection;
   SshChannel *channel;

   //Check parameters
   if(context == NULL || path == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize SCP directive
   osMemset(&directive, 0, sizeof(ScpDirective));

   //Point to the SSH connection
   connection = &context->sshConnection;
   //Point to the SSH channel
   channel = &context->sshChannel;

   //Initialize status code
   error = NO_ERROR;

   //Open the specified file for reading
   while(!error)
   {
      //Check the state of the SCP client
      if(context->state == SCP_CLIENT_STATE_CONNECTED)
      {
         //Allocate a new SSH channel
         channel = sshCreateChannel(connection);

         //Valid channel handle?
         if(channel != NULL)
         {
            //Force the channel to operate in non-blocking mode
            error = sshSetChannelTimeout(channel, 0);

            //Check status code
            if(!error)
            {
               //The client sends an SSH_MSG_CHANNEL_OPEN message to the server
               //in order to open a new channel
               error = sshSendChannelOpen(channel, "session", NULL);
            }

            //Check status code
            if(!error)
            {
               //Update SCP client state
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_OPEN);
            }
         }
         else
         {
            //Report an error
            error = ERROR_OPEN_FAILED;
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CHANNEL_OPEN)
      {
         //Wait for server's response
         error = scpClientProcessEvents(context);

         //Check status code
         if(!error)
         {
            //Check the state of the channel
            if(channel->state == SSH_CHANNEL_STATE_RESERVED)
            {
               //Continue processing
            }
            else if(channel->state == SSH_CHANNEL_STATE_OPEN)
            {
               //An SSH_MSG_CHANNEL_OPEN_CONFIRMATION message has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_REQUEST);
            }
            else if(channel->state == SSH_CHANNEL_STATE_CLOSED)
            {
               //Release SSH channel
               sshDeleteChannel(&context->sshChannel);
               //Update SCP client state
               scpClientChangeState(context, SCP_CLIENT_STATE_CONNECTED);
               //An SSH_MSG_CHANNEL_OPEN_FAILURE message has been received
               error = ERROR_OPEN_FAILED;
            }
            else
            {
               //Invalid state
               error = ERROR_WRONG_STATE;
            }
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CHANNEL_REQUEST)
      {
         SshExecParams requestParams;

         //Format SCP command line
         osSprintf(context->buffer, "scp -f %s", path);

         //Set "exec" request parameters
         requestParams.command.value = context->buffer;
         requestParams.command.length = osStrlen(context->buffer);

         //Send an SSH_MSG_CHANNEL_REQUEST message to the server
         error = sshSendChannelRequest(channel, "exec", &requestParams, TRUE);

         //Check status code
         if(!error)
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_REPLY);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CHANNEL_REPLY)
      {
         //Wait for server's response
         error = scpClientProcessEvents(context);

         //Check status code
         if(!error)
         {
            //Check the state of the channel request
            if(channel->requestState == SSH_REQUEST_STATE_PENDING)
            {
               //Continue processing
            }
            else if(channel->requestState == SSH_REQUEST_STATE_SUCCESS)
            {
               //An SSH_MSG_CHANNEL_SUCCESS message has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_READ_INIT);
            }
            else if(channel->requestState == SSH_REQUEST_STATE_FAILURE)
            {
               //An SSH_MSG_CHANNEL_FAILURE message has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_CLOSE);
            }
            else
            {
               //Invalid state
               error = ERROR_WRONG_STATE;
            }
         }
      }
      else if(context->state == SCP_CLIENT_STATE_READ_INIT)
      {
         //This status directive indicates a success
         directive.opcode = SCP_OPCODE_OK;
         //Send the directive to the SCP server
         error = scpClientSendDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_READ_COMMAND);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_READ_COMMAND)
      {
         //Wait for a directive from the SCP server
         error = scpClientReceiveDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Check directive opcode
            if(directive.opcode == SCP_OPCODE_FILE)
            {
               //Save the size of the file
               context->fileSize = directive.size;
               context->fileOffset = 0;

               //A valid directive has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_READ_ACK);
            }
            else
            {
               //A warning or an error message has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_CLOSE);
            }
         }
      }
      else if(context->state == SCP_CLIENT_STATE_READ_ACK)
      {
         //This status directive indicates a success
         directive.opcode = SCP_OPCODE_OK;
         //Send the directive to the SCP server
         error = scpClientSendDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_READ_DATA);
            //We are done
            break;
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CHANNEL_CLOSE)
      {
         //When either party wishes to terminate the channel, it sends an
         //SSH_MSG_CHANNEL_CLOSE message
         error = sshCloseChannel(&context->sshChannel);

         //Check status code
         if(error == NO_ERROR)
         {
            //Wait for the SSH_MSG_CHANNEL_CLOSE message to be transmitted
            if(context->sshConnection.txBufferLen > 0)
            {
               //Flush pending data
               error = scpClientProcessEvents(context);
            }
            else
            {
               //Release SSH channel
               sshDeleteChannel(&context->sshChannel);
               //Update SCP client state
               scpClientChangeState(context, SCP_CLIENT_STATE_CONNECTED);
               //Report an error
               error = ERROR_UNEXPECTED_RESPONSE;
            }
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = scpClientProcessEvents(context);
         }
         else
         {
            //Just for sanity
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(!error)
   {
      //The parameter is optional
      if(size != NULL)
      {
         //Return the size of the file, in bytes
         *size = context->fileSize;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Write to a remote file
 * @param[in] context Pointer to the SCP client context
 * @param[in] data Pointer to a buffer containing the data to be written
 * @param[in] length Number of data bytes to write
 * @param[in] written Number of bytes that have been written (optional parameter)
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t scpClientWriteFile(ScpClientContext *context, const void *data,
   size_t length, size_t *written, uint_t flags)
{
   error_t error;
   uint64_t m;
   size_t n;
   size_t totalLength;

   //Make sure the SCP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;
   //Actual number of bytes written
   totalLength = 0;

   //Write as much data as possible
   while(totalLength < length && !error)
   {
      //Check the state of the SCP client
      if(context->state == SCP_CLIENT_STATE_WRITE_DATA)
      {
         //Check file offset
         if(context->fileOffset < context->fileSize)
         {
            //Number of data bytes left to write
            m = context->fileSize - context->fileOffset;
            //Number of bytes available in the buffer
            n = length - totalLength;

            //Limit the number of bytes to write at a time
            if((uint64_t) n > m)
            {
               n = (size_t) m;
            }

            //Send more data
            error = sshWriteChannel(&context->sshChannel, data, n, &n, flags);

            //Check status code
            if(error == NO_ERROR || error == ERROR_TIMEOUT)
            {
               //Any data transmitted?
               if(n > 0)
               {
                  //Advance data pointer
                  data = (uint8_t *) data + n;
                  totalLength += n;

                  //Increment file offset
                  context->fileOffset += n;

                  //Save current time
                  context->timestamp = osGetSystemTime();
               }
            }

            //Check status code
            if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
            {
               //Process SSH connection events
               error = scpClientProcessEvents(context);
            }
         }
         else
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_WRITE_STATUS);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_WRITE_STATUS)
      {
         //Any data left to write?
         if(totalLength < length)
         {
            //The length of the data cannot exceed the value specified in
            //the SCP directive
            error = ERROR_INVALID_LENGTH;
         }
         else
         {
            //Successful write operation
            error = NO_ERROR;
         }

         //We are done
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //The parameter is optional
   if(written != NULL)
   {
      //Total number of data that have been written
      *written = totalLength;
   }

   //Return status code
   return error;
}


/**
 * @brief Read from a remote file
 * @param[in] context Pointer to the SCP client context
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be read
 * @param[out] received Actual number of bytes that have been read
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t scpClientReadFile(ScpClientContext *context, void *data, size_t size,
   size_t *received, uint_t flags)
{
   error_t error;
   uint64_t m;
   size_t n;

   //Check parameters
   if(context == NULL || data == NULL || received == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;
   //No data has been read yet
   *received = 0;

   //Read as much data as possible
   while(*received < size && !error)
   {
      //Check the state of the SCP client
      if(context->state == SCP_CLIENT_STATE_READ_DATA)
      {
         //Check file offset
         if(context->fileOffset < context->fileSize)
         {
            //Number of data bytes left to read
            m = context->fileSize - context->fileOffset;
            //Number of bytes available in the buffer
            n = size - *received;

            //Limit the number of bytes to read at a time
            if((uint64_t) n > m)
            {
               n = (size_t) m;
            }

            //Receive more data
            error = sshReadChannel(&context->sshChannel, data, n, &n, flags);

            //Check status code
            if(error == NO_ERROR)
            {
               //Advance data pointer
               data = (uint8_t *) data + n;
               *received += n;

               //Increment file offset
               context->fileOffset += n;

               //Save current time
               context->timestamp = osGetSystemTime();
            }
            else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
            {
               //Process SSH connection events
               error = scpClientProcessEvents(context);
            }
            else
            {
               //Communication error
            }
         }
         else
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_READ_STATUS);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_READ_STATUS)
      {
         //The user must be satisfied with data already on hand
         if(*received > 0)
         {
            //Some data are pending in the receive buffer
            error = NO_ERROR;
         }
         else
         {
            //The end of the file has been reached
            error = ERROR_END_OF_STREAM;
         }

         //We are done
         break;
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
 * @brief Close file
 * @param[in] context Pointer to the SCP client context
 * @return Error code
 **/

error_t scpClientCloseFile(ScpClientContext *context)
{
   error_t error;
   ScpDirective directive;

   //Make sure the SCP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize SCP directive
   osMemset(&directive, 0, sizeof(ScpDirective));

   //Initialize status code
   error = NO_ERROR;

   //Close the file
   while(!error)
   {
      //Check the state of the SCP client
      if(context->state == SCP_CLIENT_STATE_WRITE_INIT ||
         context->state == SCP_CLIENT_STATE_WRITE_COMMAND ||
         context->state == SCP_CLIENT_STATE_WRITE_ACK ||
         context->state == SCP_CLIENT_STATE_WRITE_DATA ||
         context->state == SCP_CLIENT_STATE_READ_INIT ||
         context->state == SCP_CLIENT_STATE_READ_COMMAND ||
         context->state == SCP_CLIENT_STATE_READ_ACK ||
         context->state == SCP_CLIENT_STATE_READ_DATA)
      {
         //Update SCP client state
         scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_CLOSE);
      }
      else if(context->state == SCP_CLIENT_STATE_WRITE_STATUS)
      {
         //This status directive indicates a success
         directive.opcode = SCP_OPCODE_OK;
         //Send the directive to the SCP server
         error = scpClientSendDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_WRITE_FIN);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_WRITE_FIN)
      {
         //Wait for a status directive from the SCP server
         error = scpClientReceiveDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Save SCP status code
            context->statusCode = directive.opcode;
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_CLOSE);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_READ_STATUS)
      {
         //Wait for a status directive from the SCP server
         error = scpClientReceiveDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Save SCP status code
            context->statusCode = directive.opcode;

            //Check directive opcode
            if(directive.opcode == SCP_OPCODE_OK)
            {
               //A success directive has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_READ_FIN);
            }
            else
            {
               //A warning or error directive has been received
               scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_CLOSE);
            }
         }
      }
      else if(context->state == SCP_CLIENT_STATE_READ_FIN)
      {
         //This status directive indicates a success
         directive.opcode = SCP_OPCODE_OK;
         //Send the directive to the SCP server
         error = scpClientSendDirective(context, &directive);

         //Check status code
         if(!error)
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_CHANNEL_CLOSE);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CHANNEL_CLOSE)
      {
         //When either party wishes to terminate the channel, it sends an
         //SSH_MSG_CHANNEL_CLOSE message
         error = sshCloseChannel(&context->sshChannel);

         //Check status code
         if(error == NO_ERROR)
         {
            //Wait for the SSH_MSG_CHANNEL_CLOSE message to be transmitted
            if(context->sshConnection.txBufferLen > 0)
            {
               //Flush pending data
               error = scpClientProcessEvents(context);
            }
            else
            {
               //Release SSH channel
               sshDeleteChannel(&context->sshChannel);
               //Update SCP client state
               scpClientChangeState(context, SCP_CLIENT_STATE_CONNECTED);
            }
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = scpClientProcessEvents(context);
         }
         else
         {
            //Just for sanity
         }
      }
      else if(context->state == SCP_CLIENT_STATE_CONNECTED)
      {
         //Check SCP status code
         if(context->statusCode == SCP_OPCODE_OK)
         {
            //A success directive has been received
            error = NO_ERROR;
         }
         else
         {
            //A warning or error directive has been received
            error = ERROR_UNEXPECTED_RESPONSE;
         }

         //We are done
         break;
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
 * @brief Gracefully disconnect from the SCP server
 * @param[in] context Pointer to the SCP client context
 * @return Error code
 **/

error_t scpClientDisconnect(ScpClientContext *context)
{
   error_t error;

   //Make sure the SCP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Gracefully disconnect from the SCP server
   while(!error)
   {
      //Check current state
      if(context->state == SCP_CLIENT_STATE_CONNECTED)
      {
         //Send an SSH_MSG_DISCONNECT message
         error = sshSendDisconnect(&context->sshConnection,
            SSH_DISCONNECT_BY_APPLICATION, "Connection closed by user");

         //Check status code
         if(!error)
         {
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_DISCONNECTING_1);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_DISCONNECTING_1)
      {
         //Wait for the SSH_MSG_DISCONNECT message to be transmitted
         error = scpClientProcessEvents(context);

         //Check status code
         if(error == ERROR_CONNECTION_CLOSING)
         {
            //Catch exception
            error = NO_ERROR;
            //Set timeout
            socketSetTimeout(context->sshConnection.socket, context->timeout);
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_DISCONNECTING_2);
         }
      }
      else if(context->state == SCP_CLIENT_STATE_DISCONNECTING_2)
      {
         //Shutdown TCP connection
         error = socketShutdown(context->sshConnection.socket, SOCKET_SD_BOTH);

         //Check status code
         if(error == NO_ERROR)
         {
            //Close network connection
            scpClientCloseConnection(context);
            //Update SCP client state
            scpClientChangeState(context, SCP_CLIENT_STATE_DISCONNECTED);
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Check whether the timeout has elapsed
            error = scpClientCheckTimeout(context);
         }
         else
         {
            //A communication error has occurred
         }
      }
      else if(context->state == SCP_CLIENT_STATE_DISCONNECTED)
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

   //Failed to gracefully disconnect from the SCP server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Close network connection
      scpClientCloseConnection(context);
      //Update SCP client state
      scpClientChangeState(context, SCP_CLIENT_STATE_DISCONNECTED);
   }

   //Return status code
   return error;
}


/**
 * @brief Close the connection with the SCP server
 * @param[in] context Pointer to the SCP client context
 * @return Error code
 **/

error_t scpClientClose(ScpClientContext *context)
{
   //Make sure the SCP client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Close network connection
   scpClientCloseConnection(context);
   //Update SCP client state
   scpClientChangeState(context, SCP_CLIENT_STATE_DISCONNECTED);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release SCP client context
 * @param[in] context Pointer to the SCP client context
 **/

void scpClientDeinit(ScpClientContext *context)
{
   //Make sure the SCP client context is valid
   if(context != NULL)
   {
      //Close network connection
      scpClientCloseConnection(context);

      //Clear SCP client context
      osMemset(context, 0, sizeof(ScpClientContext));
   }
}

#endif
