/**
 * @file shell_client.c
 * @brief SSH secure shell client
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
#define TRACE_LEVEL SHELL_TRACE_LEVEL

//Dependencies
#include <stdarg.h>
#include "ssh/ssh.h"
#include "ssh/ssh_connection.h"
#include "ssh/ssh_transport.h"
#include "ssh/ssh_request.h"
#include "shell/shell_client.h"
#include "shell/shell_client_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SHELL_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Initialize shell client context
 * @param[in] context Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientInit(ShellClientContext *context)
{
   //Make sure the shell client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear shell client context
   osMemset(context, 0, sizeof(ShellClientContext));

   //Initialize shell client state
   context->state = SHELL_CLIENT_STATE_DISCONNECTED;
   //Default timeout
   context->timeout = SHELL_CLIENT_DEFAULT_TIMEOUT;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register SSH initialization callback function
 * @param[in] context Pointer to the shell client context
 * @param[in] callback SSH initialization callback function
 * @return Error code
 **/

error_t shellClientRegisterSshInitCallback(ShellClientContext *context,
   ShellClientSshInitCallback callback)
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
 * @param[in] context Pointer to the shell client context
 * @param[in] timeout Timeout value, in milliseconds
 * @return Error code
 **/

error_t shellClientSetTimeout(ShellClientContext *context, systime_t timeout)
{
   //Make sure the shell client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Bind the shell client to a particular network interface
 * @param[in] context Pointer to the shell client context
 * @param[in] interface Network interface to be used
 * @return Error code
 **/

error_t shellClientBindToInterface(ShellClientContext *context,
   NetInterface *interface)
{
   //Make sure the shell client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Explicitly associate the shell client with the specified interface
   context->interface = interface;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Establish a connection with the specified SSH server
 * @param[in] context Pointer to the shell client context
 * @param[in] serverIpAddr IP address of the SSH server to connect to
 * @param[in] serverPort Port number
 * @return Error code
 **/

error_t shellClientConnect(ShellClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort)
{
   error_t error;

   //Make sure the shell client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Establish connection with the SSH server
   while(!error)
   {
      //Check current state
      if(context->state == SHELL_CLIENT_STATE_DISCONNECTED)
      {
         //Open network connection
         error = shellClientOpenConnection(context);

         //Check status code
         if(!error)
         {
            //Update shell client state
            shellClientChangeState(context, SHELL_CLIENT_STATE_CONNECTING_1);
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_CONNECTING_1)
      {
         //Establish network connection
         error = socketConnect(context->sshConnection.socket, serverIpAddr,
            serverPort);

         //Check status code
         if(error == NO_ERROR)
         {
            //Force the socket to operate in non-blocking mode
            socketSetTimeout(context->sshConnection.socket, 0);

            //Update shell client state
            shellClientChangeState(context, SHELL_CLIENT_STATE_CONNECTING_2);
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Check whether the timeout has elapsed
            error = shellClientCheckTimeout(context);
         }
         else
         {
            //Communication error
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_CONNECTING_2)
      {
         //Establish SSH connection
         error = shellClientEstablishConnection(context);
      }
      else if(context->state == SHELL_CLIENT_STATE_CONNECTED)
      {
         //The shell client is connected
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to establish connection with the SSH server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Clean up side effects
      shellClientCloseConnection(context);
      //Update shell client state
      shellClientChangeState(context, SHELL_CLIENT_STATE_DISCONNECTED);
   }

   //Return status code
   return error;
}


/**
 * @brief Format a command line
 * @param[in] context Pointer to the shell client context
 * @param[in] command NULL-terminating string containing the command line
 * @param[in] ... Optional arguments
 * @return Error code
 **/

error_t shellClientFormatCommand(ShellClientContext *context,
   const char_t *command, ...)
{
   error_t error;

   //Check parameters
   if(context == NULL || command == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Execute the command line
   while(!error)
   {
      //Check the state of the shell client
      if(context->state == SHELL_CLIENT_STATE_CONNECTED)
      {
         size_t n;
         va_list args;

         //Initialize processing of a varying-length argument list
         va_start(args, command);

         //Format command line
         n = osVsnprintf(context->buffer, SHELL_CLIENT_BUFFER_SIZE, command,
            args);

         //End varying-length argument list processing
         va_end(args);

         //Check the length of the resulting string
         if(n < SHELL_CLIENT_BUFFER_SIZE)
         {
            //Update shell client state
            shellClientChangeState(context, SHELL_CLIENT_STATE_CHANNEL_INIT);
         }
         else
         {
            //A return value larger than or equal to buffer size means that the
            //output was truncated
            error = ERROR_BUFFER_OVERFLOW;
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_CHANNEL_INIT ||
         context->state == SHELL_CLIENT_STATE_CHANNEL_OPEN ||
         context->state == SHELL_CLIENT_STATE_CHANNEL_REQUEST ||
         context->state == SHELL_CLIENT_STATE_CHANNEL_REPLY ||
         context->state == SHELL_CLIENT_STATE_CHANNEL_CLOSE)
      {
         //Send the "exec" request
         error = shellClientExecuteCommand(context, context->buffer);
      }
      else if(context->state == SHELL_CLIENT_STATE_CHANNEL_DATA)
      {
         //An SSH_MSG_CHANNEL_SUCCESS message has been received
         shellClientChangeState(context, SHELL_CLIENT_STATE_CHANNEL_DATA);
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
 * @brief Execute a command line
 * @param[in] context Pointer to the shell client context
 * @param[in] command NULL-terminating string containing the command line
 * @return Error code
 **/

error_t shellClientExecuteCommand(ShellClientContext *context,
   const char_t *command)
{
   error_t error;
   SshConnection *connection;
   SshChannel *channel;

   //Check parameters
   if(context == NULL || command == NULL)
      return ERROR_INVALID_PARAMETER;

   //Point to the SSH connection
   connection = &context->sshConnection;
   //Point to the SSH channel
   channel = &context->sshChannel;

   //Initialize status code
   error = NO_ERROR;

   //Execute the command line
   while(!error)
   {
      //Check the state of the shell client
      if(context->state == SHELL_CLIENT_STATE_CONNECTED)
      {
         //Update shell client state
         shellClientChangeState(context, SHELL_CLIENT_STATE_CHANNEL_INIT);
      }
      else if(context->state == SHELL_CLIENT_STATE_CHANNEL_INIT)
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
               //Update shell client state
               shellClientChangeState(context, SHELL_CLIENT_STATE_CHANNEL_OPEN);
            }
         }
         else
         {
            //Update shell client state
            shellClientChangeState(context, SHELL_CLIENT_STATE_CONNECTED);
            //Report an error
            error = ERROR_OPEN_FAILED;
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_CHANNEL_OPEN)
      {
         //Wait for server's response
         error = shellClientProcessEvents(context);

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
               shellClientChangeState(context, SHELL_CLIENT_STATE_CHANNEL_REQUEST);
            }
            else if(channel->state == SSH_CHANNEL_STATE_CLOSED)
            {
               //Release SSH channel
               sshDeleteChannel(&context->sshChannel);
               //Update shell client state
               shellClientChangeState(context, SHELL_CLIENT_STATE_CONNECTED);
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
      else if(context->state == SHELL_CLIENT_STATE_CHANNEL_REQUEST)
      {
         SshExecParams requestParams;

         //Set "exec" request parameters
         requestParams.command.value = command;
         requestParams.command.length = osStrlen(command);

         //Send an SSH_MSG_CHANNEL_REQUEST message to the server
         error = sshSendChannelRequest(channel, "exec", &requestParams, TRUE);

         //Check status code
         if(!error)
         {
            //Update shell client state
            shellClientChangeState(context, SHELL_CLIENT_STATE_CHANNEL_REPLY);
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_CHANNEL_REPLY)
      {
         //Wait for server's response
         error = shellClientProcessEvents(context);

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
               shellClientChangeState(context, SHELL_CLIENT_STATE_CHANNEL_DATA);
               //We are done
               break;
            }
            else if(channel->requestState == SSH_REQUEST_STATE_FAILURE)
            {
               //An SSH_MSG_CHANNEL_FAILURE message has been received
               shellClientChangeState(context, SHELL_CLIENT_STATE_CHANNEL_CLOSE);
            }
            else
            {
               //Invalid state
               error = ERROR_WRONG_STATE;
            }
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_CHANNEL_CLOSE)
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
               error = shellClientProcessEvents(context);
            }
            else
            {
               //Release SSH channel
               sshDeleteChannel(&context->sshChannel);
               //Update shell client state
               shellClientChangeState(context, SHELL_CLIENT_STATE_CONNECTED);
               //Report an error
               error = ERROR_UNEXPECTED_RESPONSE;
            }
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = shellClientProcessEvents(context);
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
 * @brief Write to stdin stream
 * @param[in] context Pointer to the shell client context
 * @param[in] data Pointer to a buffer containing the data to be written
 * @param[in] length Number of data bytes to write
 * @param[in] written Number of bytes that have been written (optional parameter)
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t shellClientWriteStream(ShellClientContext *context, const void *data,
   size_t length, size_t *written, uint_t flags)
{
   error_t error;
   size_t n;
   size_t totalLength;

   //Make sure the shell client context is valid
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
      //Check the state of the shell client
      if(context->state == SHELL_CLIENT_STATE_CHANNEL_DATA)
      {
         //Write data to stdin stream
         error = sshWriteChannel(&context->sshChannel, data, length, &n, flags);

         //Check status code
         if(error == NO_ERROR || error == ERROR_TIMEOUT)
         {
            //Any data transmitted?
            if(n > 0)
            {
               //Advance data pointer
               data = (uint8_t *) data + n;
               totalLength += n;

               //Save current time
               context->timestamp = osGetSystemTime();
            }
         }

         //Check status code
         if(error == NO_ERROR)
         {
            //Successful write operation
            break;
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = shellClientProcessEvents(context);
         }
         else
         {
            //Communication error
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
      //Flush pending data
      error = shellClientFlushStream(context);
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
 * @brief Flush stdin stream
 * @param[in] context Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientFlushStream(ShellClientContext *context)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Check the state of the shell client
   if(context->state == SHELL_CLIENT_STATE_CHANNEL_DATA)
   {
      //Any data pending for transmission?
      while(context->sshChannel.txBuffer.length > 0 && !error)
      {
         //Flush pending data
         error = shellClientProcessEvents(context);
      }
   }
   else
   {
      //Invalid state
      error = ERROR_WRONG_STATE;
   }

   //Return error code
   return error;
}


/**
 * @brief Read from stdout stream
 * @param[in] context Pointer to the shell client context
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be read
 * @param[out] received Actual number of bytes that have been read
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t shellClientReadStream(ShellClientContext *context, void *data,
   size_t size, size_t *received, uint_t flags)
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

   //Read as much data as possible
   while(*received < size && !error)
   {
      //Check the state of the shell client
      if(context->state == SHELL_CLIENT_STATE_CHANNEL_DATA)
      {
         //Read more data
         error = sshReadChannel(&context->sshChannel, data, size, &n, flags);

         //Check status code
         if(error == NO_ERROR || error == ERROR_TIMEOUT)
         {
            //Any data received?
            if(n > 0)
            {
               //Advance data pointer
               data = (uint8_t *) data + n;
               *received += n;

               //Save current time
               context->timestamp = osGetSystemTime();
            }
         }

         //Check status code
         if(error == NO_ERROR)
         {
            //Successful read operation
            break;
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = shellClientProcessEvents(context);
         }
         else
         {
            //Communication error
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Check status code
   if(error == ERROR_END_OF_STREAM)
   {
      //Check flags
      if((flags & SSH_FLAG_BREAK_CHAR) != 0 || (flags & SSH_FLAG_WAIT_ALL) == 0)
      {
         //The user must be satisfied with data already on hand
         if(*received > 0)
         {
            error = NO_ERROR;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Close stream
 * @param[in] context Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientCloseStream(ShellClientContext *context)
{
   error_t error;
   size_t n;

   //Make sure the shell client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Close the file
   while(!error)
   {
      //Check the state of the shell client
      if(context->state == SHELL_CLIENT_STATE_CHANNEL_DATA)
      {
         //Discard data from stdout stream
         error = sshReadChannel(&context->sshChannel, context->buffer,
            SHELL_CLIENT_BUFFER_SIZE, &n, 0);

         //Check status code
         if(error == NO_ERROR)
         {
            //Save current time
            context->timestamp = osGetSystemTime();
         }
         else if(error == ERROR_END_OF_STREAM)
         {
            //An SSH_MSG_CHANNEL_EOF message has been received
            error = NO_ERROR;
            //Update shell client state
            shellClientChangeState(context, SHELL_CLIENT_STATE_CHANNEL_CLOSE);
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = shellClientProcessEvents(context);
         }
         else
         {
            //Communication error
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_CHANNEL_CLOSE)
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
               error = shellClientProcessEvents(context);
            }
            else
            {
               //Release SSH channel
               sshDeleteChannel(&context->sshChannel);
               //Update shell client state
               shellClientChangeState(context, SHELL_CLIENT_STATE_CONNECTED);
            }
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Process SSH connection events
            error = shellClientProcessEvents(context);
         }
         else
         {
            //Just for sanity
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_CONNECTED)
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

   //Return status code
   return error;
}


/**
 * @brief Retrieve exit status
 * @param[in] context Pointer to the shell client context
 * @return Exit status
 **/

uint32_t shellClientGetExitStatus(ShellClientContext *context)
{
   uint32_t exitStatus;

   //Make sure the shell client context is valid
   if(context != NULL)
   {
      //Get exit status
      exitStatus = context->exitStatus;
   }
   else
   {
      //The shell client context is not valid
      exitStatus = 0;
   }

   //Return exit status
   return exitStatus;
}


/**
 * @brief Gracefully disconnect from the SSH server
 * @param[in] context Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientDisconnect(ShellClientContext *context)
{
   error_t error;

   //Make sure the shell client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Gracefully disconnect from the SSH server
   while(!error)
   {
      //Check current state
      if(context->state == SHELL_CLIENT_STATE_CONNECTED)
      {
         //Send an SSH_MSG_DISCONNECT message
         error = sshSendDisconnect(&context->sshConnection,
            SSH_DISCONNECT_BY_APPLICATION, "Connection closed by user");

         //Check status code
         if(!error)
         {
            //Update shell client state
            shellClientChangeState(context, SHELL_CLIENT_STATE_DISCONNECTING_1);
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_DISCONNECTING_1)
      {
         //Wait for the SSH_MSG_DISCONNECT message to be transmitted
         error = shellClientProcessEvents(context);

         //Check status code
         if(error == ERROR_CONNECTION_CLOSING)
         {
            //Catch exception
            error = NO_ERROR;
            //Set timeout
            socketSetTimeout(context->sshConnection.socket, context->timeout);
            //Update shell client state
            shellClientChangeState(context, SHELL_CLIENT_STATE_DISCONNECTING_2);
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_DISCONNECTING_2)
      {
         //Shutdown TCP connection
         error = socketShutdown(context->sshConnection.socket, SOCKET_SD_BOTH);

         //Check status code
         if(error == NO_ERROR)
         {
            //Close network connection
            shellClientCloseConnection(context);
            //Update shell client state
            shellClientChangeState(context, SHELL_CLIENT_STATE_DISCONNECTED);
         }
         else if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
         {
            //Check whether the timeout has elapsed
            error = shellClientCheckTimeout(context);
         }
         else
         {
            //A communication error has occurred
         }
      }
      else if(context->state == SHELL_CLIENT_STATE_DISCONNECTED)
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

   //Failed to gracefully disconnect from the SSH server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Close network connection
      shellClientCloseConnection(context);
      //Update shell client state
      shellClientChangeState(context, SHELL_CLIENT_STATE_DISCONNECTED);
   }

   //Return status code
   return error;
}


/**
 * @brief Close the connection with the SSH server
 * @param[in] context Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientClose(ShellClientContext *context)
{
   //Make sure the shell client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Close network connection
   shellClientCloseConnection(context);
   //Update shell client state
   shellClientChangeState(context, SHELL_CLIENT_STATE_DISCONNECTED);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release shell client context
 * @param[in] context Pointer to the shell client context
 **/

void shellClientDeinit(ShellClientContext *context)
{
   //Make sure the shell client context is valid
   if(context != NULL)
   {
      //Close network connection
      shellClientCloseConnection(context);

      //Clear shell client context
      osMemset(context, 0, sizeof(ShellClientContext));
   }
}

#endif
