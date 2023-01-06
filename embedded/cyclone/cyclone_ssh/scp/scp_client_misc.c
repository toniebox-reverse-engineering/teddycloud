/**
 * @file scp_client_misc.c
 * @brief Helper functions for SCP client
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
#include "ssh/ssh_request.h"
#include "ssh/ssh_misc.h"
#include "scp/scp_client.h"
#include "scp/scp_client_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SCP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Update SCP client state
 * @param[in] context Pointer to the SCP client context
 * @param[in] newState New state to switch to
 **/

void scpClientChangeState(ScpClientContext *context,
   ScpClientState newState)
{
   //Switch to the new state
   context->state = newState;

   //Save current time
   context->timestamp = osGetSystemTime();
}


/**
 * @brief Open SSH connection
 * @param[in] context Pointer to the SCP client context
 * @return Error code
 **/

error_t scpClientOpenConnection(ScpClientContext *context)
{
   error_t error;
   Socket *socket;
   SshConnection *connection;

   //Initialize SSH context
   error = sshInit(&context->sshContext, &context->sshConnection, 1,
      &context->sshChannel, 1);
   //Any error to report?
   if(error)
      return error;

   //Select client operation mode
   error = sshSetOperationMode(&context->sshContext, SSH_OPERATION_MODE_CLIENT);
   //Any error to report?
   if(error)
      return error;

   //Invoke user-defined callback, if any
   if(context->sshInitCallback != NULL)
   {
      //Perform SSH related initialization
      error = context->sshInitCallback(context, &context->sshContext);
      //Any error to report?
      if(error)
         return error;
   }

   //Open a TCP socket
   socket = socketOpen(SOCKET_TYPE_STREAM, SOCKET_IP_PROTO_TCP);

   //Valid socket handle
   if(socket != NULL)
   {
      //Associate the socket with the relevant interface
      socketBindToInterface(socket, context->interface);
      //Set timeout
      socketSetTimeout(socket, context->timeout);

      //Open a new SSH connection
      connection = sshOpenConnection(&context->sshContext, socket);

      //Failed to open connection?
      if(connection == NULL)
      {
         //Clean up side effects
         socketClose(socket);
         //Report an error
         error = ERROR_OPEN_FAILED;
      }
   }
   else
   {
      //Failed to open socket
      error = ERROR_OPEN_FAILED;
   }

   //Return status code
   return error;
}


/**
 * @brief Establish SSH connection
 * @param[in] context Pointer to the SCP client context
 * @return Error code
 **/

error_t scpClientEstablishConnection(ScpClientContext *context)
{
   error_t error;

   //Check the state of the SSH connection
   if(context->sshConnection.state < SSH_CONN_STATE_OPEN)
   {
      //Perform SSH key exchange and user authentication
      error = scpClientProcessEvents(context);
   }
   else if(context->sshConnection.state == SSH_CONN_STATE_OPEN)
   {
      //The SSH connection is established
      scpClientChangeState(context, SCP_CLIENT_STATE_CONNECTED);
      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Invalid state
      error = ERROR_WRONG_STATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Close SSH connection
 * @param[in] context Pointer to the SCP client context
 **/

void scpClientCloseConnection(ScpClientContext *context)
{
   //Check the state of the SSH connection
   if(context->sshConnection.state != SSH_CONN_STATE_CLOSED)
   {
      //Close SSH connection
      sshCloseConnection(&context->sshConnection);
   }

   //Release SSH context
   sshDeinit(&context->sshContext);
}


/**
 * @brief Send a SCP directive to the server
 * @param[in] context Pointer to the SCP client context
 * @param[in] directive SCP directive parameters
 * @return Error code
 **/

error_t scpClientSendDirective(ScpClientContext *context,
   const ScpDirective *directive)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Format and and send status message
   while(!error)
   {
      //Manage message transmission
      if(context->bufferLen == 0)
      {
         //Format directive line
         n = scpFormatDirective(directive, context->buffer);

         //Save the length of the directive line
         context->bufferLen = n;
         context->bufferPos = 0;
      }
      else if(context->bufferPos < context->bufferLen)
      {
         //Send more data
         error = sshWriteChannel(&context->sshChannel,
            context->buffer + context->bufferPos,
            context->bufferLen - context->bufferPos, &n, 0);

         //Check status code
         if(error == NO_ERROR || error == ERROR_TIMEOUT)
         {
            //Advance data pointer
            context->bufferPos += n;
         }
      }
      else
      {
         //Flush transmit buffer
         context->bufferLen = 0;
         context->bufferPos = 0;

         //We are done
         break;
      }

      //Check status code
      if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
      {
         //Process SSH connection events
         error = scpClientProcessEvents(context);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Receive a SCP directive from the server
 * @param[in] context Pointer to the SCP client context
 * @param[in] directive SCP directive parameters
 * @return Error code
 **/

error_t scpClientReceiveDirective(ScpClientContext *context,
   ScpDirective *directive)
{
   error_t error;
   size_t n;
   uint8_t opcode;

   //Initialize status code
   error = NO_ERROR;

   //Receive and parse SCP directive
   while(!error)
   {
      //Manage message reception
      if(context->bufferLen == 0)
      {
         //Read the directive opcode
         error = sshReadChannel(&context->sshChannel, context->buffer, 1,
            &n, 0);

         //Check status code
         if(!error)
         {
            //Adjust the length of the buffer
            context->bufferLen += n;
         }
      }
      else if(context->bufferLen < SCP_CLIENT_BUFFER_SIZE)
      {
         //Retrieve directive opcode
         opcode = context->buffer[0];

         //Check directive opcode
         if(opcode == SCP_OPCODE_OK ||
            opcode == SCP_OPCODE_END)
         {
            //Parse the received directive
            error = scpParseDirective(context->buffer, directive);

            //Flush receive buffer
            context->bufferLen = 0;
            context->bufferPos = 0;

            //We are done
            break;
         }
         else if(opcode == SCP_OPCODE_WARNING ||
            opcode == SCP_OPCODE_ERROR ||
            opcode == SCP_OPCODE_FILE ||
            opcode == SCP_OPCODE_DIR ||
            opcode == SCP_OPCODE_TIME)
         {
            //Limit the number of bytes to read at a time
            n = SCP_CLIENT_BUFFER_SIZE - context->bufferLen;

            //Read more data
            error = sshReadChannel(&context->sshChannel, context->buffer +
               context->bufferLen, n, &n, SSH_FLAG_BREAK_CRLF);

            //Check status code
            if(!error)
            {
               //Adjust the length of the buffer
               context->bufferLen += n;

               //Check whether the string is properly terminated
               if(context->bufferLen > 0 &&
                  context->buffer[context->bufferLen - 1] == '\n')
               {
                  //Properly terminate the string with a NULL character
                  context->buffer[context->bufferLen - 1] = '\0';

                  //Parse the received directive
                  error = scpParseDirective(context->buffer, directive);

                  //Flush receive buffer
                  context->bufferLen = 0;
                  context->bufferPos = 0;

                  //We are done
                  break;
               }
               else
               {
                  //Wait for a new line character
                  error = ERROR_WOULD_BLOCK;
               }
            }
         }
         else
         {
            //Unknown directive
            error = ERROR_INVALID_COMMAND;
         }
      }
      else
      {
         //The implementation limits the size of messages it accepts
         error = ERROR_BUFFER_OVERFLOW;
      }

      //Check status code
      if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
      {
         //Process SSH connection events
         error = scpClientProcessEvents(context);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Process SCP client events
 * @param[in] context Pointer to the SCP client context
 * @return Error code
 **/

error_t scpClientProcessEvents(ScpClientContext *context)
{
   error_t error;
   uint_t i;
   SshContext *sshContext;
   SshConnection *connection;

   //Point to the SSH context
   sshContext = &context->sshContext;

   //Clear event descriptor set
   osMemset(sshContext->eventDesc, 0, sizeof(sshContext->eventDesc));

   //Specify the events the application is interested in
   for(i = 0; i < sshContext->numConnections; i++)
   {
      //Point to the structure describing the current connection
      connection = &sshContext->connections[i];

      //Loop through active connections only
      if(connection->state != SSH_CONN_STATE_CLOSED)
      {
         //Register the events related to the current SSH connection
         sshRegisterConnectionEvents(sshContext, connection, &sshContext->eventDesc[i]);
      }
   }

   //Wait for one of the set of sockets to become ready to perform I/O
   error = socketPoll(sshContext->eventDesc, sshContext->numConnections,
      &sshContext->event, context->timeout);

   //Verify status code
   if(!error)
   {
      //Event-driven processing
      for(i = 0; i < sshContext->numConnections && !error; i++)
      {
         //Point to the structure describing the current connection
         connection = &sshContext->connections[i];

         //Loop through active connections only
         if(connection->state != SSH_CONN_STATE_CLOSED)
         {
            //Check whether the socket is ready to perform I/O
            if(sshContext->eventDesc[i].eventFlags != 0)
            {
               //Connection event handler
               error = sshProcessConnectionEvents(sshContext, connection);
            }
         }
      }
   }

   //Check status code
   if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Check whether the timeout has elapsed
      error = scpClientCheckTimeout(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Determine whether a timeout error has occurred
 * @param[in] context Pointer to the SCP client context
 * @return Error code
 **/

error_t scpClientCheckTimeout(ScpClientContext *context)
{
   error_t error;
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //Check whether the timeout has elapsed
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Report a timeout error
      error = ERROR_TIMEOUT;
   }
   else
   {
#if (NET_RTOS_SUPPORT == ENABLED)
      //Successful operation
      error = NO_ERROR;
#else
      //The operation would block
      error = ERROR_WOULD_BLOCK;
#endif
   }

   //Return status code
   return error;
}

#endif
