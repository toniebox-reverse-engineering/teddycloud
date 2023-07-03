/**
 * @file shell_client_misc.c
 * @brief Helper functions for SSH secure shell client
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
#include "ssh/ssh.h"
#include "ssh/ssh_connection.h"
#include "ssh/ssh_request.h"
#include "ssh/ssh_misc.h"
#include "shell/shell_client.h"
#include "shell/shell_client_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SHELL_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Update Shell client state
 * @param[in] context Pointer to the shell client context
 * @param[in] newState New state to switch to
 **/

void shellClientChangeState(ShellClientContext *context,
   ShellClientState newState)
{
   //Switch to the new state
   context->state = newState;

   //Save current time
   context->timestamp = osGetSystemTime();
}


/**
 * @brief SSH channel request callback
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] type Request type
 * @param[in] data Request-specific data
 * @param[in] length Length of the request-specific data, in bytes
 * @param[in] param Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientChannelRequestCallback(SshChannel *channel,
   const SshString *type, const uint8_t *data, size_t length,
   void *param)
{
   error_t error;
   ShellClientContext *context;

   //Debug message
   TRACE_INFO("Shell client: SSH channel request callback...\r\n");

   //Point to the shell client context
   context = (ShellClientContext *) param;

   //Check request type
   if(sshCompareString(type, "exit-status"))
   {
      SshExitStatusParams requestParams;

      //An SSH_MSG_CHANNEL_REQUEST message can be sent to return the exit
      //status when the command running at the other end terminates (refer
      //to RFC 4254, section 6.10)
      error = sshParseExitStatusParams(data, length, &requestParams);

      //Check status code
      if(!error)
      {
         //Matching channel?
         if(channel == &context->sshChannel)
         {
            //Save exit status
            context->exitStatus = requestParams.exitStatus;
         }
         else
         {
            //Unknown channel
            error = ERROR_UNKNOWN_REQUEST;
         }
      }
   }
   else
   {
      //The request is not supported
      error = ERROR_UNKNOWN_REQUEST;
   }

   //Return status code
   return error;
}


/**
 * @brief Open SSH connection
 * @param[in] context Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientOpenConnection(ShellClientContext *context)
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

   //Register channel request processing callback
   error = sshRegisterChannelRequestCallback(&context->sshContext,
      shellClientChannelRequestCallback, context);
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
 * @param[in] context Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientEstablishConnection(ShellClientContext *context)
{
   error_t error;

   //Check the state of the SSH connection
   if(context->sshConnection.state < SSH_CONN_STATE_OPEN)
   {
      //Perform SSH key exchange and user authentication
      error = shellClientProcessEvents(context);
   }
   else if(context->sshConnection.state == SSH_CONN_STATE_OPEN)
   {
      //The SSH connection is established
      shellClientChangeState(context, SHELL_CLIENT_STATE_CONNECTED);
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
 * @param[in] context Pointer to the shell client context
 **/

void shellClientCloseConnection(ShellClientContext *context)
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
 * @brief Process shell client events
 * @param[in] context Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientProcessEvents(ShellClientContext *context)
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
      error = shellClientCheckTimeout(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Determine whether a timeout error has occurred
 * @param[in] context Pointer to the shell client context
 * @return Error code
 **/

error_t shellClientCheckTimeout(ShellClientContext *context)
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
