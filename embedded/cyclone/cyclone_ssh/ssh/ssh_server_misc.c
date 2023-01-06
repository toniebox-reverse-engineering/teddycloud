/**
 * @file ssh_server_misc.c
 * @brief Helper functions for SSH server
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
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_server.h"
#include "ssh/ssh_server_misc.h"
#include "ssh/ssh_transport.h"
#include "ssh/ssh_channel.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_SERVER_SUPPORT == ENABLED)


/**
 * @brief Handle periodic operations
 * @param[in] context Pointer to the SSH server context
 **/

void sshServerTick(SshServerContext *context)
{
   error_t error;
   uint_t i;
   systime_t time;
   SshConnection *connection;

   //Get current time
   time = osGetSystemTime();

   //Loop through the connection table
   for(i = 0; i < context->sshContext.numConnections; i++)
   {
      //Point to the current entry
      connection = &context->sshContext.connections[i];

      //Active connection?
      if(connection->state != SSH_CONN_STATE_CLOSED)
      {
         //Check idle connection timeout (a value of zero means no timeout)
         if(context->timeout != 0)
         {
            //Disconnect inactive client after idle timeout
            if(timeCompare(time, connection->timestamp + context->timeout) >= 0)
            {
               //Debug message
               TRACE_INFO("SSH server: Closing inactive connection...\r\n");

               //Send an SSH_MSG_DISCONNECT message
               error = sshSendDisconnect(connection, SSH_DISCONNECT_BY_APPLICATION,
                  "Session idle timeout");

               //Failed to send message?
               if(error)
               {
                  //Close the SSH connection
                  sshCloseConnection(connection);
               }
            }
         }
      }
   }
}


/**
 * @brief Accept connection request
 * @param[in] context Pointer to the SSH server context
 **/

void sshServerAcceptConnection(SshServerContext *context)
{
   Socket *socket;
   IpAddr clientIpAddr;
   uint16_t clientPort;
   SshConnection *connection;

   //Accept incoming connection
   socket = socketAccept(context->socket, &clientIpAddr, &clientPort);

   //Make sure the socket handle is valid
   if(socket != NULL)
   {
      //Allocate a new SSH connection
      connection = sshOpenConnection(&context->sshContext, socket);

      //If the connection table runs out of space, then the client's connection
      //request is rejected
      if(connection != NULL)
      {
         //Debug message
         TRACE_INFO("SSH server: Connection established with client %s port %"
            PRIu16 "...\r\n", ipAddrToString(&clientIpAddr, NULL), clientPort);

         //Force the socket to operate in non-blocking mode
         socketSetTimeout(socket, 0);
      }
      else
      {
         //Debug message
         TRACE_INFO("SSH Server: Connection refused with client %s port %"
            PRIu16 "...\r\n", ipAddrToString(&clientIpAddr, NULL), clientPort);

         //The SSH server cannot accept the incoming connection request
         socketClose(socket);
      }
   }
}

#endif
