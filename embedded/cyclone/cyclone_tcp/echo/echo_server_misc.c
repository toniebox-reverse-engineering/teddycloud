/**
 * @file echo_server_misc.c
 * @brief Helper functions for Echo server
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneTCP Open.
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
#define TRACE_LEVEL ECHO_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "echo/echo_server.h"
#include "echo/echo_server_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ECHO_SERVER_SUPPORT == ENABLED)


/**
 * @brief Handle periodic operations
 * @param[in] context Pointer to the Echo server context
 **/

void echoServerTick(EchoServerContext *context)
{
#if (ECHO_SERVER_TCP_SUPPORT == ENABLED)
   uint_t i;
   systime_t time;
   EchoTcpConnection *connection;

   //Get current time
   time = osGetSystemTime();

   //Loop through the connection table
   for(i = 0; i < ECHO_SERVER_MAX_TCP_CONNECTIONS; i++)
   {
      //Point to the current entry
      connection = &context->tcpConnection[i];

      //Check the state of the current connection
      if(connection->state != ECHO_TCP_CONNECTION_STATE_CLOSED)
      {
         //Disconnect inactive client after idle timeout
         if(timeCompare(time, connection->timestamp + ECHO_SERVER_TIMEOUT) >= 0)
         {
            //Debug message
            TRACE_INFO("Echo server: Closing inactive TCP connection...\r\n");
            //Close the TCP connection
            echoServerCloseTcpConnection(connection);
         }
      }
   }
#endif
}


/**
 * @brief Accept connection request
 * @param[in] context Pointer to the Echo server context
 **/

void echoServerAcceptTcpConnection(EchoServerContext *context)
{
#if (ECHO_SERVER_TCP_SUPPORT == ENABLED)
   uint_t i;
   Socket *socket;
   IpAddr clientIpAddr;
   uint16_t clientPort;
   EchoTcpConnection *connection;

   //Accept incoming connection
   socket = socketAccept(context->tcpSocket, &clientIpAddr, &clientPort);

   //Make sure the socket handle is valid
   if(socket != NULL)
   {
      //Force the socket to operate in non-blocking mode
      socketSetTimeout(socket, 0);

      //Initialize pointer
      connection = NULL;

      //Loop through the TCP connection table
      for(i = 0; i < ECHO_SERVER_MAX_TCP_CONNECTIONS; i++)
      {
         //Check the state of the current connection
         if(context->tcpConnection[i].state == ECHO_TCP_CONNECTION_STATE_CLOSED)
         {
            //The current entry is free
            connection = &context->tcpConnection[i];
            break;
         }
      }

      //If the connection table runs out of space, then the client's connection
      //request is rejected
      if(connection != NULL)
      {
         //Debug message
         TRACE_INFO("Echo Server: TCP connection established with client %s port %"
            PRIu16 "...\r\n", ipAddrToString(&clientIpAddr, NULL), clientPort);

         //Clear the structure describing the connection
         osMemset(connection, 0, sizeof(EchoTcpConnection));

         //Save socket handle
         connection->socket = socket;
         //Initialize time stamp
         connection->timestamp = osGetSystemTime();

         //Wait for incoming data
         connection->state = ECHO_TCP_CONNECTION_STATE_OPEN;
      }
      else
      {
         //Debug message
         TRACE_INFO("Echo Server: TCP connection refused with client %s port %"
            PRIu16 "...\r\n", ipAddrToString(&clientIpAddr, NULL), clientPort);

         //The Echo server cannot accept the incoming connection request
         socketClose(socket);
      }
   }
#endif
}


/**
 * @brief Register TCP connection events
 * @param[in] connection Pointer to the TCP connection
 * @param[in] eventDesc Socket events to be registered
 **/

void echoServerRegisterTcpConnectionEvents(EchoTcpConnection *connection,
   SocketEventDesc *eventDesc)
{
   //Check the state of the TCP connection
   if(connection->state == ECHO_TCP_CONNECTION_STATE_OPEN)
   {
      //Any data pending in the send buffer?
      if(connection->bufferPos < connection->bufferLen)
      {
         //Wait until there is more room in the send buffer
         eventDesc->socket = connection->socket;
         eventDesc->eventMask = SOCKET_EVENT_TX_READY;
      }
      else
      {
         //Wait for data to be available for reading
         eventDesc->socket = connection->socket;
         eventDesc->eventMask = SOCKET_EVENT_RX_READY;
      }
   }
}


/**
 * @brief Connection event handler
 * @param[in] connection Pointer to the TCP connection
 **/

void echoServerProcessTcpConnectionEvents(EchoTcpConnection *connection)
{
   error_t error;
   size_t n;

   //Check the state of the TCP connection
   if(connection->state == ECHO_TCP_CONNECTION_STATE_OPEN)
   {
      //Any data pending in the send buffer?
      if(connection->bufferPos < connection->bufferLen)
      {
         //Send more data
         error = socketSend(connection->socket,
            connection->buffer + connection->bufferPos,
            connection->bufferLen - connection->bufferPos, &n, 0);

         //Check status code
         if(error == NO_ERROR || error == ERROR_TIMEOUT)
         {
            //Advance data pointer
            connection->bufferPos += n;

            //Update time stamp
            connection->timestamp = osGetSystemTime();
         }
      }
      else
      {
         //Receive more data
         error = socketReceive(connection->socket, connection->buffer,
            ECHO_SERVER_TCP_BUFFER_SIZE, &n, 0);

         //Check status code
         if(error == NO_ERROR)
         {
            //Data has been successfully received
            connection->bufferLen = n;
            connection->bufferPos = 0;

            //Update time stamp
            connection->timestamp = osGetSystemTime();
         }
         else if(error == ERROR_END_OF_STREAM)
         {
            //Debug message
            TRACE_INFO("Echo server: Closing TCP connection...\r\n");
            //Close the TCP connection
            echoServerCloseTcpConnection(connection);
         }
         else
         {
            //Just for sanity
         }
      }
   }
}


/**
 * @brief Close TCP connection
 * @param[in] connection Pointer to the TCP connection
 **/

void echoServerCloseTcpConnection(EchoTcpConnection *connection)
{
   //Close TCP connection
   if(connection->socket != NULL)
   {
      socketClose(connection->socket);
      connection->socket = NULL;
   }

   //Mark the connection as closed
   connection->state = ECHO_TCP_CONNECTION_STATE_CLOSED;
}


/**
 * @brief Process incoming UDP datagram
 * @param[in] context Pointer to the Echo server context
 **/

void echoServerProcessUdpDatagram(EchoServerContext *context)
{
#if (ECHO_SERVER_UDP_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   IpAddr clientIpAddr;
   uint16_t clientPort;

   //Receive incoming datagram
   error = socketReceiveFrom(context->udpSocket, &clientIpAddr, &clientPort,
      context->udpBuffer, ECHO_SERVER_UDP_BUFFER_SIZE, &length, 0);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("Echo server: UDP datagram received from %s port %" PRIu16
         " (%" PRIuSIZE " bytes)\r\n",
         ipAddrToString(&clientIpAddr, NULL), clientPort, length);

      //When a datagram is received, the data from it is sent back in an
      //answering datagram
      error = socketSendTo(context->udpSocket, &clientIpAddr, clientPort,
         context->udpBuffer, length, NULL, 0);
   }
#endif
}

#endif
