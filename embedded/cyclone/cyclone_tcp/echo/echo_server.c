/**
 * @file echo_server.c
 * @brief Echo server
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
 * @section Description
 *
 * The Echo service simply sends back to the originating source
 * any data it receives. Refer to RFC 862 for complete details
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
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains Echo server settings
 **/

void echoServerGetDefaultSettings(EchoServerSettings *settings)
{
   //The Echo server is not bound to any interface
   settings->interface = NULL;

   //Echo service port number
   settings->port = ECHO_PORT;
}


/**
 * @brief Initialize Echo server context
 * @param[in] context Pointer to the Echo server context
 * @param[in] settings Echo server specific settings
 * @return Error code
 **/

error_t echoServerInit(EchoServerContext *context,
   const EchoServerSettings *settings)
{
   error_t error;

   //Debug message
   TRACE_INFO("Initializing Echo server...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear Echo server context
   osMemset(context, 0, sizeof(EchoServerContext));

   //Save user settings
   context->settings = *settings;

   //Initialize status code
   error = NO_ERROR;

   //Create an event object to poll the state of sockets
   if(!osCreateEvent(&context->event))
   {
      //Failed to create event
      error = ERROR_OUT_OF_RESOURCES;
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      echoServerDeinit(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Start Echo server
 * @param[in] context Pointer to the Echo server context
 * @return Error code
 **/

error_t echoServerStart(EchoServerContext *context)
{
   error_t error;

   //Make sure the Echo server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting Echo server...\r\n");

   //Make sure the Echo server is not already running
   if(context->running)
      return ERROR_ALREADY_RUNNING;

   //Start of exception handling block
   do
   {
#if (ECHO_SERVER_TCP_SUPPORT == ENABLED)
      //Open a TCP socket
      context->tcpSocket = socketOpen(SOCKET_TYPE_STREAM, SOCKET_IP_PROTO_TCP);
      //Failed to open socket?
      if(context->tcpSocket == NULL)
      {
         //Report an error
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Force the socket to operate in non-blocking mode
      error = socketSetTimeout(context->tcpSocket, 0);
      //Any error to report?
      if(error)
         break;

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->tcpSocket,
         context->settings.interface);
      //Any error to report?
      if(error)
         break;

      //The Echo server listens for TCP connection requests on port 7
      error = socketBind(context->tcpSocket, &IP_ADDR_ANY,
         context->settings.port);
      //Any error to report?
      if(error)
         break;

      //Place socket in listening state
      error = socketListen(context->tcpSocket, 0);
      //Any error to report?
      if(error)
         break;
#endif

#if (ECHO_SERVER_UDP_SUPPORT == ENABLED)
      //Open a UDP socket
      context->udpSocket = socketOpen(SOCKET_TYPE_DGRAM, SOCKET_IP_PROTO_UDP);
      //Failed to open socket?
      if(context->udpSocket == NULL)
      {
         //Report an error
         error = ERROR_OPEN_FAILED;
         break;
      }

      //Force the socket to operate in non-blocking mode
      error = socketSetTimeout(context->udpSocket, 0);
      //Any error to report?
      if(error)
         break;

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->udpSocket,
         context->settings.interface);
      //Any error to report?
      if(error)
         break;

      //The Echo server listens for UDP datagrams on port 7
      error = socketBind(context->udpSocket, &IP_ADDR_ANY,
         context->settings.port);
      //Any error to report?
      if(error)
         break;
#endif

      //Start the Echo server
      context->stop = FALSE;
      context->running = TRUE;

#if (OS_STATIC_TASK_SUPPORT == ENABLED)
      //Create a task using statically allocated memory
      context->taskId = osCreateStaticTask("Echo Server",
         (OsTaskCode) echoServerTask, context, &context->taskTcb,
         context->taskStack, ECHO_SERVER_STACK_SIZE, ECHO_SERVER_PRIORITY);
#else
      //Create a task
      context->taskId = osCreateTask("Echo Server",
         (OsTaskCode) echoServerTask, context, ECHO_SERVER_STACK_SIZE,
         ECHO_SERVER_PRIORITY);
#endif

      //Failed to create task?
      if(context->taskId == OS_INVALID_TASK_ID)
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      context->running = FALSE;

#if (ECHO_SERVER_TCP_SUPPORT == ENABLED)
      //Close listening TCP socket
      socketClose(context->tcpSocket);
      context->tcpSocket = NULL;
#endif

#if (ECHO_SERVER_UDP_SUPPORT == ENABLED)
      //Close UDP socket
      socketClose(context->udpSocket);
      context->udpSocket = NULL;
#endif
   }

   //Return status code
   return error;
}


/**
 * @brief Stop Echo server
 * @param[in] context Pointer to the Echo server context
 * @return Error code
 **/

error_t echoServerStop(EchoServerContext *context)
{
#if (ECHO_SERVER_TCP_SUPPORT == ENABLED)
   uint_t i;
#endif

   //Make sure the Echo server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping Echo server...\r\n");

   //Check whether the Echo server is running
   if(context->running)
   {
      //Stop the Echo server
      context->stop = TRUE;
      //Send a signal to the task to abort any blocking operation
      osSetEvent(&context->event);

      //Wait for the task to terminate
      while(context->running)
      {
         osDelayTask(1);
      }

#if (ECHO_SERVER_TCP_SUPPORT == ENABLED)
      //Loop through the TCP connection table
      for(i = 0; i < ECHO_SERVER_MAX_TCP_CONNECTIONS; i++)
      {
         //Close TCP connection
         echoServerCloseTcpConnection(&context->tcpConnection[i]);
      }

      //Close listening TCP socket
      socketClose(context->tcpSocket);
      context->tcpSocket = NULL;
#endif

#if (ECHO_SERVER_UDP_SUPPORT == ENABLED)
      //Close UDP socket
      socketClose(context->udpSocket);
      context->udpSocket = NULL;
#endif
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Echo server task
 * @param[in] context Pointer to the Echo server context
 **/

void echoServerTask(EchoServerContext *context)
{
   error_t error;
   uint_t i;
   systime_t timeout;
   SocketEventDesc eventDesc[ECHO_SERVER_MAX_TCP_CONNECTIONS + 2];

#if (NET_RTOS_SUPPORT == ENABLED)
   //Task prologue
   osEnterTask();

   //Process events
   while(1)
   {
#endif
      //Set polling timeout
      timeout = ECHO_SERVER_TICK_INTERVAL;

      //Clear event descriptor set
      osMemset(eventDesc, 0, sizeof(eventDesc));

#if (ECHO_SERVER_TCP_SUPPORT == ENABLED)
      //Specify the events the application is interested in
      for(i = 0; i < ECHO_SERVER_MAX_TCP_CONNECTIONS; i++)
      {
         EchoTcpConnection *connection;

         //Point to the structure describing the current TCP connection
         connection = &context->tcpConnection[i];

         //Loop through active connections only
         if(connection->state != ECHO_TCP_CONNECTION_STATE_CLOSED)
         {
            //Register connection events
            echoServerRegisterTcpConnectionEvents(connection, &eventDesc[i]);

            //Check whether the socket is ready for I/O operation
            if(eventDesc[i].eventFlags != 0)
            {
               //No need to poll the underlying socket for incoming traffic
               timeout = 0;
            }
         }
      }

      //The Echo server listens for TCP connection requests on port 7
      eventDesc[i].socket = context->tcpSocket;
      eventDesc[i++].eventMask = SOCKET_EVENT_RX_READY;
#else
      //TCP Echo service is not supported
      i = 0;
#endif

#if (ECHO_SERVER_UDP_SUPPORT == ENABLED)
      //The Echo server listens for UDP datagrams on port 7
      eventDesc[i].socket = context->udpSocket;
      eventDesc[i++].eventMask = SOCKET_EVENT_RX_READY;
#endif

      //Wait for one of the set of sockets to become ready to perform I/O
      error = socketPoll(eventDesc, i, &context->event, timeout);

      //Check status code
      if(error == NO_ERROR || error == ERROR_TIMEOUT)
      {
         //Stop request?
         if(context->stop)
         {
            //Stop Echo server operation
            context->running = FALSE;
            //Task epilogue
            osExitTask();
            //Kill ourselves
            osDeleteTask(OS_SELF_TASK_ID);
         }

#if (ECHO_SERVER_TCP_SUPPORT == ENABLED)
         //Event-driven processing
         for(i = 0; i < ECHO_SERVER_MAX_TCP_CONNECTIONS; i++)
         {
            EchoTcpConnection *connection;

            //Point to the structure describing the current TCP connection
            connection = &context->tcpConnection[i];

            //Loop through active connections only
            if(connection->state != ECHO_TCP_CONNECTION_STATE_CLOSED)
            {
               //Check whether the socket is ready to perform I/O
               if(eventDesc[i].eventFlags != 0)
               {
                  //Connection event handler
                  echoServerProcessTcpConnectionEvents(connection);
               }
            }
         }

         //Any TCP connection request received on port 7?
         if(eventDesc[i++].eventFlags != 0)
         {
            //Accept TCP connection request
            echoServerAcceptTcpConnection(context);
         }
#else
         //TCP Echo service is not supported
         i = 0;
#endif

#if (ECHO_SERVER_UDP_SUPPORT == ENABLED)
         //Any UDP datagram received on port 7?
         if(eventDesc[i].eventFlags != 0)
         {
            //Process incoming UDP datagram
            echoServerProcessUdpDatagram(context);
         }
#endif
      }

      //Handle periodic operations
      echoServerTick(context);

#if (NET_RTOS_SUPPORT == ENABLED)
   }
#endif
}


/**
 * @brief Release Echo server context
 * @param[in] context Pointer to the Echo server context
 **/

void echoServerDeinit(EchoServerContext *context)
{
   //Make sure the Echo server context is valid
   if(context != NULL)
   {
      //Free previously allocated resources
      osDeleteEvent(&context->event);

      //Clear Echo server context
      osMemset(context, 0, sizeof(EchoServerContext));
   }
}

#endif
