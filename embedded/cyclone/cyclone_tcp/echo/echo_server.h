/**
 * @file echo_server.h
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

#ifndef _ECHO_SERVER_H
#define _ECHO_SERVER_H

//Dependencies
#include "core/net.h"
#include "core/socket.h"

//Echo server support
#ifndef ECHO_SERVER_SUPPORT
   #define ECHO_SERVER_SUPPORT DISABLED
#elif (ECHO_SERVER_SUPPORT != ENABLED && ECHO_SERVER_SUPPORT != DISABLED)
   #error ECHO_SERVER_SUPPORT parameter is not valid
#endif

//Stack size required to run the Echo server
#ifndef ECHO_SERVER_STACK_SIZE
   #define ECHO_SERVER_STACK_SIZE 500
#elif (ECHO_SERVER_STACK_SIZE < 1)
   #error ECHO_SERVER_STACK_SIZE parameter is not valid
#endif

//Priority at which the Echo server should run
#ifndef ECHO_SERVER_PRIORITY
   #define ECHO_SERVER_PRIORITY OS_TASK_PRIORITY_NORMAL
#endif

//TCP Echo service support
#ifndef ECHO_SERVER_TCP_SUPPORT
   #define ECHO_SERVER_TCP_SUPPORT ENABLED
#elif (ECHO_SERVER_TCP_SUPPORT != ENABLED && ECHO_SERVER_TCP_SUPPORT != DISABLED)
   #error ECHO_SERVER_TCP_SUPPORT parameter is not valid
#endif

//Maximum number of simultaneous TCP connections
#ifndef ECHO_SERVER_MAX_TCP_CONNECTIONS
   #define ECHO_SERVER_MAX_TCP_CONNECTIONS 2
#elif (ECHO_SERVER_MAX_TCP_CONNECTIONS < 1)
   #error ECHO_SERVER_MAX_TCP_CONNECTIONS parameter is not valid
#endif

//Size of the buffer for input/output operations (TCP)
#ifndef ECHO_SERVER_TCP_BUFFER_SIZE
   #define ECHO_SERVER_TCP_BUFFER_SIZE 512
#elif (ECHO_SERVER_TCP_BUFFER_SIZE < 1)
   #error ECHO_SERVER_TCP_BUFFER_SIZE parameter is not valid
#endif

//UDP Echo service support
#ifndef ECHO_SERVER_UDP_SUPPORT
   #define ECHO_SERVER_UDP_SUPPORT ENABLED
#elif (ECHO_SERVER_UDP_SUPPORT != ENABLED && ECHO_SERVER_UDP_SUPPORT != DISABLED)
   #error ECHO_SERVER_UDP_SUPPORT parameter is not valid
#endif

//Size of the buffer for input/output operations (UDP)
#ifndef ECHO_SERVER_UDP_BUFFER_SIZE
   #define ECHO_SERVER_UDP_BUFFER_SIZE 1472
#elif (ECHO_SERVER_UDP_BUFFER_SIZE < 1)
   #error ECHO_SERVER_UDP_BUFFER_SIZE parameter is not valid
#endif

//Idle connection timeout
#ifndef ECHO_SERVER_TIMEOUT
   #define ECHO_SERVER_TIMEOUT 30000
#elif (ECHO_SERVER_TIMEOUT < 1)
   #error ECHO_SERVER_TIMEOUT parameter is not valid
#endif

//Echo server tick interval
#ifndef ECHO_SERVER_TICK_INTERVAL
   #define ECHO_SERVER_TICK_INTERVAL 1000
#elif (ECHO_SERVER_TICK_INTERVAL < 100)
   #error ECHO_SERVER_TICK_INTERVAL parameter is not valid
#endif

//Application specific context
#ifndef ECHO_SERVER_PRIVATE_CONTEXT
   #define ECHO_SERVER_PRIVATE_CONTEXT
#endif

//Echo service port number
#define ECHO_PORT 7

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief TCP connection state
 **/

typedef enum
{
   ECHO_TCP_CONNECTION_STATE_CLOSED = 0,
   ECHO_TCP_CONNECTION_STATE_OPEN   = 1
} EchoTcpConnectionState;


/**
 * @brief Echo server settings
 **/

typedef struct
{
   NetInterface *interface; ///<Underlying network interface
   uint16_t port;           ///<Echo server port number
} EchoServerSettings;


/**
 * @brief Echo TCP connection
 **/

typedef struct
{
   EchoTcpConnectionState state;               ///<Connection state
   Socket *socket;                             ///<Underlying TCP socket
   systime_t timestamp;                        ///<Time stamp
   char_t buffer[ECHO_SERVER_TCP_BUFFER_SIZE]; ///<Memory buffer for input/output operations (TCP)
   size_t bufferLen;                           ///<Length of the buffer, in bytes
   size_t bufferPos;                           ///<Current position in the buffer
} EchoTcpConnection;


/**
 * @brief Echo server context
 **/

typedef struct
{
   EchoServerSettings settings;                   ///<User settings
   bool_t running;                                ///<Operational state of the Echo server
   bool_t stop;                                   ///<Stop request
   OsEvent event;                                 ///<Event object used to poll the sockets
   OsTaskId taskId;                               ///<Task identifier
#if (OS_STATIC_TASK_SUPPORT == ENABLED)
   OsTaskTcb taskTcb;                             ///<Task control block
   OsStackType taskStack[ECHO_SERVER_STACK_SIZE]; ///<Task stack
#endif
#if (ECHO_SERVER_TCP_SUPPORT == ENABLED)
   Socket *tcpSocket;                             ///<Listening TCP socket
   EchoTcpConnection tcpConnection[ECHO_SERVER_MAX_TCP_CONNECTIONS]; ///<TCP connections
#endif
#if (ECHO_SERVER_UDP_SUPPORT == ENABLED)
   Socket *udpSocket;                             ///<UDP socket
   char_t udpBuffer[ECHO_SERVER_UDP_BUFFER_SIZE]; ///<Memory buffer for input/output operations (UDP)
#endif
   ECHO_SERVER_PRIVATE_CONTEXT                    ///<Application specific context
} EchoServerContext;


//Echo server related functions
void echoServerGetDefaultSettings(EchoServerSettings *settings);

error_t echoServerInit(EchoServerContext *context,
   const EchoServerSettings *settings);

error_t echoServerStart(EchoServerContext *context);
error_t echoServerStop(EchoServerContext *context);

void echoServerTask(EchoServerContext *context);

void echoServerDeinit(EchoServerContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
