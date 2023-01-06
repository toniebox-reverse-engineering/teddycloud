/**
 * @file shell_client.h
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

#ifndef _SHELL_CLIENT_H
#define _SHELL_CLIENT_H

//Dependencies
#include "ssh/ssh.h"

//Shell client support
#ifndef SHELL_CLIENT_SUPPORT
   #define SHELL_CLIENT_SUPPORT ENABLED
#elif (SHELL_CLIENT_SUPPORT != ENABLED && SHELL_CLIENT_SUPPORT != DISABLED)
   #error SHELL_CLIENT_SUPPORT parameter is not valid
#endif

//Default timeout
#ifndef SHELL_CLIENT_DEFAULT_TIMEOUT
   #define SHELL_CLIENT_DEFAULT_TIMEOUT 20000
#elif (SHELL_CLIENT_DEFAULT_TIMEOUT < 1000)
   #error SHELL_CLIENT_DEFAULT_TIMEOUT parameter is not valid
#endif

//Size of the buffer for input/output operations
#ifndef SHELL_CLIENT_BUFFER_SIZE
   #define SHELL_CLIENT_BUFFER_SIZE 512
#elif (SHELL_CLIENT_BUFFER_SIZE < 256)
   #error SHELL_CLIENT_BUFFER_SIZE parameter is not valid
#endif

//Forward declaration of ShellClientContext structure
struct _ShellClientContext;
#define ShellClientContext struct _ShellClientContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Shell client state
 **/

typedef enum
{
   SHELL_CLIENT_STATE_DISCONNECTED    = 0,
   SHELL_CLIENT_STATE_CONNECTING_1    = 1,
   SHELL_CLIENT_STATE_CONNECTING_2    = 2,
   SHELL_CLIENT_STATE_CONNECTED       = 3,
   SHELL_CLIENT_STATE_CHANNEL_INIT    = 4,
   SHELL_CLIENT_STATE_CHANNEL_OPEN    = 5,
   SHELL_CLIENT_STATE_CHANNEL_REQUEST = 6,
   SHELL_CLIENT_STATE_CHANNEL_REPLY   = 7,
   SHELL_CLIENT_STATE_CHANNEL_DATA    = 8,
   SHELL_CLIENT_STATE_CHANNEL_CLOSE   = 9,
   SHELL_CLIENT_STATE_DISCONNECTING_1 = 10,
   SHELL_CLIENT_STATE_DISCONNECTING_2 = 11
} ShellClientState;


/**
 * @brief SSH initialization callback function
 **/

typedef error_t (*ShellClientSshInitCallback)(ShellClientContext *context,
   SshContext *sshContext);


/**
 * @brief Shell client context
 **/

struct _ShellClientContext
{
   ShellClientState state;                     ///<Shell client state
   NetInterface *interface;                  ///<Underlying network interface
   ShellClientSshInitCallback sshInitCallback; ///<SSH initialization callback function
   systime_t timeout;                        ///<Timeout value
   systime_t timestamp;                      ///<Timestamp to manage timeout
   char_t buffer[SHELL_CLIENT_BUFFER_SIZE];    ///<Memory buffer for input/output operations
   size_t bufferLen;                         ///<Length of the buffer, in bytes
   size_t bufferPos;                         ///<Current position in the buffer
   uint32_t exitStatus;                      ///<Exit status
   SshContext sshContext;                    ///<SSH context
   SshConnection sshConnection;              ///<SSH connection
   SshChannel sshChannel;                    ///<SSH channel
};


//Shell client related functions
error_t shellClientInit(ShellClientContext *context);

error_t shellClientRegisterSshInitCallback(ShellClientContext *context,
   ShellClientSshInitCallback callback);

error_t shellClientSetTimeout(ShellClientContext *context, systime_t timeout);

error_t shellClientBindToInterface(ShellClientContext *context,
   NetInterface *interface);

error_t shellClientConnect(ShellClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort);

error_t shellClientFormatCommand(ShellClientContext *context,
   const char_t *command, ...);

error_t shellClientExecuteCommand(ShellClientContext *context,
   const char_t *command);

error_t shellClientWriteStream(ShellClientContext *context, const void *data,
   size_t length, size_t *written, uint_t flags);

error_t shellClientFlushStream(ShellClientContext *context);

error_t shellClientReadStream(ShellClientContext *context, void *data,
   size_t size, size_t *received, uint_t flags);

error_t shellClientCloseStream(ShellClientContext *context);
uint32_t shellClientGetExitStatus(ShellClientContext *context);

error_t shellClientDisconnect(ShellClientContext *context);
error_t shellClientClose(ShellClientContext *context);

void shellClientDeinit(ShellClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
