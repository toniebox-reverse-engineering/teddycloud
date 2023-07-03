/**
 * @file scp_client.h
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

#ifndef _SCP_CLIENT_H
#define _SCP_CLIENT_H

//Dependencies
#include "ssh/ssh.h"
#include "scp/scp_common.h"

//SCP client support
#ifndef SCP_CLIENT_SUPPORT
   #define SCP_CLIENT_SUPPORT ENABLED
#elif (SCP_CLIENT_SUPPORT != ENABLED && SCP_CLIENT_SUPPORT != DISABLED)
   #error SCP_CLIENT_SUPPORT parameter is not valid
#endif

//Default timeout
#ifndef SCP_CLIENT_DEFAULT_TIMEOUT
   #define SCP_CLIENT_DEFAULT_TIMEOUT 20000
#elif (SCP_CLIENT_DEFAULT_TIMEOUT < 1000)
   #error SCP_CLIENT_DEFAULT_TIMEOUT parameter is not valid
#endif

//Size of the buffer for input/output operations
#ifndef SCP_CLIENT_BUFFER_SIZE
   #define SCP_CLIENT_BUFFER_SIZE 512
#elif (SCP_CLIENT_BUFFER_SIZE < 256)
   #error SCP_CLIENT_BUFFER_SIZE parameter is not valid
#endif

//Forward declaration of ScpClientContext structure
struct _ScpClientContext;
#define ScpClientContext struct _ScpClientContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SCP client state
 **/

typedef enum
{
   SCP_CLIENT_STATE_DISCONNECTED    = 0,
   SCP_CLIENT_STATE_CONNECTING_1    = 1,
   SCP_CLIENT_STATE_CONNECTING_2    = 2,
   SCP_CLIENT_STATE_CONNECTED       = 3,
   SCP_CLIENT_STATE_CHANNEL_OPEN    = 4,
   SCP_CLIENT_STATE_CHANNEL_REQUEST = 6,
   SCP_CLIENT_STATE_CHANNEL_REPLY   = 7,
   SCP_CLIENT_STATE_WRITE_INIT      = 8,
   SCP_CLIENT_STATE_WRITE_COMMAND   = 9,
   SCP_CLIENT_STATE_WRITE_ACK       = 10,
   SCP_CLIENT_STATE_WRITE_DATA      = 11,
   SCP_CLIENT_STATE_WRITE_STATUS    = 12,
   SCP_CLIENT_STATE_WRITE_FIN       = 13,
   SCP_CLIENT_STATE_READ_INIT       = 14,
   SCP_CLIENT_STATE_READ_COMMAND    = 15,
   SCP_CLIENT_STATE_READ_ACK        = 16,
   SCP_CLIENT_STATE_READ_DATA       = 17,
   SCP_CLIENT_STATE_READ_STATUS     = 18,
   SCP_CLIENT_STATE_READ_FIN        = 19,
   SCP_CLIENT_STATE_CHANNEL_CLOSE   = 20,
   SCP_CLIENT_STATE_DISCONNECTING_1 = 21,
   SCP_CLIENT_STATE_DISCONNECTING_2 = 22
} ScpClientState;


/**
 * @brief SSH initialization callback function
 **/

typedef error_t (*ScpClientSshInitCallback)(ScpClientContext *context,
   SshContext *sshContext);


/**
 * @brief SCP client context
 **/

struct _ScpClientContext
{
   ScpClientState state;                     ///<SCP client state
   NetInterface *interface;                  ///<Underlying network interface
   ScpClientSshInitCallback sshInitCallback; ///<SSH initialization callback function
   systime_t timeout;                        ///<Timeout value
   systime_t timestamp;                      ///<Timestamp to manage timeout
   char_t buffer[SCP_CLIENT_BUFFER_SIZE];    ///<Memory buffer for input/output operations
   size_t bufferLen;                         ///<Length of the buffer, in bytes
   size_t bufferPos;                         ///<Current position in the buffer
   ScpOpcode statusCode;                     ///<Status code
   uint64_t fileSize;                        ///<Size of the file, in bytes
   uint64_t fileOffset;                      ///<Offset within the file
   SshContext sshContext;                    ///<SSH context
   SshConnection sshConnection;              ///<SSH connection
   SshChannel sshChannel;                    ///<SSH channel
};


//SCP client related functions
error_t scpClientInit(ScpClientContext *context);

error_t scpClientRegisterSshInitCallback(ScpClientContext *context,
   ScpClientSshInitCallback callback);

error_t scpClientSetTimeout(ScpClientContext *context, systime_t timeout);

error_t scpClientBindToInterface(ScpClientContext *context,
   NetInterface *interface);

error_t scpClientConnect(ScpClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort);

error_t scpClientOpenFileForWriting(ScpClientContext *context,
   const char_t *path, uint_t mode, uint64_t size);

error_t scpClientOpenFileForReading(ScpClientContext *context,
   const char_t *path, uint64_t *size);

error_t scpClientWriteFile(ScpClientContext *context, const void *data,
   size_t length, size_t *written, uint_t flags);

error_t scpClientReadFile(ScpClientContext *context, void *data, size_t size,
   size_t *received, uint_t flags);

error_t scpClientCloseFile(ScpClientContext *context);

error_t scpClientDisconnect(ScpClientContext *context);
error_t scpClientClose(ScpClientContext *context);

void scpClientDeinit(ScpClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
