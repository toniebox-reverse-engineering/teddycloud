/**
 * @file sftp_client.h
 * @brief SFTP client
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

#ifndef _SFTP_CLIENT_H
#define _SFTP_CLIENT_H

//Dependencies
#include "ssh/ssh.h"
#include "sftp/sftp_common.h"

//SFTP client support
#ifndef SFTP_CLIENT_SUPPORT
   #define SFTP_CLIENT_SUPPORT ENABLED
#elif (SFTP_CLIENT_SUPPORT != ENABLED && SFTP_CLIENT_SUPPORT != DISABLED)
   #error SFTP_CLIENT_SUPPORT parameter is not valid
#endif

//Minimum SFTP protocol version that can be negotiated
#ifndef SFTP_CLIENT_MIN_VERSION
   #define SFTP_CLIENT_MIN_VERSION 1
#elif (SFTP_CLIENT_MIN_VERSION < 1)
   #error SFTP_CLIENT_MIN_VERSION parameter is not valid
#endif

//Maximum SFTP protocol version that can be negotiated
#ifndef SFTP_CLIENT_MAX_VERSION
   #define SFTP_CLIENT_MAX_VERSION 3
#elif (SFTP_CLIENT_MAX_VERSION > 3 || SFTP_CLIENT_MAX_VERSION < SFTP_CLIENT_MIN_VERSION)
   #error SFTP_CLIENT_MAX_VERSION parameter is not valid
#endif

//Default timeout
#ifndef SFTP_CLIENT_DEFAULT_TIMEOUT
   #define SFTP_CLIENT_DEFAULT_TIMEOUT 20000
#elif (SFTP_CLIENT_DEFAULT_TIMEOUT < 1000)
   #error SFTP_CLIENT_DEFAULT_TIMEOUT parameter is not valid
#endif

//Maximum packet size
#ifndef SFTP_CLIENT_MAX_PACKET_SIZE
   #define SFTP_CLIENT_MAX_PACKET_SIZE 32768
#elif (SFTP_CLIENT_MAX_PACKET_SIZE < 256)
   #error SFTP_CLIENT_MAX_PACKET_SIZE parameter is not valid
#endif

//Size of the buffer for input/output operations
#ifndef SFTP_CLIENT_BUFFER_SIZE
   #define SFTP_CLIENT_BUFFER_SIZE 1024
#elif (SFTP_CLIENT_BUFFER_SIZE < 256)
   #error SFTP_CLIENT_BUFFER_SIZE parameter is not valid
#endif

//Maximum size of file handle
#ifndef SFTP_CLIENT_MAX_HANDLE_SIZE
   #define SFTP_CLIENT_MAX_HANDLE_SIZE 32
#elif (SFTP_CLIENT_MAX_HANDLE_SIZE < 4)
   #error SFTP_CLIENT_MAX_HANDLE_SIZE parameter is not valid
#endif

//Maximum length of file names
#ifndef SFTP_CLIENT_MAX_FILENAME_LEN
   #define SFTP_CLIENT_MAX_FILENAME_LEN 64
#elif (SFTP_CLIENT_MAX_FILENAME_LEN < 16)
   #error SFTP_CLIENT_MAX_FILENAME_LEN parameter is not valid
#endif

//Maximum path length
#ifndef SFTP_CLIENT_MAX_PATH_LEN
   #define SFTP_CLIENT_MAX_PATH_LEN 128
#elif (SFTP_CLIENT_MAX_PATH_LEN < 16)
   #error SFTP_CLIENT_MAX_PATH_LEN parameter is not valid
#endif

//Forward declaration of SftpClientContext structure
struct _SftpClientContext;
#define SftpClientContext struct _SftpClientContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SFTP client state
 **/

typedef enum
{
   SFTP_CLIENT_STATE_DISCONNECTED       = 0,
   SFTP_CLIENT_STATE_CONNECTING         = 1,
   SFTP_CLIENT_STATE_CONNECTED          = 2,
   SFTP_CLIENT_STATE_CHANNEL_OPEN       = 3,
   SFTP_CLIENT_STATE_CHANNEL_OPEN_REPLY = 4,
   SFTP_CLIENT_STATE_CHANNEL_REQUEST    = 5,
   SFTP_CLIENT_STATE_CHANNEL_REPLY      = 6,
   SFTP_CLIENT_STATE_CHANNEL_DATA       = 7,
   SFTP_CLIENT_STATE_SENDING_COMMAND_1  = 8,
   SFTP_CLIENT_STATE_SENDING_COMMAND_2  = 9,
   SFTP_CLIENT_STATE_SENDING_DATA       = 10,
   SFTP_CLIENT_STATE_RECEIVING_DATA     = 11,
   SFTP_CLIENT_STATE_RECEIVING_NAME     = 12,
   SFTP_CLIENT_STATE_DISCONNECTING_1    = 13,
   SFTP_CLIENT_STATE_DISCONNECTING_2    = 14,
   SFTP_CLIENT_STATE_DISCONNECTING_3    = 15
} SftpClientState;


/**
 * @brief SSH initialization callback function
 **/

typedef error_t (*SftpClientSshInitCallback)(SftpClientContext *context,
   SshContext *sshContext);


/**
 * @brief SFTP client context
 **/

struct _SftpClientContext
{
   SftpVersion version;                             ///<SFTP protocol version
   SftpClientState state;                           ///<SFTP client state
   NetInterface *interface;                         ///<Underlying network interface
   SftpClientSshInitCallback sshInitCallback;       ///<SSH initialization callback function
   systime_t timeout;                               ///<Timeout value
   systime_t timestamp;                             ///<Timestamp to manage timeout
   uint8_t buffer[SFTP_CLIENT_BUFFER_SIZE];         ///<Memory buffer for input/output operations
   SftpPacketType requestType;                      ///<Request type
   uint32_t requestId;                              ///<Request identifier
   size_t requestLen;
   size_t requestPos;
   size_t responseLen;
   size_t responsePos;
   size_t responseTotalLen;
   size_t dataLen;                                  ///<Length of the data payload
   uint64_t fileOffset;                             ///<Offset within the file
   uint32_t statusCode;                             ///<Status code returned by the server
   char_t currentDir[SFTP_CLIENT_MAX_PATH_LEN + 1]; ///<Current directory
   uint8_t handle[SFTP_CLIENT_MAX_HANDLE_SIZE];     ///<File handle (opaque string)
   size_t handleLen;                                ///<Length of the file handle, in bytes
   SshContext sshContext;                           ///<SSH context
   SshConnection sshConnection;                     ///<SSH connection
   SshChannel sshChannel;                           ///<SSH channel
};


/**
 * @brief Directory entry
 **/

typedef struct
{
   char_t name[SFTP_CLIENT_MAX_FILENAME_LEN + 1];
   uint32_t type;
   uint64_t size;
   uint32_t permissions;
   DateTime modified;
} SftpDirEntry;


//SFTP client related functions
error_t sftpClientInit(SftpClientContext *context);

error_t sftpClientRegisterSshInitCallback(SftpClientContext *context,
   SftpClientSshInitCallback callback);

error_t sftpClientSetTimeout(SftpClientContext *context, systime_t timeout);

error_t sftpClientBindToInterface(SftpClientContext *context,
   NetInterface *interface);

error_t sftpClientConnect(SftpClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort);

const char_t *sftpClientGetWorkingDir(SftpClientContext *context);

error_t sftpClientChangeWorkingDir(SftpClientContext *context,
   const char_t *path);

error_t sftpClientChangeToParentDir(SftpClientContext *context);

error_t sftpClientOpenDir(SftpClientContext *context, const char_t *path);
error_t sftpClientReadDir(SftpClientContext *context, SftpDirEntry *dirEntry);
error_t sftpClientCloseDir(SftpClientContext *context);

error_t sftpClientCreateDir(SftpClientContext *context, const char_t *path);
error_t sftpClientDeleteDir(SftpClientContext *context, const char_t *path);

error_t sftpClientOpenFile(SftpClientContext *context, const char_t *path,
   uint_t mode);

error_t sftpClientWriteFile(SftpClientContext *context, const void *data,
   size_t length, size_t *written, uint_t flags);

error_t sftpClientReadFile(SftpClientContext *context, void *data, size_t size,
   size_t *received, uint_t flags);

error_t sftpClientCloseFile(SftpClientContext *context);

error_t sftpClientRenameFile(SftpClientContext *context, const char_t *oldPath,
   const char_t *newPath);

error_t sftpClientDeleteFile(SftpClientContext *context, const char_t *path);

SftpStatusCode sftpClientGetStatusCode(SftpClientContext *context);

error_t sftpClientDisconnect(SftpClientContext *context);
error_t sftpClientClose(SftpClientContext *context);

void sftpClientDeinit(SftpClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
