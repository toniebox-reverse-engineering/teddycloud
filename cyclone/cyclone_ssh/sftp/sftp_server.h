/**
 * @file sftp_server.h
 * @brief SFTP server
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

#ifndef _SFTP_SERVER_H
#define _SFTP_SERVER_H

//Dependencies
#include "ssh/ssh_server.h"
#include "sftp/sftp_common.h"
#include "fs_port.h"

//SFTP server support
#ifndef SFTP_SERVER_SUPPORT
   #define SFTP_SERVER_SUPPORT ENABLED
#elif (SFTP_SERVER_SUPPORT != ENABLED && SFTP_SERVER_SUPPORT != DISABLED)
   #error SFTP_SERVER_SUPPORT parameter is not valid
#endif

//Stack size required to run the SFTP server
#ifndef SFTP_SERVER_STACK_SIZE
   #define SFTP_SERVER_STACK_SIZE 650
#elif (SFTP_SERVER_STACK_SIZE < 1)
   #error SFTP_SERVER_STACK_SIZE parameter is not valid
#endif

//Priority at which the SFTP server should run
#ifndef SFTP_SERVER_PRIORITY
   #define SFTP_SERVER_PRIORITY OS_TASK_PRIORITY_NORMAL
#endif

//Maximum number of simultaneous SFTP sessions
#ifndef SFTP_SERVER_MAX_SESSIONS
   #define SFTP_SERVER_MAX_SESSIONS 10
#elif (SFTP_SERVER_MAX_SESSIONS < 1)
   #error SFTP_SERVER_MAX_SESSIONS parameter is not valid
#endif

//SFTP server tick interval
#ifndef SFTP_SERVER_TICK_INTERVAL
   #define SFTP_SERVER_TICK_INTERVAL 1000
#elif (SFTP_SERVER_TICK_INTERVAL < 100)
   #error SFTP_SERVER_TICK_INTERVAL parameter is not valid
#endif

//Minimum SFTP protocol version that can be negotiated
#ifndef SFTP_SERVER_MIN_VERSION
   #define SFTP_SERVER_MIN_VERSION 1
#elif (SFTP_SERVER_MIN_VERSION < 1)
   #error SFTP_SERVER_MIN_VERSION parameter is not valid
#endif

//Maximum SFTP protocol version that can be negotiated
#ifndef SFTP_SERVER_MAX_VERSION
   #define SFTP_SERVER_MAX_VERSION 3
#elif (SFTP_SERVER_MAX_VERSION > 3 || SFTP_SERVER_MAX_VERSION < SFTP_CLIENT_MIN_VERSION)
   #error SFTP_SERVER_MAX_VERSION parameter is not valid
#endif

//Size of buffer used for input/output operations
#ifndef SFTP_SERVER_BUFFER_SIZE
   #define SFTP_SERVER_BUFFER_SIZE 1024
#elif (SFTP_SERVER_BUFFER_SIZE < 128)
   #error SFTP_SERVER_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of root directory
#ifndef SFTP_SERVER_MAX_ROOT_DIR_LEN
   #define SFTP_SERVER_MAX_ROOT_DIR_LEN 63
#elif (SFTP_SERVER_MAX_ROOT_DIR_LEN < 7)
   #error SFTP_SERVER_MAX_ROOT_DIR_LEN parameter is not valid
#endif

//Maximum length of home directory
#ifndef SFTP_SERVER_MAX_HOME_DIR_LEN
   #define SFTP_SERVER_MAX_HOME_DIR_LEN 63
#elif (SFTP_SERVER_MAX_HOME_DIR_LEN < 7)
   #error SFTP_SERVER_MAX_HOME_DIR_LEN parameter is not valid
#endif

//Maximum path length
#ifndef SFTP_SERVER_MAX_PATH_LEN
   #define SFTP_SERVER_MAX_PATH_LEN 255
#elif (SFTP_SERVER_MAX_PATH_LEN < 7)
   #error SFTP_SERVER_MAX_PATH_LEN parameter is not valid
#endif

//Forward declaration of SftpServerContext structure
struct _SftpServerContext;
#define SftpServerContext struct _SftpServerContext

//Forward declaration of SftpServerSession structure
struct _SftpServerSession;
#define SftpServerSession struct _SftpServerSession

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Access status
 **/

typedef enum
{
   SFTP_ACCESS_DENIED  = 0,
   SFTP_ACCESS_ALLOWED = 1
} SftpAccessStatus;


/**
 * @brief File permissions
 **/

typedef enum
{
   SFTP_FILE_PERM_LIST  = 0x01,
   SFTP_FILE_PERM_READ  = 0x02,
   SFTP_FILE_PERM_WRITE = 0x04
} SFtpFilePerm;


/**
 * @brief SFTP session state
 **/

typedef enum
{
   SFTP_SERVER_SESSION_STATE_CLOSED         = 0,
   SFTP_SERVER_SESSION_STATE_RECEIVING      = 1,
   SFTP_SERVER_SESSION_STATE_SENDING        = 2,
   SFTP_SERVER_SESSION_STATE_RECEIVING_DATA = 3,
   SFTP_SERVER_SESSION_STATE_SENDING_DATA   = 4
} SftpServerSessionState;


/**
 * @brief User verification callback function
 **/

typedef SftpAccessStatus (*SftpServerCheckUserCallback)(SftpServerSession *session,
   const char_t *user);


/**
 * @brief Callback used to retrieve file permissions
 **/

typedef uint_t (*SftpServerGetFilePermCallback)(SftpServerSession *session,
   const char_t *user, const char_t *path);


/**
 * @brief File or directory object
 **/

typedef struct
{
   SftpFileType type;                         ///<File type
   SftpServerSession *session;                ///<Pointer to the SFTP session
   char_t path[SFTP_SERVER_MAX_PATH_LEN + 1]; ///<Path name
   uint32_t handle;                           ///<Opaque value that identifies the file
   uint64_t size;                             ///<Size of the file
   uint64_t offset;                           ///<Offset within the file
   FsFile *file;                              ///<File pointer
   FsDir *dir;                                ///<Directory pointer
} SftpFileObject;


/**
 * @brief SFTP server settings
 **/

typedef struct
{
   SshServerContext *sshServerContext;                ///<SSH server context
   uint_t numSessions;                                ///<Maximum number of SFTP sessions
   SftpServerSession *sessions;                       ///<SFTP sessions
   uint_t numFileObjects;                             ///<Maximum number of file objects
   SftpFileObject *fileObjects;                       ///<File objects
   const char_t *rootDir;                             ///<Root directory
   SftpServerCheckUserCallback checkUserCallback;     ///<User verification callback function
   SftpServerGetFilePermCallback getFilePermCallback; ///<Callback used to retrieve file permissions
} SftpServerSettings;


/**
 * @brief SFTP session
 **/

struct _SftpServerSession
{
   SftpServerSessionState state;                     ///<Session state
   SftpVersion version;                              ///<SFTP protocol version
   SftpServerContext *context;                       ///<SFTP server context
   SshChannel *channel;                              ///<Underlying SSH channel
   char_t rootDir[SFTP_SERVER_MAX_ROOT_DIR_LEN + 1]; ///<Root directory
   char_t homeDir[SFTP_SERVER_MAX_HOME_DIR_LEN + 1]; ///<Home directory
   uint32_t requestId;                               ///<Request identifier
   error_t requestStatus;                            ///<Status of the request
   FsFile *file;                                     ///<File pointer
   size_t dataLen;                                   ///<Length of the data payload
   uint8_t buffer[SFTP_SERVER_BUFFER_SIZE];          ///<Memory buffer for input/output operations
   size_t bufferPos;                                 ///<Current position in the buffer
   size_t bufferLen;                                 ///<Actual length of the buffer, in bytes
   size_t totalLen;
   uint32_t handle;                                  ///<File or directory handle
};


/**
 * @brief SFTP server context
 **/

struct _SftpServerContext
{
   SshServerContext *sshServerContext;                      ///<SSH server context
   uint_t numSessions;                                      ///<Maximum number of SFTP sessions
   SftpServerSession *sessions;                             ///<SFTP sessions
   uint_t numFileObjects;                                   ///<Maximum number of file objects
   SftpFileObject *fileObjects;                             ///<File objects
   char_t rootDir[SFTP_SERVER_MAX_ROOT_DIR_LEN + 1];        ///<Root directory
   SftpServerCheckUserCallback checkUserCallback;           ///<User verification callback function
   SftpServerGetFilePermCallback getFilePermCallback;       ///<Callback used to retrieve file permissions
   bool_t running;                                          ///<Operational state of the FTP server
   bool_t stop;                                             ///<Stop request
   OsEvent event;                                           ///<Event object used to poll the channels
   OsTaskId taskId;                                         ///<Task identifier
#if (OS_STATIC_TASK_SUPPORT == ENABLED)
   OsTaskTcb taskTcb;                                       ///<Task control block
   OsStackType taskStack[SFTP_SERVER_STACK_SIZE];           ///<Task stack
#endif
   SshChannelEventDesc eventDesc[SFTP_SERVER_MAX_SESSIONS]; ///<The events the application is interested in
   char_t path[SFTP_SERVER_MAX_PATH_LEN + 1];               ///<Path name
};


//SFTP server related functions
void sftpServerGetDefaultSettings(SftpServerSettings *settings);

error_t sftpServerInit(SftpServerContext *context,
   const SftpServerSettings *settings);

error_t sftpServerStart(SftpServerContext *context);
error_t sftpServerStop(SftpServerContext *context);

error_t sftpServerSetRootDir(SftpServerSession *session, const char_t *rootDir);
error_t sftpServerSetHomeDir(SftpServerSession *session, const char_t *homeDir);

void sftpServerTask(void *param);

void sftpServerDeinit(SftpServerContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
