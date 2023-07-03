/**
 * @file scp_server.h
 * @brief SCP server
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

#ifndef _SCP_SERVER_H
#define _SCP_SERVER_H

//Dependencies
#include "ssh/ssh_server.h"
#include "scp/scp_common.h"
#include "fs_port.h"

//SCP server support
#ifndef SCP_SERVER_SUPPORT
   #define SCP_SERVER_SUPPORT ENABLED
#elif (SCP_SERVER_SUPPORT != ENABLED && SCP_SERVER_SUPPORT != DISABLED)
   #error SCP_SERVER_SUPPORT parameter is not valid
#endif

//Stack size required to run the SCP server
#ifndef SCP_SERVER_STACK_SIZE
   #define SCP_SERVER_STACK_SIZE 650
#elif (SCP_SERVER_STACK_SIZE < 1)
   #error SCP_SERVER_STACK_SIZE parameter is not valid
#endif

//Priority at which the SCP server should run
#ifndef SCP_SERVER_PRIORITY
   #define SCP_SERVER_PRIORITY OS_TASK_PRIORITY_NORMAL
#endif

//Maximum number of simultaneous SCP sessions
#ifndef SCP_SERVER_MAX_SESSIONS
   #define SCP_SERVER_MAX_SESSIONS 10
#elif (SCP_SERVER_MAX_SESSIONS < 1)
   #error SCP_SERVER_MAX_SESSIONS parameter is not valid
#endif

//SCP server tick interval
#ifndef SCP_SERVER_TICK_INTERVAL
   #define SCP_SERVER_TICK_INTERVAL 1000
#elif (SCP_SERVER_TICK_INTERVAL < 100)
   #error SCP_SERVER_TICK_INTERVAL parameter is not valid
#endif

//Size of buffer used for input/output operations
#ifndef SCP_SERVER_BUFFER_SIZE
   #define SCP_SERVER_BUFFER_SIZE 512
#elif (SCP_SERVER_BUFFER_SIZE < 128)
   #error SCP_SERVER_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of root directory
#ifndef SCP_SERVER_MAX_ROOT_DIR_LEN
   #define SCP_SERVER_MAX_ROOT_DIR_LEN 63
#elif (SCP_SERVER_MAX_ROOT_DIR_LEN < 7)
   #error SCP_SERVER_MAX_ROOT_DIR_LEN parameter is not valid
#endif

//Maximum length of home directory
#ifndef SCP_SERVER_MAX_HOME_DIR_LEN
   #define SCP_SERVER_MAX_HOME_DIR_LEN 63
#elif (SCP_SERVER_MAX_HOME_DIR_LEN < 7)
   #error SCP_SERVER_MAX_HOME_DIR_LEN parameter is not valid
#endif

//Maximum path length
#ifndef SCP_SERVER_MAX_PATH_LEN
   #define SCP_SERVER_MAX_PATH_LEN 255
#elif (SCP_SERVER_MAX_PATH_LEN < 7)
   #error SCP_SERVER_MAX_PATH_LEN parameter is not valid
#endif

//Maximum recursion depth
#ifndef SCP_SERVER_MAX_RECURSION_LEVEL
   #define SCP_SERVER_MAX_RECURSION_LEVEL 4
#elif (SCP_SERVER_MAX_RECURSION_LEVEL < 1)
   #error SCP_SERVER_MAX_RECURSION_LEVEL parameter is not valid
#endif

//Forward declaration of ScpServerContext structure
struct _ScpServerContext;
#define ScpServerContext struct _ScpServerContext

//Forward declaration of ScpServerSession structure
struct _ScpServerSession;
#define ScpServerSession struct _ScpServerSession

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Access status
 **/

typedef enum
{
   SCP_ACCESS_DENIED  = 0,
   SCP_ACCESS_ALLOWED = 1
} ScpAccessStatus;


/**
 * @brief File permissions
 **/

typedef enum
{
   SCP_FILE_PERM_LIST  = 0x01,
   SCP_FILE_PERM_READ  = 0x02,
   SCP_FILE_PERM_WRITE = 0x04
} ScpFilePerm;


/**
 * @brief SCP session state
 **/

typedef enum
{
   SCP_SERVER_SESSION_STATE_CLOSED        = 0,
   SCP_SERVER_SESSION_STATE_WRITE_INIT    = 1,
   SCP_SERVER_SESSION_STATE_WRITE_COMMAND = 2,
   SCP_SERVER_SESSION_STATE_WRITE_ACK     = 3,
   SCP_SERVER_SESSION_STATE_WRITE_DATA    = 4,
   SCP_SERVER_SESSION_STATE_WRITE_STATUS  = 5,
   SCP_SERVER_SESSION_STATE_WRITE_FIN     = 6,
   SCP_SERVER_SESSION_STATE_READ_INIT     = 7,
   SCP_SERVER_SESSION_STATE_READ_COMMAND  = 8,
   SCP_SERVER_SESSION_STATE_READ_ACK      = 9,
   SCP_SERVER_SESSION_STATE_READ_DATA     = 10,
   SCP_SERVER_SESSION_STATE_READ_STATUS   = 11,
   SCP_SERVER_SESSION_STATE_READ_FIN      = 12,
   SCP_SERVER_SESSION_STATE_ERROR         = 13,
   SCP_SERVER_SESSION_STATE_CLOSING       = 14
} ScpServerSessionState;


/**
 * @brief User verification callback function
 **/

typedef ScpAccessStatus (*ScpServerCheckUserCallback)(ScpServerSession *session,
   const char_t *user);


/**
 * @brief Callback used to retrieve file permissions
 **/

typedef uint_t (*ScpServerGetFilePermCallback)(ScpServerSession *session,
   const char_t *user, const char_t *path);


/**
 * @brief SCP server settings
 **/

typedef struct
{
   SshServerContext *sshServerContext;               ///<SSH server context
   uint_t numSessions;                               ///<Maximum number of SCP sessions
   ScpServerSession *sessions;                       ///<SCP sessions
   const char_t *rootDir;                            ///<Root directory
   ScpServerCheckUserCallback checkUserCallback;     ///<User verification callback function
   ScpServerGetFilePermCallback getFilePermCallback; ///<Callback used to retrieve file permissions
} ScpServerSettings;


/**
 * @brief SCP session
 **/

struct _ScpServerSession
{
   ScpServerSessionState state;                     ///<Session state
   ScpServerContext *context;                       ///<SCP server context
   SshChannel *channel;                             ///<Underlying SSH channel
   char_t rootDir[SCP_SERVER_MAX_ROOT_DIR_LEN + 1]; ///<Root directory
   char_t homeDir[SCP_SERVER_MAX_HOME_DIR_LEN + 1]; ///<Home directory
   char_t path[SCP_SERVER_MAX_PATH_LEN + 1];        ///<Path name
   bool_t recursive;                                ///<Recursive copy
   bool_t targetIsDir;                              ///<The target is a directory
   uint_t dirLevel;                                 ///<Current level of recursion
   FsDir *dir[SCP_SERVER_MAX_RECURSION_LEVEL];      ///<Directory pointers
   FsFile *file;                                    ///<File pointer
   uint32_t fileMode;                               ///<File access rights
   uint64_t fileSize;                               ///<Size of the file, in bytes
   uint64_t fileOffset;                             ///<Offset within the file
   char_t buffer[SCP_SERVER_BUFFER_SIZE];           ///<Memory buffer for input/output operations
   size_t bufferPos;                                ///<Current position in the buffer
   size_t bufferLen;                                ///<Actual length of the buffer, in bytes
   error_t statusCode;                              ///<Status code
};


/**
 * @brief SCP server context
 **/

struct _ScpServerContext
{
   SshServerContext *sshServerContext;                     ///<SSH server context
   uint_t numSessions;                                     ///<Maximum number of SCP sessions
   ScpServerSession *sessions;                             ///<SCP sessions
   char_t rootDir[SCP_SERVER_MAX_ROOT_DIR_LEN + 1];        ///<Root directory
   ScpServerCheckUserCallback checkUserCallback;           ///<User verification callback function
   ScpServerGetFilePermCallback getFilePermCallback;       ///<Callback used to retrieve file permissions
   bool_t running;                                         ///<Operational state of the FTP server
   bool_t stop;                                            ///<Stop request
   OsEvent event;                                          ///<Event object used to poll the channels
   OsTaskId taskId;                                        ///<Task identifier
#if (OS_STATIC_TASK_SUPPORT == ENABLED)
   OsTaskTcb taskTcb;                                      ///<Task control block
   OsStackType taskStack[SCP_SERVER_STACK_SIZE];           ///<Task stack
#endif
   SshChannelEventDesc eventDesc[SCP_SERVER_MAX_SESSIONS]; ///<The events the application is interested in
   char_t path[SCP_SERVER_MAX_PATH_LEN + 1];               ///<Path name
};


//SCP server related functions
void scpServerGetDefaultSettings(ScpServerSettings *settings);

error_t scpServerInit(ScpServerContext *context,
   const ScpServerSettings *settings);

error_t scpServerStart(ScpServerContext *context);
error_t scpServerStop(ScpServerContext *context);

error_t scpServerSetRootDir(ScpServerSession *session, const char_t *rootDir);
error_t scpServerSetHomeDir(ScpServerSession *session, const char_t *homeDir);

void scpServerTask(void *param);

void scpServerDeinit(ScpServerContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
