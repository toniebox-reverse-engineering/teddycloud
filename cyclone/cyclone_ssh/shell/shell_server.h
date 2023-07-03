/**
 * @file shell_server.h
 * @brief SSH secure shell server
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

#ifndef _SHELL_SERVER_H
#define _SHELL_SERVER_H

//Dependencies
#include "ssh/ssh_server.h"

//Shell server support
#ifndef SHELL_SERVER_SUPPORT
   #define SHELL_SERVER_SUPPORT ENABLED
#elif (SHELL_SERVER_SUPPORT != ENABLED && SHELL_SERVER_SUPPORT != DISABLED)
   #error SHELL_SERVER_SUPPORT parameter is not valid
#endif

//Stack size required to run the shell server
#ifndef SHELL_SERVER_STACK_SIZE
   #define SHELL_SERVER_STACK_SIZE 650
#elif (SHELL_SERVER_STACK_SIZE < 1)
   #error SHELL_SERVER_STACK_SIZE parameter is not valid
#endif

//Priority at which the shell server should run
#ifndef SHELL_SERVER_PRIORITY
   #define SHELL_SERVER_PRIORITY OS_TASK_PRIORITY_NORMAL
#endif

//Maximum number of simultaneous shell sessions
#ifndef SHELL_SERVER_MAX_SESSIONS
   #define SHELL_SERVER_MAX_SESSIONS 10
#elif (SHELL_SERVER_MAX_SESSIONS < 1)
   #error SHELL_SERVER_MAX_SESSIONS parameter is not valid
#endif

//Shell server tick interval
#ifndef SHELL_SERVER_TICK_INTERVAL
   #define SHELL_SERVER_TICK_INTERVAL 1000
#elif (SHELL_SERVER_TICK_INTERVAL < 100)
   #error SHELL_SERVER_TICK_INTERVAL parameter is not valid
#endif

//Size of buffer used for input/output operations
#ifndef SHELL_SERVER_BUFFER_SIZE
   #define SHELL_SERVER_BUFFER_SIZE 256
#elif (SHELL_SERVER_BUFFER_SIZE < 128)
   #error SHELL_SERVER_BUFFER_SIZE parameter is not valid
#endif

//Command history support
#ifndef SHELL_SERVER_HISTORY_SUPPORT
   #define SHELL_SERVER_HISTORY_SUPPORT ENABLED
#elif (SHELL_SERVER_HISTORY_SUPPORT != ENABLED && SHELL_SERVER_HISTORY_SUPPORT != DISABLED)
   #error SHELL_SERVER_HISTORY_SUPPORT parameter is not valid
#endif

//Size of command history buffer
#ifndef SHELL_SERVER_HISTORY_SIZE
   #define SHELL_SERVER_HISTORY_SIZE 256
#elif (SHELL_SERVER_HISTORY_SIZE < 1)
   #error SHELL_SERVER_HISTORY_SIZE parameter is not valid
#endif

//Maximum length of shell prompt
#ifndef SHELL_SERVER_MAX_PROMPT_LEN
   #define SHELL_SERVER_MAX_PROMPT_LEN 64
#elif (SHELL_SERVER_MAX_PROMPT_LEN < 1)
   #error SHELL_SERVER_MAX_PROMPT_LEN parameter is not valid
#endif

//Default terminal width (in characters)
#ifndef SHELL_SERVER_DEFAULT_TERM_WIDTH
   #define SHELL_SERVER_DEFAULT_TERM_WIDTH 80
#elif (SHELL_SERVER_DEFAULT_TERM_WIDTH < 1)
   #error SHELL_SERVER_DEFAULT_TERM_WIDTH parameter is not valid
#endif

//Default terminal height (in row)
#ifndef SHELL_SERVER_DEFAULT_TERM_HEIGHT
   #define SHELL_SERVER_DEFAULT_TERM_HEIGHT 60
#elif (SHELL_SERVER_DEFAULT_TERM_HEIGHT < 1)
   #error SHELL_SERVER_DEFAULT_TERM_HEIGHT parameter is not valid
#endif

//Maximum length of multibyte escape sequences
#define SHELL_SERVER_MAX_ESC_SEQ_LEN 7

//Forward declaration of ShellServerContext structure
struct _ShellServerContext;
#define ShellServerContext struct _ShellServerContext

//Forward declaration of ShellServerSession structure
struct _ShellServerSession;
#define ShellServerSession struct _ShellServerSession

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Access status
 **/

typedef enum
{
   SHELL_ACCESS_DENIED  = 0,
   SHELL_ACCESS_ALLOWED = 1
} ShellAccessStatus;


/**
 * @brief Shell session state
 **/

typedef enum
{
   SHELL_SERVER_SESSION_STATE_CLOSED = 0,
   SHELL_SERVER_SESSION_STATE_INIT   = 1,
   SHELL_SERVER_SESSION_STATE_OPEN   = 2,
   SHELL_SERVER_SESSION_STATE_EXEC   = 3
} ShellServerSessionState;


/**
 * @brief User verification callback function
 **/

typedef ShellAccessStatus (*ShellServerCheckUserCallback)(ShellServerSession *session,
   const char_t *user);


/**
 * @brief Command line processing callback function
 **/

typedef error_t (*ShellServerCommandLineCallback)(ShellServerSession *session,
   char_t *commandLine);


/**
 * @brief Session closing callback function
 **/

typedef void (*ShellServerCloseCallback)(ShellServerSession *session,
   const char_t *user);


/**
 * @brief Shell server settings
 **/

typedef struct
{
   SshServerContext *sshServerContext;                 ///<SSH server context
   uint_t numSessions;                                 ///<Maximum number of shell sessions
   ShellServerSession *sessions;                       ///<Shell sessions
   ShellServerCheckUserCallback checkUserCallback;     ///<User verification callback function
   ShellServerCommandLineCallback commandLineCallback; ///<Command line processing callback function
   ShellServerCloseCallback closeCallback;             ///<Session closing callback function
} ShellServerSettings;


/**
 * @brief Shell session
 **/

struct _ShellServerSession
{
   ShellServerSessionState state;                    ///<Session state
   OsEvent startEvent;
   OsEvent event;
   OsTaskId taskId;                                  ///<Task identifier
#if (OS_STATIC_TASK_SUPPORT == ENABLED)
   OsTaskTcb taskTcb;                                ///<Task control block
   OsStackType taskStack[SHELL_SERVER_STACK_SIZE];   ///<Task stack
#endif
   ShellServerContext *context;                      ///<Shell server context
   SshChannel *channel;                              ///<Underlying SSH channel
   char_t prompt[SHELL_SERVER_MAX_PROMPT_LEN + 1];   ///<Shell prompt
   size_t promptLen;                                 ///<Length of the shell prompt
   char_t buffer[SHELL_SERVER_BUFFER_SIZE];          ///<Memory buffer for input/output operations
   size_t bufferPos;                                 ///<Current position in the buffer
   size_t bufferLen;                                 ///<Actual length of the buffer, in bytes
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   char_t history[SHELL_SERVER_HISTORY_SIZE];        ///<Command history buffer
   size_t historyLen;                                ///<Length of the command history buffer, in bytes
   size_t historyPos;                                ///<Current position in the command history buffer
#endif
   char_t backspaceCode;                             ///<Backspace key code
   char_t deleteCode;                                ///<Delete key code
   uint32_t termWidth;                               ///<Current terminal width (in characters)
   uint32_t termHeight;                              ///<Current terminal height (in rows)
   uint32_t newTermWidth;                            ///<New terminal width (in characters)
   uint32_t newTermHeight;                           ///<New terminal height (in rows)
   bool_t windowResize;                              ///<Window resize event
   char_t escSeq[SHELL_SERVER_MAX_ESC_SEQ_LEN + 1];  ///<Multibyte escape sequence
   size_t escSeqLen;                                 ///<Length of the multibyte escape sequence
#ifdef SHELL_SERVER_SESSION_PRIVATE_VARS
   SHELL_SERVER_SESSION_PRIVATE_VARS                 ///<Application specific context
#endif
};


/**
 * @brief shell server context
 **/

struct _ShellServerContext
{
   SshServerContext *sshServerContext;                       ///<SSH server context
   uint_t numSessions;                                       ///<Maximum number of shell sessions
   ShellServerSession *sessions;                             ///<Shell sessions
   ShellServerCheckUserCallback checkUserCallback;           ///<User verification callback function
   ShellServerCommandLineCallback commandLineCallback;       ///<Command line processing callback function
   ShellServerCloseCallback closeCallback;                   ///<Session closing callback function
   bool_t running;                                           ///<Operational state of the shell server
   bool_t stop;                                              ///<Stop request
   OsEvent event;                                            ///<Event object used to poll the channels
   SshChannelEventDesc eventDesc[SHELL_SERVER_MAX_SESSIONS]; ///<The events the application is interested in
#ifdef SHELL_SERVER_CONTEXT_PRIVATE_VARS
   SHELL_SERVER_CONTEXT_PRIVATE_VARS                         ///<Application specific context
#endif
};


//Shell server related functions
void shellServerGetDefaultSettings(ShellServerSettings *settings);

error_t shellServerInit(ShellServerContext *context,
   const ShellServerSettings *settings);

error_t shellServerStart(ShellServerContext *context);

error_t shellServerSetBanner(ShellServerSession *session,
   const char_t *banner);

error_t shellServerSetPrompt(ShellServerSession *session,
   const char_t *prompt);

error_t shellServerSetTimeout(ShellServerSession *session, systime_t timeout);

error_t shellServerWriteStream(ShellServerSession *session, const void *data,
   size_t length, size_t *written, uint_t flags);

error_t shellServerReadStream(ShellServerSession *session, void *data,
   size_t size, size_t *received, uint_t flags);

error_t shellServerSaveHistory(ShellServerSession *session, char_t *history,
   size_t size, size_t *length);

error_t shellServerRestoreHistory(ShellServerSession *session,
   const char_t *history, size_t length);

error_t shellServerClearHistory(ShellServerSession *session);

void shellServerTask(void *param);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
