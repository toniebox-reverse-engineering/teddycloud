/**
 * @file shell_server.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SHELL_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "shell/shell_server.h"
#include "shell/shell_server_pty.h"
#include "shell/shell_server_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SHELL_SERVER_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains shell server settings
 **/

void shellServerGetDefaultSettings(ShellServerSettings *settings)
{
   //SSH server context
   settings->sshServerContext = NULL;

   //Shell sessions
   settings->numSessions = 0;
   settings->sessions = NULL;

   //User verification callback function
   settings->checkUserCallback = NULL;
   //Command line processing callback function
   settings->commandLineCallback = NULL;
   //Session closing callback function
   settings->closeCallback = NULL;
}


/**
 * @brief Initialize shell server context
 * @param[in] context Pointer to the shell server context
 * @param[in] settings Shell server specific settings
 * @return Error code
 **/

error_t shellServerInit(ShellServerContext *context,
   const ShellServerSettings *settings)
{
   uint_t i;
   ShellServerSession *session;

   //Debug message
   TRACE_INFO("Initializing shell server...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid shell sessions?
   if(settings->sessions == NULL || settings->numSessions < 1 ||
      settings->numSessions > SHELL_SERVER_MAX_SESSIONS)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Clear shell server context
   osMemset(context, 0, sizeof(ShellServerContext));

   //Save user settings
   context->sshServerContext = settings->sshServerContext;
   context->numSessions = settings->numSessions;
   context->sessions = settings->sessions;
   context->checkUserCallback = settings->checkUserCallback;
   context->commandLineCallback = settings->commandLineCallback;
   context->closeCallback = settings->closeCallback;

   //Loop through shell sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Point to the structure describing the current session
      session = &context->sessions[i];

      //Initialize the structure representing the shell session
      osMemset(session, 0, sizeof(ShellServerSession));
      //Attach shell server context
      session->context = context;

      //Create an event object to manage session lifetime
      if(!osCreateEvent(&session->startEvent))
         return ERROR_OUT_OF_RESOURCES;

      //Create an event object to manage session events
      if(!osCreateEvent(&session->event))
         return ERROR_OUT_OF_RESOURCES;
   }

   //Create an event object to poll the state of channels
   if(!osCreateEvent(&context->event))
      return ERROR_OUT_OF_RESOURCES;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start shell server
 * @param[in] context Pointer to the shell server context
 * @return Error code
 **/

error_t shellServerStart(ShellServerContext *context)
{
   error_t error;
   uint_t i;
   ShellServerSession *session;

   //Make sure the shell server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting shell server...\r\n");

   //Make sure the shell server is not already running
   if(context->running)
      return ERROR_ALREADY_RUNNING;

   //Register channel request processing callback
   error = sshServerRegisterChannelRequestCallback(context->sshServerContext,
      shellServerChannelRequestCallback, context);
   //Any error to report?
   if(error)
      return error;

   //Loop through the shell sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Point to the current session
      session = &context->sessions[i];

#if (OS_STATIC_TASK_SUPPORT == ENABLED)
      //Create a task using statically allocated memory
      session->taskId = osCreateStaticTask("Shell Session",
         (OsTaskCode) shellServerTask, session, &session->taskTcb,
         session->taskStack, SHELL_SERVER_STACK_SIZE, SHELL_SERVER_PRIORITY);
#else
      //Create a task
      session->taskId = osCreateTask("Shell Session", shellServerTask,
         session, SHELL_SERVER_STACK_SIZE, SHELL_SERVER_PRIORITY);
#endif

      //Failed to create task?
      if(session->taskId == OS_INVALID_TASK_ID)
         return ERROR_OUT_OF_RESOURCES;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set welcome banner
 * @param[in] session Handle referencing a shell session
 * @param[in] banner NULL-terminated string containing the banner message
 * @return Error code
 **/

error_t shellServerSetBanner(ShellServerSession *session,
   const char_t *banner)
{
   size_t n;

   //Check parameters
   if(session == NULL || banner == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the banner message
   n = osStrlen(banner);

   //Check the length of the string
   if(n > SHELL_SERVER_BUFFER_SIZE)
      return ERROR_INVALID_LENGTH;

   //Copy the banner message
   osMemcpy(session->buffer, banner, n);

   //Save the length of the banner message
   session->bufferLen = n;
   session->bufferPos = 0;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set shell prompt
 * @param[in] session Handle referencing a shell session
 * @param[in] prompt NULL-terminated string containing the prompt to be used
 * @return Error code
 **/

error_t shellServerSetPrompt(ShellServerSession *session,
   const char_t *prompt)
{
   //Check parameters
   if(session == NULL || prompt == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the prompt string
   if(osStrlen(prompt) > SHELL_SERVER_MAX_PROMPT_LEN)
      return ERROR_INVALID_LENGTH;

   //Set the shell prompt to be used
   osStrcpy(session->prompt, prompt);
   //Save the length of the prompt string
   session->promptLen = osStrlen(prompt);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set timeout for read/write operations
 * @param[in] session Handle referencing a shell session
 * @param[in] timeout Maximum time to wait
 * @return Error code
 **/

error_t shellServerSetTimeout(ShellServerSession *session, systime_t timeout)
{
   error_t error;

   //Valid shell session?
   if(session != NULL)
   {
      //Set timeout for read/write operations
      error = sshSetChannelTimeout(session->channel, timeout);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Write to stdout stream
 * @param[in] session Handle referencing a shell session
 * @param[in] data Pointer to a buffer containing the data to be written
 * @param[in] length Number of data bytes to write
 * @param[in] written Number of bytes that have been written (optional parameter)
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t shellServerWriteStream(ShellServerSession *session, const void *data,
   size_t length, size_t *written, uint_t flags)
{
   error_t error;

   //Valid shell session?
   if(session != NULL)
   {
      //Write data to the specified channel
      error = sshWriteChannel(session->channel, data, length, written, flags);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Read from stdin stream
 * @param[in] session Handle referencing a shell session
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be read
 * @param[out] received Actual number of bytes that have been read
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t shellServerReadStream(ShellServerSession *session, void *data,
   size_t size, size_t *received, uint_t flags)
{
   error_t error;

   //Valid shell session?
   if(session != NULL)
   {
      //Receive data from the specified channel
      error = sshReadChannel(session->channel, data, size, received, flags);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Save command history
 * @param[in] session Handle referencing a shell session
 * @param[out] history Output buffer where to store the command history
 * @param[in] size Size of the buffer, in bytes
 * @param[out] length Actual length of the command history, in bytes
 * @return Error code
 **/

error_t shellServerSaveHistory(ShellServerSession *session, char_t *history,
   size_t size, size_t *length)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   size_t i;

   //Check parameters
   if(session == NULL || history == NULL || length == NULL)
      return ERROR_INVALID_PARAMETER;

   //If the output buffer is not large enough, then the oldest commands are
   //discarded
   for(i = 0; (session->historyLen - i) > size; )
   {
      //Each entry is terminated by a NULL character
      while(i < session->historyLen && session->history[i] != '\0')
      {
         i++;
      }

      //Skip the NULL terminator
      if(i < session->historyLen)
      {
         i++;
      }
   }

   //Save the most recent commands
   osMemcpy(history, session->history + i, session->historyLen - i);
   //Return the length of the command history
   *length = session->historyLen - i;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Restore command history
 * @param[in] session Handle referencing a shell session
 * @param[in] history Pointer to the buffer that contains the command history
 * @param[in] length Length of the command history, in bytes
 * @return Error code
 **/

error_t shellServerRestoreHistory(ShellServerSession *session,
   const char_t *history, size_t length)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   size_t i;

   //Check parameters
   if(session == NULL || history == NULL)
      return ERROR_INVALID_PARAMETER;

   //If the command history buffer is not large enough, then the oldest commands
   //are discarded
   for(i = 0; (length - i) > SHELL_SERVER_HISTORY_SIZE; )
   {
      //Each entry is terminated by a NULL character
      while(i < length && history[i] != '\0')
      {
         i++;
      }

      //Skip the NULL terminator
      if(i < length)
      {
         i++;
      }
   }

   //Restore the most recent commands
   osMemcpy(session->history, history, length - i);

   //Save the length of the command history
   session->historyLen = length - i;
   session->historyPos = length - i;

   //Properly terminate the last entry with a NULL character
   if(session->historyLen > 0)
   {
      session->history[session->historyLen - 1] = '\0';
   }

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Clear command history
 * @param[in] session Handle referencing a shell session
 * @return Error code
 **/

error_t shellServerClearHistory(ShellServerSession *session)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   //Make sure the shell session is valid
   if(session == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear all entries from command history
   session->historyLen = 0;
   session->historyPos = 0;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Shell server task
 * @param[in] param Pointer to the shell session
 **/

void shellServerTask(void *param)
{
   error_t error;
   SshChannel *channel;
   ShellServerContext *context;
   ShellServerSession *session;

   //Task prologue
   osEnterTask();

   //Point to the shell session
   session = (ShellServerSession *) param;
   //Point to the shell server context
   context = session->context;

   //Debug message
   TRACE_INFO("Starting shell task...\r\n");

   //Initialize status code
   error = NO_ERROR;

   //Process connection requests
   while(1)
   {
      //Wait for an connection request
      osWaitForEvent(&session->startEvent, INFINITE_DELAY);

      //Debug message
      TRACE_INFO("Starting shell session...\r\n");

      //Retrieve SSH channel handle
      channel = session->channel;

      //Check session state
      if(session->state == SHELL_SERVER_SESSION_STATE_OPEN)
      {
         //Set timeout for read/write operations
         sshSetChannelTimeout(channel, INFINITE_DELAY);

         //Any banner message?
         if(session->bufferLen > 0)
         {
            //Display welcome banner
            error = sshWriteChannel(channel, session->buffer,
               session->bufferLen, NULL, 0);
         }

         //Check status code
         if(!error)
         {
            //Display shell prompt
            error = sshWriteChannel(channel, session->prompt,
               osStrlen(session->prompt), NULL, 0);
         }

         //Initialize variables
         session->bufferLen = 0;
         session->bufferPos = 0;
         session->escSeqLen = 0;

         //Process user commands
         while(!error)
         {
            SshChannelEventDesc eventDesc[1];

            //Specifying the events the application is interested in
            eventDesc[0].channel = channel;
            eventDesc[0].eventMask = SSH_CHANNEL_EVENT_RX_READY;
            eventDesc[0].eventFlags = 0;

            //Wait for the channel to become ready to perform I/O
            error = sshPollChannels(eventDesc, 1, &session->event,
               SHELL_SERVER_TICK_INTERVAL);

            //Check status code
            if(error == NO_ERROR || error == ERROR_TIMEOUT)
            {
               //Window resized?
               if(session->windowResize)
               {
                  //Process window resize event
                  error = shellServerProcessWindowResize(session);
               }

               //Character received?
               if(eventDesc[0].eventFlags != 0)
               {
                  //Process received character
                  error = shellServerProcessChar(session);
               }
               else
               {
                  //Wait for the next character
                  error = NO_ERROR;
               }
            }
            else
            {
               //A communication error has occurred
               break;
            }
         }

         //Invoke user-defined callback, if any
         if(context->closeCallback != NULL)
         {
            //The session is about to close
            context->closeCallback(session, session->channel->connection->user);
         }
      }
      else if(session->state == SHELL_SERVER_SESSION_STATE_EXEC)
      {
         //Properly terminate the command line with a NULL character
         session->buffer[session->bufferLen] = '\0';
         //Process command line
         error = shellServerProcessCommandLine(session, session->buffer);
      }
      else
      {
         //Just for sanity
      }

      //Close SSH channel
      sshCloseChannel(channel);

      //Mark the current session as closed
      session->state = SHELL_SERVER_SESSION_STATE_CLOSED;

      //Debug message
      TRACE_INFO("Shell session terminated...\r\n");
   }
}

#endif
