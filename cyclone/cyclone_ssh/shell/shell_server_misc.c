/**
 * @file shell_server_misc.c
 * @brief Helper functions for SSH secure shell server
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
#include "ssh/ssh_request.h"
#include "ssh/ssh_misc.h"
#include "shell/shell_server.h"
#include "shell/shell_server_pty.h"
#include "shell/shell_server_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SHELL_SERVER_SUPPORT == ENABLED)


/**
 * @brief Handle periodic operations
 * @param[in] context Pointer to the shell server context
 **/

void shellServerTick(ShellServerContext *context)
{
}


/**
 * @brief SSH channel request callback
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] type Request type
 * @param[in] data Request-specific data
 * @param[in] length Length of the request-specific data, in bytes
 * @param[in] param Pointer to the shell server context
 * @return Error code
 **/

error_t shellServerChannelRequestCallback(SshChannel *channel,
   const SshString *type, const uint8_t *data, size_t length,
   void *param)
{
   error_t error;
   ShellAccessStatus status;
   ShellServerContext *context;
   ShellServerSession *session;

   //Debug message
   TRACE_INFO("Shell server: SSH channel request callback...\r\n");

   //Initialize status code
   error = NO_ERROR;

   //Point to the shell server context
   context = (ShellServerContext *) param;

   //Check request type
   if(sshCompareString(type, "pty-req"))
   {
      SshPtyReqParams requestParams;

      //Parse type-specific data
      error = sshParsePtyReqParams(data, length, &requestParams);

      //Successful parsing?
      if(!error)
      {
         //Retrieve the session that matches the channel number
         session = shellServerFindSession(context, channel);

         //If no matching session exists, a new session is started
         if(session == NULL)
         {
            //Allocate a new session
            session = shellServerOpenSession(context, channel);
         }

         //Valid session handle?
         if(session != NULL)
         {
            //All encoded terminal modes passed in a pty request are encoded
            //into a byte stream (refer to RFC 4254, section 8)
            shellServerParseTermModes(session, requestParams.termModes.value,
               requestParams.termModes.length);

            //Zero dimension parameters must be ignored (refer to RFC 4254,
            //section 6.2)
            if(requestParams.termWidthChars > 0)
            {
               //Save the terminal width (in characters)
               session->termWidth = requestParams.termWidthChars;
            }

            //Zero dimension parameters must be ignored (refer to RFC 4254,
            //section 6.2)
            if(requestParams.termHeightRows > 0)
            {
               //Save terminal height (in rows)
               session->termHeight = requestParams.termHeightRows;
            }
         }
         else
         {
            //The session table runs out of resources
            error = ERROR_OUT_OF_RESOURCES;
         }
      }
   }
   else if(sshCompareString(type, "env"))
   {
      //Environment variables may be passed to the shell/command to be
      //started later
   }
   else if(sshCompareString(type, "shell"))
   {
      //Check the length of the type-specific data
      if(length == 0)
      {
         //Retrieve the session that matches the channel number
         session = shellServerFindSession(context, channel);

         //If no matching session exists, a new session is started
         if(session == NULL)
         {
            //Allocate a new session
            session = shellServerOpenSession(context, channel);
         }

         //Valid session handle?
         if(session != NULL)
         {
            //Check session state
            if(session->state == SHELL_SERVER_SESSION_STATE_INIT)
            {
               //Invoke user-defined callback, if any
               if(context->checkUserCallback != NULL)
               {
                  //Check user name
                  status = context->checkUserCallback(session,
                     channel->connection->user);
               }
               else
               {
                  status = SHELL_ACCESS_ALLOWED;
               }

               //Check if user is granted access to the shell
               if(status == SHELL_ACCESS_ALLOWED)
               {
                  //Set initial session state
                  session->state = SHELL_SERVER_SESSION_STATE_OPEN;
                  //Start executing user commands
                  osSetEvent(&session->startEvent);
               }
               else
               {
                  //Access denied
                  shellServerCloseSession(session);
               }
            }
            else
            {
               //Only one of the "shell", "exec" and "subsystem" requests can
               //succeed per channel (refer to RFC 4254, section 6.5)
               error = ERROR_WRONG_STATE;
            }
         }
         else
         {
            //The session table runs out of resources
            error = ERROR_OUT_OF_RESOURCES;
         }
      }
      else
      {
         //The request must not contain type-specific data
         error = ERROR_INVALID_MESSAGE;
      }
   }
   else if(sshCompareString(type, "exec"))
   {
      SshString arg;
      SshExecParams requestParams;

      //This message will request that the server start the execution of the
      //given command
      error = sshParseExecParams(data, length, &requestParams);

      //Successful parsing?
      if(!error)
      {
         //Check the first argument of the command line
         if(sshGetExecArg(&requestParams, 0, &arg) &&
            sshCompareString(&arg, "scp"))
         {
            //Always reject SCP requests
            error = ERROR_UNKNOWN_REQUEST;
         }
         else
         {
            //Check the length of the command line
            if(requestParams.command.length < SHELL_SERVER_BUFFER_SIZE)
            {
               //Retrieve the session that matches the channel number
               session = shellServerFindSession(context, channel);

               //If no matching session exists, a new session is started
               if(session == NULL)
               {
                  //Allocate a new session
                  session = shellServerOpenSession(context, channel);
               }

               //Valid session handle?
               if(session != NULL)
               {
                  //Check session state
                  if(session->state == SHELL_SERVER_SESSION_STATE_INIT)
                  {
                     //Invoke user-defined callback, if any
                     if(context->checkUserCallback != NULL)
                     {
                        //Check user name
                        status = context->checkUserCallback(session,
                           channel->connection->user);
                     }
                     else
                     {
                        status = SHELL_ACCESS_ALLOWED;
                     }

                     //Check if user is granted access to the shell
                     if(status == SHELL_ACCESS_ALLOWED)
                     {
                        //Set initial session state
                        session->state = SHELL_SERVER_SESSION_STATE_EXEC;

                        //Copy command string
                        osMemcpy(session->buffer, requestParams.command.value,
                           requestParams.command.length);

                        //Properly terminate the string with a NULL character
                        session->buffer[requestParams.command.length] = '\0';
                        //Save the length of the command
                        session->bufferLen = requestParams.command.length;

                        //Start the execution of the given command
                        osSetEvent(&session->startEvent);
                     }
                     else
                     {
                        //Access denied
                        shellServerCloseSession(session);
                     }
                  }
                  else
                  {
                     //Only one of the "shell", "exec" and "subsystem" requests
                     //can succeed per channel (refer to RFC 4254, section 6.5)
                     error = ERROR_WRONG_STATE;
                  }
               }
               else
               {
                  //The session table runs out of resources
                  error = ERROR_OUT_OF_RESOURCES;
               }
            }
            else
            {
               //The command line is too long
               error = ERROR_INVALID_LENGTH;
            }
         }
      }
   }
   else if(sshCompareString(type, "window-change"))
   {
      SshWindowChangeParams requestParams;

      //When the window (terminal) size changes on the client side, it may
      //send a message to the other side to inform it of the new dimensions
      error = sshParseWindowChangeParams(data, length, &requestParams);

      //Successful parsing?
      if(!error)
      {
         //Retrieve the session that matches the channel number
         session = shellServerFindSession(context, channel);

         //Any active session found?
         if(session != NULL)
         {
            //Check whether the terminal has been resized
            if(requestParams.termWidthChars != session->termWidth ||
               requestParams.termHeightRows != session->termHeight)
            {
               //Zero dimension parameters must be ignored (refer to RFC 4254,
               //section 6.2)
               if(requestParams.termWidthChars > 0)
               {
                  //Save the new terminal width (in characters)
                  session->newTermWidth = requestParams.termWidthChars;
               }

               //Zero dimension parameters must be ignored (refer to RFC 4254,
               //section 6.2)
               if(requestParams.termHeightRows > 0)
               {
                  //Save the new terminal height (in rows)
                  session->newTermHeight = requestParams.termHeightRows;
               }

               //Notify the application of the window resize event
               session->windowResize = TRUE;
               osSetEvent(&session->event);
            }
         }
      }
   }
   else if(sshCompareString(type, "signal"))
   {
      SshSignalParams requestParams;

      //Parse type-specific data
      error = sshParseSignalParams(data, length, &requestParams);
   }
   else if(sshCompareString(type, "break"))
   {
      SshBreakParams requestParams;

      //Parse type-specific data
      error = sshParseBreakParams(data, length, &requestParams);
   }
   else
   {
      //The request is not supported
      error = ERROR_UNKNOWN_REQUEST;
   }

   //Return status code
   return error;
}


/**
 * @brief Find the shell session that matches a given SSH channel
 * @param[in] context Pointer to the shell server context
 * @param[in] channel Handle referencing an SSH channel
 * @return Pointer to the matching shell session
 **/

ShellServerSession *shellServerFindSession(ShellServerContext *context,
   SshChannel *channel)
{
   uint_t i;
   ShellServerSession *session;

   //Loop through shell sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Point to the current session
      session = &context->sessions[i];

      //Active session?
      if(session->state != SHELL_SERVER_SESSION_STATE_CLOSED)
      {
         //Matching channel found?
         if(session->channel == channel)
         {
            return session;
         }
      }
   }

   //The channel number does not match any active session
   return NULL;
}


/**
 * @brief Open a new shell session
 * @param[in] context Pointer to the shell server context
 * @param[in] channel Handle referencing an SSH channel
 * @return Pointer to the newly created shell session
 **/

ShellServerSession *shellServerOpenSession(ShellServerContext *context,
   SshChannel *channel)
{
   uint_t i;
   ShellServerSession *session;

   //Initialize pointer
   session = NULL;

   //Prefer sessions in CLOSED state
   for(i = 0; i < context->numSessions; i++)
   {
      //Check whether the current session is free
      if(context->sessions[i].state == SHELL_SERVER_SESSION_STATE_CLOSED)
      {
         //Point to the current session
         session = &context->sessions[i];
         break;
      }
   }

   //Reuse orphan sessions in INIT state, if necessary
   if(session == NULL)
   {
      //Loop through shell sessions
      for(i = 0; i < context->numSessions; i++)
      {
         //Check whether the current session can be reused
         if(context->sessions[i].state == SHELL_SERVER_SESSION_STATE_INIT)
         {
            //Point to the current session
            session = &context->sessions[i];
            break;
         }
      }
   }

   //Valid session?
   if(session != NULL)
   {
      //Attach shell server context
      session->context = context;
      //Attach SSH channel
      session->channel = channel;

      //Default shell prompt
      osStrcpy(session->prompt, ">");
      //Save the length of the prompt string
      session->promptLen = osStrlen(session->prompt);

      //Initialize session parameters
      session->backspaceCode = VT100_DEL_CODE;
      session->deleteCode = VT100_BS_CODE;
      session->termWidth = SHELL_SERVER_DEFAULT_TERM_WIDTH;
      session->termHeight = SHELL_SERVER_DEFAULT_TERM_HEIGHT;
      session->newTermWidth = SHELL_SERVER_DEFAULT_TERM_WIDTH;
      session->newTermHeight = SHELL_SERVER_DEFAULT_TERM_HEIGHT;

      //Initialize variables
      session->bufferPos = 0;
      session->bufferLen = 0;
      session->windowResize = FALSE;
      session->escSeqLen = 0;

#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
      //Clear command history
      session->historyPos = 0;
      session->historyLen = 0;
#endif

      //Set initial session state
      session->state = SHELL_SERVER_SESSION_STATE_INIT;
   }

   //Return a pointer to the newly created shell session, if any
   return session;
}


/**
 * @brief Close a shell session
 * @param[in] session Handle referencing a shell session
 **/

void shellServerCloseSession(ShellServerSession *session)
{
   //Debug message
   TRACE_INFO("Closing shell session...\r\n");

   //Close SSH channel
   sshCloseChannel(session->channel);
   session->channel = NULL;

   //Mark the current session as closed
   session->state = SHELL_SERVER_SESSION_STATE_CLOSED;
}


/**
 * @brief Parse encoded terminal modes
 * @param[in] session Handle referencing an shell session
 * @param[in] termModes Encoded terminal modes
 * @param[in] length Length of the encoded terminal modes, in bytes
 * @return Error code
 **/

error_t shellServerParseTermModes(ShellServerSession *session,
   const uint8_t *termModes, size_t length)
{
   error_t error;
   size_t i;

   //Initialize status code
   error = NO_ERROR;

   //All encoded terminal modes passed in a pty request are encoded into a
   //byte stream (refer to RFC 4254, section 8)
   for(i = 0; i < length && !error; i++)
   {
      //The stream consists of opcode-argument pairs wherein the opcode is
      //a byte value
      if(termModes[i] == 0)
      {
         //The stream is terminated by opcode TTY_OP_END
         break;
      }
      else if(termModes[i] >= 1 && termModes[i] <= 159)
      {
         //Opcodes 1 to 159 have a single uint32 argument
         if((i + sizeof(uint32_t)) < length)
         {
            //Check mnemonic
            if(termModes[i] == SHELL_TERM_MODE_VERASE)
            {
               //Set backspace key code
               session->backspaceCode = LOAD32BE(termModes + i + 1);

               //Set delete key code
               if(session->backspaceCode == VT100_BS_CODE)
               {
                  session->deleteCode = VT100_DEL_CODE;
               }
            }

            //Jump to the next opcode-argument pair
            i += sizeof(uint32_t);
         }
         else
         {
            //The opcode-argument pair is not valid
            error = ERROR_INVALID_SYNTAX;
         }
      }
      else
      {
         //Opcodes 160 to 255 are not yet defined, and cause parsing to stop
         break;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Command line processing
 * @param[in] session Handle referencing an shell session
 * @param[in] commandLine NULL-terminated string that contains the command line
 * @return error code
 **/

error_t shellServerProcessCommandLine(ShellServerSession *session,
   char_t *commandLine)
{
   error_t error;
   ShellServerContext *context;

   //Point to the shell server context
   context = session->context;

   //Invoke user-defined callback, if any
   if(context->commandLineCallback != NULL)
   {
      //Process the received command line
      error = context->commandLineCallback(session, commandLine);
   }
   else
   {
      //Discard the command line
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Add command line to history
 * @param[in] session Handle referencing an shell session
 * @param[in] commandLine NULL-terminated string that contains the command line
 **/

void shellServerAddCommandLine(ShellServerSession *session,
   const char_t *commandLine)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   size_t i;
   size_t j;
   size_t n;

   //Retrieve the length of the command line
   n = osStrlen(commandLine);

   //Valid command line?
   if(n > 0 && n < SHELL_SERVER_HISTORY_SIZE)
   {
      //Point to the first entry
      i = 0;

      //Remove duplicate entries from command history
      while(i < session->historyLen)
      {
         //Save current index
         j = i;

         //Each entry is terminated by a NULL character
         while(i < session->historyLen && session->history[i] != '\0')
         {
            i++;
         }

         //Check whether the current entry is a duplicate
         if((i - j) == n && osMemcmp(session->history + j, commandLine, n) == 0)
         {
            //Skip the NULL terminator
            if(i < session->historyLen)
            {
               i++;
            }

            //Remove the duplicate entry
            osMemmove(session->history + j, session->history + i,
               session->historyLen - i);

            //Adjust the length of the command history buffer
            session->historyLen -= i - j;
         }
         else
         {
            //Skip the NULL terminator
            i++;
         }
      }

      //Rewind to the first entry
      i = 0;

      //The oldest commands are discarded when the command history buffer runs
      //out of space
      while((session->historyLen + n + 1 - i) > SHELL_SERVER_HISTORY_SIZE)
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

      //Make room for the new entry
      if(i > 0)
      {
         //Delete the oldest entries
         osMemmove(session->history, session->history + i, session->historyLen - i);
         //Adjust the length of the command history buffer
         session->historyLen -= i;
      }

      //Add command line to history
      osMemcpy(session->history + session->historyLen, commandLine, n);
      //Properly terminate the new entry with a NULL character
      session->history[session->historyLen + n] = '\0';
      //Adjust the length of the command history buffer
      session->historyLen += n + 1;
   }

   //Change current position in history
   session->historyPos = session->historyLen;
#endif
}


/**
 * @brief Extract previous command line from history
 * @param[in] session Handle referencing an shell session
 * @param[out] commandLine Pointer to the previous command line
 * @param[out] length Length of the command line
 * @return error code
 **/

error_t shellServerGetPrevCommandLine(ShellServerSession *session,
   const char_t **commandLine, size_t *length)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   error_t error;
   size_t i;

   //Check current position in history
   if(session->historyPos > 0)
   {
      //Point to the last character of the previous entry
      i = session->historyPos - 1;

      //Entries are separated with a NULL character
      while(i > 0 && session->history[i - 1] != '\0')
      {
         i--;
      }

      //Extract the previous command line
      *commandLine = session->history + i;
      *length = osStrlen(session->history + i);

      //Change current position in history
      session->historyPos = i;

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //The oldest entry has been reached
      error = ERROR_NOT_FOUND;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Extract next command line from history
 * @param[in] session Handle referencing an shell session
 * @param[out] commandLine Pointer to the next command line
 * @param[out] length Length of the command line
 * @return error code
 **/

error_t shellServerGetNextCommandLine(ShellServerSession *session,
   const char_t **commandLine, size_t *length)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   error_t error;
   size_t i;

   //Get current position in history
   i = session->historyPos;

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

   //Next command line found?
   if(i < session->historyLen)
   {
      //Extract the next command line
      *commandLine = session->history + i;
      *length = osStrlen(session->history + i);

      //Change current position in history
      session->historyPos = i;

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //The most recent entry has been reached
      error = ERROR_NOT_FOUND;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Extract first command line from history
 * @param[in] session Handle referencing an shell session
 * @param[out] commandLine Pointer to the first command line
 * @param[out] length Length of the command line
 * @return error code
 **/

error_t shellServerGetFirstCommandLine(ShellServerSession *session,
   const char_t **commandLine, size_t *length)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   error_t error;

   //Check current position in history
   if(session->historyPos > 0)
   {
      //Extract the first command line
      *commandLine = session->history;
      *length = osStrlen(session->history);

      //Change current position in history
      session->historyPos = 0;

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //The oldest entry has been reached
      error = ERROR_NOT_FOUND;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Extract last command line from history
 * @param[in] session Handle referencing an shell session
 * @param[out] commandLine Pointer to the last command line
 * @param[out] length Length of the command line
 * @return error code
 **/

error_t shellServerGetLastCommandLine(ShellServerSession *session,
   const char_t **commandLine, size_t *length)
{
#if (SHELL_SERVER_HISTORY_SUPPORT == ENABLED)
   error_t error;
   size_t i;

   //Any entry found in command history?
   if(session->historyLen > 0)
   {
      //Point to the last character of the last entry
      i = session->historyLen - 1;

      //Entries are separated with a NULL character
      while(i > 0 && session->history[i - 1] != '\0')
      {
         i--;
      }

      //Extract the last command line
      *commandLine = session->history + i;
      *length = osStrlen(session->history + i);

      //Change current position in history
      session->historyPos = i;

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //The command history is empty
      error = ERROR_NOT_FOUND;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
