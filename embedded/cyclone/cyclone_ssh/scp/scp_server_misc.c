/**
 * @file scp_server_misc.c
 * @brief Helper functions for SCP server
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
#define TRACE_LEVEL SCP_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_request.h"
#include "ssh/ssh_misc.h"
#include "scp/scp_server.h"
#include "scp/scp_server_file.h"
#include "scp/scp_server_directory.h"
#include "scp/scp_server_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SCP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Handle periodic operations
 * @param[in] context Pointer to the SCP server context
 **/

void scpServerTick(ScpServerContext *context)
{
}


/**
 * @brief SSH channel request callback
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] type Request type
 * @param[in] data Request-specific data
 * @param[in] length Length of the request-specific data, in bytes
 * @param[in] param Pointer to the SCP server context
 * @return Error code
 **/

error_t scpServerChannelRequestCallback(SshChannel *channel,
   const SshString *type, const uint8_t *data, size_t length,
   void *param)
{
   error_t error;
   ScpAccessStatus status;
   ScpServerContext *context;
   ScpServerSession *session;

   //Debug message
   TRACE_INFO("SCP server: SSH channel request callback...\r\n");

   //Initialize status code
   error = NO_ERROR;

   //Point to the SCP server context
   context = (ScpServerContext *) param;

   //Check request type
   if(sshCompareString(type, "exec"))
   {
      SshString arg;
      SshExecParams requestParams;

      //This message will request that the server start the execution of the
      //given command
      error = sshParseExecParams(data, length, &requestParams);
      //Any error to report?
      if(error)
         return error;

      //Check the first argument of the command line
      if(sshGetExecArg(&requestParams, 0, &arg) &&
         sshCompareString(&arg, "scp"))
      {
         //Retrieve the SCP session that matches the channel number
         session = scpServerFindSession(context, channel);

         //Any active session found?
         if(session != NULL)
         {
            //Only one of the "shell", "exec" and "subsystem" requests can
            //succeed per channel (refer to RFC 4254, section 6.5)
            return ERROR_WRONG_STATE;
         }
         else
         {
            //Open a new SCP session
            session = scpServerOpenSession(context, channel);
            //Check whether the session table runs out of resources
            if(session == NULL)
               return ERROR_OUT_OF_RESOURCES;

            //Invoke user-defined callback, if any
            if(context->checkUserCallback != NULL)
            {
               //Check user name
               status = context->checkUserCallback(session,
                  channel->connection->user);

               //Access denied?
               if(status != SCP_ACCESS_ALLOWED)
                  return ERROR_ACCESS_DENIED;
            }

            //Force the channel to operate in non-blocking mode
            error = sshSetChannelTimeout(channel, 0);
            //Any error to report?
            if(error)
               return error;

            //Parse SCP command line
            scpServerParseCommandLine(session, &requestParams);

            //Notify the SCP server that the session is ready
            osSetEvent(&session->context->event);
         }
      }
      else
      {
         //Unknown command
         return ERROR_UNKNOWN_REQUEST;
      }
   }
   else
   {
      //The request is not supported
      return ERROR_UNKNOWN_REQUEST;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief SCP command line parsing
 * @param[in] session Handle referencing an SCP session
 * @param[in] requestParams Pointer to the "exec" request parameters
 **/

void scpServerParseCommandLine(ScpServerSession *session,
   const SshExecParams *requestParams)
{
   error_t error;
   uint_t i;
   bool_t t;
   bool_t f;
   bool_t r;
   bool_t d;
   SshString arg;
   SshString path;

   //The options inform the direction of the copy
   t = FALSE;
   f = FALSE;
   r = FALSE;
   d = FALSE;

   //Initialize path name
   path.value = NULL;
   path.length = 0;

   //Parse SCP command line
   for(i = 1; ; i++)
   {
      //Get the value of the argument
      if(sshGetExecArg(requestParams, i, &arg))
      {
         //Valid option?
         if(arg.length > 0 && arg.value[0] == '-')
         {
            //The options inform the direction of the copy
            if(sshCompareString(&arg, "-t"))
            {
               //The -t option means copying to a remote machine
               t = TRUE;
            }
            else if(sshCompareString(&arg, "-f"))
            {
               //The -f option means copying from a remote machine
               f = TRUE;
            }
            else if(sshCompareString(&arg, "-r"))
            {
               //The -r option stands for recursive
               r = TRUE;
            }
            else if(sshCompareString(&arg, "-d"))
            {
               //The -d option means that the target should be a directory
               d = TRUE;
            }
            else
            {
               //Unknown option
            }
         }
         else
         {
            //Point to the first character of the path name
            path.value = arg.value;

            //Calculate the length of the path name
            path.length = requestParams->command.length - (arg.value -
               requestParams->command.value);

            //End of command line
            break;
         }
      }
      else
      {
         //End of command line
         break;
      }
   }

   //Valid path name?
   if(path.value != NULL && path.length > 0)
   {
      //Retrieve the full path name
      error = scpServerGetPath(session, &path, session->path,
         SCP_SERVER_MAX_PATH_LEN);

      //Check status code
      if(!error)
      {
         //Save SCP command options
         session->recursive = r;
         session->targetIsDir = d;

         //Check whether the command line is valid
         if(t && !f)
         {
            //Initiate a write operation
            session->state = SCP_SERVER_SESSION_STATE_WRITE_INIT;
         }
         else if(f && !t)
         {
            //Initiate a read operation
            session->state = SCP_SERVER_SESSION_STATE_READ_INIT;
         }
         else
         {
            //The command line is not valid
            error = ERROR_INVALID_COMMAND;
         }
      }
      else
      {
         //The path name is too long
         error = ERROR_INVALID_COMMAND;
      }
   }
   else
   {
      //The path name is not valid
      error = ERROR_INVALID_COMMAND;
   }

   //Any error to report?
   if(error)
   {
      //Save status code
      session->statusCode = error;
      //Update SCP session state
      session->state = SCP_SERVER_SESSION_STATE_ERROR;
   }
}


/**
 * @brief Find the SCP session that matches a given SSH channel
 * @param[in] context Pointer to the SCP server context
 * @param[in] channel Handle referencing an SSH channel
 * @return Pointer to the matching SCP session
 **/

ScpServerSession *scpServerFindSession(ScpServerContext *context,
   SshChannel *channel)
{
   uint_t i;
   ScpServerSession *session;

   //Loop through SCP sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Point to the current session
      session = &context->sessions[i];

      //Active session?
      if(session->state != SCP_SERVER_SESSION_STATE_CLOSED)
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
 * @brief Open a new SCP session
 * @param[in] context Pointer to the SCP server context
 * @param[in] channel Handle referencing an SSH channel
 * @return Pointer to the newly created SCP session
 **/

ScpServerSession *scpServerOpenSession(ScpServerContext *context,
   SshChannel *channel)
{
   uint_t i;
   ScpServerSession *session;

   //Loop through SCP sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Point to the current session
      session = &context->sessions[i];

      //Check whether the current session is free
      if(session->state == SCP_SERVER_SESSION_STATE_CLOSED)
      {
         //Initialize session parameters
         osMemset(session, 0, sizeof(ScpServerSession));

         //Attach SCP server context
         session->context = context;
         //Attach SSH channel
         session->channel = channel;

         //Set default user's root directory
         pathCopy(session->rootDir, context->rootDir,
            SCP_SERVER_MAX_ROOT_DIR_LEN);

         //Set default user's home directory
         pathCopy(session->homeDir, context->rootDir,
            SCP_SERVER_MAX_HOME_DIR_LEN);

         //Return session handle
         return session;
      }
   }

   //The session table runs out of space
   return NULL;
}


/**
 * @brief Close an SCP session
 * @param[in] session Handle referencing an SCP session
 **/

void scpServerCloseSession(ScpServerSession *session)
{
   uint_t i;

   //Debug message
   TRACE_INFO("Closing SCP session...\r\n");

   //Close file
   if(session->file != NULL)
   {
      fsCloseFile(session->file);
      session->file = NULL;
   }

   //Loop through open directories
   for(i = 0; i < SCP_SERVER_MAX_RECURSION_LEVEL; i++)
   {
      //Close directory
      if(session->dir[i] != NULL)
      {
         fsCloseDir(session->dir[i]);
         session->dir[i] = NULL;
      }
   }

   //Close SSH channel
   sshCloseChannel(session->channel);
   session->channel = NULL;

   //Mark the current session as closed
   session->state = SCP_SERVER_SESSION_STATE_CLOSED;
}


/**
 * @brief Register session events
 * @param[in] session Handle referencing an SCP session
 * @param[in] eventDesc SSH channel events to be registered
 **/

void scpServerRegisterSessionEvents(ScpServerSession *session,
   SshChannelEventDesc *eventDesc)
{
   //Check the state of the SCP session
   if(session->state == SCP_SERVER_SESSION_STATE_WRITE_INIT ||
      session->state == SCP_SERVER_SESSION_STATE_WRITE_ACK ||
      session->state == SCP_SERVER_SESSION_STATE_WRITE_FIN ||
      session->state == SCP_SERVER_SESSION_STATE_READ_COMMAND ||
      session->state == SCP_SERVER_SESSION_STATE_READ_STATUS ||
      session->state == SCP_SERVER_SESSION_STATE_ERROR)
   {
      eventDesc->channel = session->channel;
      eventDesc->eventMask = SSH_CHANNEL_EVENT_TX_READY;
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_WRITE_COMMAND ||
      session->state == SCP_SERVER_SESSION_STATE_WRITE_STATUS ||
      session->state == SCP_SERVER_SESSION_STATE_READ_INIT ||
      session->state == SCP_SERVER_SESSION_STATE_READ_ACK ||
      session->state == SCP_SERVER_SESSION_STATE_READ_FIN)
   {
      eventDesc->channel = session->channel;
      eventDesc->eventMask = SSH_CHANNEL_EVENT_RX_READY;
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_WRITE_DATA)
   {
      if(session->bufferPos < session->bufferLen)
      {
         eventDesc->channel = session->channel;
         eventDesc->eventMask = SSH_CHANNEL_EVENT_RX_READY;
      }
      else
      {
         eventDesc->eventFlags |= SSH_CHANNEL_EVENT_RX_READY;
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_READ_DATA)
   {
      if(session->bufferPos < session->bufferLen)
      {
         eventDesc->channel = session->channel;
         eventDesc->eventMask = SSH_CHANNEL_EVENT_TX_READY;
      }
      else
      {
         eventDesc->eventFlags |= SSH_CHANNEL_EVENT_TX_READY;
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_CLOSING)
   {
      eventDesc->eventFlags |= SSH_CHANNEL_EVENT_TX_READY;
   }
   else
   {
      //Just for sanity
   }
}


/**
 * @brief Session event handler
 * @param[in] session Handle referencing an SCP session
 **/

void scpServerProcessSessionEvents(ScpServerSession *session)
{
   error_t error;
   ScpDirective directive;

   //Initialize status code
   error = NO_ERROR;

   //Check the state of the SCP session
   if(session->state == SCP_SERVER_SESSION_STATE_WRITE_INIT)
   {
      //This status directive indicates a success
      directive.opcode = SCP_OPCODE_OK;
      //Send the directive to the SCP client
      error = scpServerSendDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Update SCP session state
         session->state = SCP_SERVER_SESSION_STATE_WRITE_COMMAND;
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_WRITE_COMMAND)
   {
      //Wait for a command from the SCP client
      error = scpServerReceiveDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //The source side feeds the commands and the target side consumes them
         scpServerProcessDirective(session, &directive);
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_WRITE_ACK)
   {
      //This status directive indicates a success
      directive.opcode = SCP_OPCODE_OK;
      //Send the directive to the SCP client
      error = scpServerSendDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Transfer the contents of the file
         session->state = SCP_SERVER_SESSION_STATE_WRITE_DATA;
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_WRITE_DATA)
   {
      //Write data to the specified file
      error = scpServerWriteData(session);
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_WRITE_STATUS)
   {
      //Wait for a status directive from the SCP client
      error = scpServerReceiveDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Check directive opcode
         if(directive.opcode == SCP_OPCODE_OK)
         {
            //A success directive has been received
            session->state = SCP_SERVER_SESSION_STATE_WRITE_FIN;
         }
         else
         {
            //A warning or error directive has been received
            session->state = SCP_SERVER_SESSION_STATE_CLOSING;
         }
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_WRITE_FIN)
   {
      //This status directive indicates a success
      directive.opcode = SCP_OPCODE_OK;
      //Send the directive to the SCP client
      error = scpServerSendDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Recursive copy?
         if(session->recursive || session->targetIsDir)
         {
            //Multiple files can be transferred by the client
            session->state = SCP_SERVER_SESSION_STATE_WRITE_COMMAND;
         }
         else
         {
            //A single file is transferred by the client
            session->state = SCP_SERVER_SESSION_STATE_CLOSING;
         }
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_READ_INIT)
   {
      //Wait for a status directive from the SCP client
      error = scpServerReceiveDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Check directive opcode
         if(directive.opcode == SCP_OPCODE_OK)
         {
            //Recursive copy?
            if(session->recursive)
            {
               //Open the specified directory
               error = scpServerOpenDir(session);
            }
            else
            {
               //Open the specified file for reading
               error = scpServerOpenFileForReading(session);
            }

            //Check status code
            if(!error)
            {
               //Update SCP session state
               session->state = SCP_SERVER_SESSION_STATE_READ_COMMAND;
            }
            else
            {
               //Save status code
               session->statusCode = error;
               //Send a status directive to indicate an error
               session->state = SCP_SERVER_SESSION_STATE_ERROR;
               //Catch exception
               error = NO_ERROR;
            }
         }
         else
         {
            //A warning or an error message has been received
            session->state = SCP_SERVER_SESSION_STATE_CLOSING;
         }
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_READ_COMMAND)
   {
      //Format command
      if(session->file != NULL)
      {
         //The 'C' directive indicates the next file to be transferred
         directive.opcode = SCP_OPCODE_FILE;
         directive.filename = pathGetFilename(session->path);
         directive.mode = session->fileMode;
         directive.size = session->fileSize;
      }
      else if(session->dir[session->dirLevel] != NULL)
      {
         //The 'D' directive indicates a directory change
         directive.opcode = SCP_OPCODE_DIR;
         directive.filename = pathGetFilename(session->path);
         directive.mode = session->fileMode;
         directive.size = 0;
      }
      else
      {
         //The 'E' directive indicates the end of the directory
         directive.opcode = SCP_OPCODE_END;
      }

      //Send the command to the SCP client
      error = scpServerSendDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Update SCP server state
         session->state = SCP_SERVER_SESSION_STATE_READ_ACK;
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_READ_ACK)
   {
      //Wait for a status directive from the SCP client
      error = scpServerReceiveDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Check directive opcode
         if(directive.opcode == SCP_OPCODE_OK)
         {
            if(session->file != NULL)
            {
               //Transfer the contents of the file
               session->state = SCP_SERVER_SESSION_STATE_READ_DATA;
            }
            else if(session->dir[session->dirLevel] != NULL)
            {
               //Fetch the next entry from the directory
               scpServerGetNextDirEntry(session);
            }
            else
            {
               //Change to the parent directory
               if(session->dirLevel > 0)
               {
                  session->dirLevel--;
               }

               //Valid directory pointer?
               if(session->dir[session->dirLevel] != NULL)
               {
                  //Fetch the next entry from the directory
                  scpServerGetNextDirEntry(session);
               }
               else
               {
                  //The copy operation is complete
                  session->state = SCP_SERVER_SESSION_STATE_CLOSING;
               }
            }
         }
         else
         {
            //A warning or an error message has been received
            session->state = SCP_SERVER_SESSION_STATE_CLOSING;
         }
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_READ_DATA)
   {
      //Read data from the specified file
      error = scpServerReadData(session);
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_READ_STATUS)
   {
      //This status directive indicates a success
      directive.opcode = SCP_OPCODE_OK;
      //Send the directive to the SCP client
      error = scpServerSendDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Update SCP session state
         session->state = SCP_SERVER_SESSION_STATE_READ_FIN;
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_READ_FIN)
   {
      //Wait for a status directive from the SCP client
      error = scpServerReceiveDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Recursive copy?
         if(session->recursive)
         {
            //Fetch the next entry from the directory
            scpServerGetNextDirEntry(session);
         }
         else
         {
            //Update SCP session state
            session->state = SCP_SERVER_SESSION_STATE_CLOSING;
         }
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_ERROR)
   {
      //This status directive indicates an error
      directive.opcode = SCP_OPCODE_ERROR;

      //Warning and error directives can be followed by a textual description
      if(session->statusCode == ERROR_INVALID_COMMAND)
      {
         directive.message = "Invalid command";
      }
      else if(session->statusCode == ERROR_INVALID_PATH)
      {
         directive.message = "Invalid path";
      }
      else if(session->statusCode == ERROR_FILE_NOT_FOUND)
      {
         directive.message = "No such file";
      }
      else if(session->statusCode == ERROR_DIRECTORY_NOT_FOUND)
      {
         directive.message = "No such directory";
      }
      else if(session->statusCode == ERROR_ACCESS_DENIED)
      {
         directive.message = "Access denied";
      }
      else
      {
         directive.message = "Protocol error";
      }

      //Send the directive to the SCP client
      error = scpServerSendDirective(session, &directive);

      //Check status code
      if(!error)
      {
         //Update SCP session state
         session->state = SCP_SERVER_SESSION_STATE_CLOSING;
      }
   }
   else if(session->state == SCP_SERVER_SESSION_STATE_CLOSING)
   {
      //Close SCP session
      scpServerCloseSession(session);
   }
   else
   {
      //Invalid state
      error = ERROR_WRONG_STATE;
   }

   //Any communication error?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK && error != ERROR_TIMEOUT)
   {
      //Close the SSH connection
      scpServerCloseSession(session);
   }
}


/**
 * @brief Send a SCP directive to the client
 * @param[in] session Handle referencing an SCP session
 * @param[in] directive SCP directive parameters
 * @return Error code
 **/

error_t scpServerSendDirective(ScpServerSession *session,
   const ScpDirective *directive)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Format and and send status message
   while(!error)
   {
      //Manage message transmission
      if(session->bufferLen == 0)
      {
         //Format directive line
         n = scpFormatDirective(directive, session->buffer);

         //Save the length of the directive line
         session->bufferLen = n;
         session->bufferPos = 0;
      }
      else if(session->bufferPos < session->bufferLen)
      {
         //Send more data
         error = sshWriteChannel(session->channel,
            session->buffer + session->bufferPos,
            session->bufferLen - session->bufferPos, &n, 0);

         //Check status code
         if(error == NO_ERROR || error == ERROR_TIMEOUT)
         {
            //Advance data pointer
            session->bufferPos += n;
         }
      }
      else
      {
         //Flush transmit buffer
         session->bufferLen = 0;
         session->bufferPos = 0;

         //We are done
         break;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Receive a SCP directive from the client
 * @param[in] session Handle referencing an SCP session
 * @param[in] directive SCP directive parameters
 * @return Error code
 **/

error_t scpServerReceiveDirective(ScpServerSession *session,
   ScpDirective *directive)
{
   error_t error;
   size_t n;
   uint8_t opcode;

   //Initialize status code
   error = NO_ERROR;

   //Receive and parse SCP directive
   while(!error)
   {
      //Manage message reception
      if(session->bufferLen == 0)
      {
         //Read the directive opcode
         error = sshReadChannel(session->channel, session->buffer, 1,
            &n, 0);

         //Check status code
         if(!error)
         {
            //Adjust the length of the buffer
            session->bufferLen += n;
         }
      }
      else if(session->bufferLen < SCP_SERVER_BUFFER_SIZE)
      {
         //Retrieve directive opcode
         opcode = session->buffer[0];

         //Check directive opcode
         if(opcode == SCP_OPCODE_OK)
         {
            //Parse the received directive
            error = scpParseDirective(session->buffer, directive);

            //Flush receive buffer
            session->bufferLen = 0;
            session->bufferPos = 0;

            //We are done
            break;
         }
         else if(opcode == SCP_OPCODE_WARNING ||
            opcode == SCP_OPCODE_ERROR ||
            opcode == SCP_OPCODE_FILE ||
            opcode == SCP_OPCODE_DIR ||
            opcode == SCP_OPCODE_END ||
            opcode == SCP_OPCODE_TIME)
         {
            //Limit the number of bytes to read at a time
            n = SCP_SERVER_BUFFER_SIZE - session->bufferLen;

            //Read more data
            error = sshReadChannel(session->channel, session->buffer +
               session->bufferLen, n, &n, SSH_FLAG_BREAK_CRLF);

            //Check status code
            if(!error)
            {
               //Adjust the length of the buffer
               session->bufferLen += n;

               //Check whether the string is properly terminated
               if(session->bufferLen > 0 &&
                  session->buffer[session->bufferLen - 1] == '\n')
               {
                  //Properly terminate the string with a NULL character
                  session->buffer[session->bufferLen - 1] = '\0';

                  //Parse the received directive
                  error = scpParseDirective(session->buffer, directive);

                  //Flush receive buffer
                  session->bufferLen = 0;
                  session->bufferPos = 0;

                  //We are done
                  break;
               }
               else
               {
                  //Wait for a new line character
                  error = ERROR_WOULD_BLOCK;
               }
            }
         }
         else
         {
            //Unknown directive
            error = ERROR_INVALID_COMMAND;
         }
      }
      else
      {
         //The implementation limits the size of messages it accepts
         error = ERROR_BUFFER_OVERFLOW;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Process SCP directive
 * @param[in] session Handle referencing an SCP session
 * @param[in] directive SCP directive sent by the client
 **/

void scpServerProcessDirective(ScpServerSession *session,
   const ScpDirective *directive)
{
   error_t error;

   //Check directive opcode
   if(directive->opcode == SCP_OPCODE_FILE)
   {
      //The file name must not contain illegal characters
      if(!osStrcmp(directive->filename, ".") ||
         !osStrcmp(directive->filename, "..") ||
         osStrchr(directive->filename, '*') ||
         osStrchr(directive->filename, '/') ||
         osStrchr(directive->filename, '\\'))
      {
         //Save status code
         session->statusCode = ERROR_INVALID_PATH;
         //Send a status directive to indicate an error
         session->state = SCP_SERVER_SESSION_STATE_ERROR;
      }
      else
      {
         //Open the specified file for reading
         error = scpServerOpenFileForWriting(session, directive->filename,
            directive->mode, directive->size);

         //Check status code
         if(!error)
         {
            //Initiate data transfer
            session->state = SCP_SERVER_SESSION_STATE_WRITE_ACK;
         }
         else
         {
            //Save status code
            session->statusCode = ERROR_FILE_NOT_FOUND;
            //Send a status directive to indicate an error
            session->state = SCP_SERVER_SESSION_STATE_ERROR;
         }
      }
   }
   else if(directive->opcode == SCP_OPCODE_DIR)
   {
      //The file name must not contain illegal characters
      if(!osStrcmp(directive->filename, ".") ||
         !osStrcmp(directive->filename, "..") ||
         osStrchr(directive->filename, '*') ||
         osStrchr(directive->filename, '/') ||
         osStrchr(directive->filename, '\\'))
      {
         //Save status code
         session->statusCode = ERROR_INVALID_PATH;
         //Send a status directive to indicate an error
         session->state = SCP_SERVER_SESSION_STATE_ERROR;
      }
      else
      {
         //If the folder does not exist, then create it
         error = scpServerCreateDir(session, directive->filename);

         //Check status code
         if(!error)
         {
            //Wait for the next command
            session->state = SCP_SERVER_SESSION_STATE_WRITE_INIT;
         }
         else
         {
            //Save status code
            session->statusCode = error;
            //Send a status directive to indicate an error
            session->state = SCP_SERVER_SESSION_STATE_ERROR;
         }
      }
   }
   else if(directive->opcode == SCP_OPCODE_END)
   {
      //Check current level of recursion
      if(session->dirLevel > 0)
      {
         //Change to the parent directory
         pathRemoveFilename(session->path);
         pathRemoveSlash(session->path);

         //Decrement recursion level
         session->dirLevel--;
         //Wait for the next command
         session->state = SCP_SERVER_SESSION_STATE_WRITE_INIT;
      }
      else
      {
         //Report an error
         session->statusCode = ERROR_DIRECTORY_NOT_FOUND;
         //Send a status directive to indicate an error
         session->state = SCP_SERVER_SESSION_STATE_ERROR;
      }
   }
   else if(directive->opcode == SCP_OPCODE_TIME)
   {
      //Discard time directives
      session->state = SCP_SERVER_SESSION_STATE_WRITE_INIT;
   }
   else
   {
      //A warning or an error message has been received
      session->state = SCP_SERVER_SESSION_STATE_CLOSING;
   }
}


/**
 * @brief Get permissions for the specified file or directory
 * @param[in] session Handle referencing an SCP session
 * @param[in] path Canonical path of the file
 * @return Access rights for the specified file
 **/

uint_t scpServerGetFilePermissions(ScpServerSession *session,
   const char_t *path)
{
   size_t n;
   uint_t perm;
   ScpServerContext *context;

   //Point to the SCP server context
   context = session->context;

   //Calculate the length of the root directory
   n = osStrlen(session->rootDir);

   //Make sure the pathname is valid
   if(!osStrncmp(path, session->rootDir, n))
   {
      //Strip root directory from the pathname
      path = scpServerStripRootDir(session, path);

      //Invoke user-defined callback, if any
      if(context->getFilePermCallback != NULL)
      {
         //Retrieve access rights for the specified file
         perm = context->getFilePermCallback(session,
            session->channel->connection->user, path);
      }
      else
      {
         //Use default access rights
         perm = SCP_FILE_PERM_LIST | SCP_FILE_PERM_READ |
            SCP_FILE_PERM_WRITE;
      }
   }
   else
   {
      //The specified pathname is not valid
      perm = 0;
   }

   //Return access rights
   return perm;
}


/**
 * @brief Retrieve the full pathname
 * @param[in] session Handle referencing an SCP session
 * @param[in] path Relative or absolute path
 * @param[out] fullPath Resulting full path
 * @param[in] maxLen Maximum acceptable path length
 * @return Error code
 **/

error_t scpServerGetPath(ScpServerSession *session, const SshString *path,
   char_t *fullPath, size_t maxLen)
{
   size_t n;

   //Relative or absolute path?
   if(path->length > 0 && (path->value[0] == '/' || path->value[0] == '\\'))
   {
      //Check the length of the root directory
      if(osStrlen(session->rootDir) > maxLen)
         return ERROR_FAILURE;

      //Copy the root directory
      osStrcpy(fullPath, session->rootDir);
   }
   else
   {
      //Check the length of the home directory
      if(osStrlen(session->homeDir) > maxLen)
         return ERROR_FAILURE;

      //Copy the home directory
      osStrcpy(fullPath, session->homeDir);
   }

   //Append a slash character to the root directory
   if(fullPath[0] != '\0')
   {
      pathAddSlash(fullPath, maxLen);
   }

   //Retrieve the length of the path name
   n = osStrlen(fullPath);

   //Check the length of the full path name
   if((n + path->length) > maxLen)
      return ERROR_FAILURE;

   //Append the specified path
   osStrncpy(fullPath + n, path->value, path->length);
   //Properly terminate the string with a NULL character
   fullPath[n + path->length] = '\0';

   //Clean the resulting path
   pathCanonicalize(fullPath);
   pathRemoveSlash(fullPath);

   //Calculate the length of the home directory
   n = osStrlen(session->rootDir);

   //If the server implementation limits access to certain parts of the file
   //system, it must be extra careful in parsing file names when enforcing
   //such restrictions
   if(osStrncmp(fullPath, session->rootDir, n))
      return ERROR_INVALID_PATH;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Strip root dir from specified pathname
 * @param[in] session Handle referencing an SCP session
 * @param[in] path input pathname
 * @return Resulting pathname with root dir stripped
 **/

const char_t *scpServerStripRootDir(ScpServerSession *session,
   const char_t *path)
{
   //Default directory
   static const char_t defaultDir[] = "/";

   //Local variables
   size_t m;
   size_t n;

   //Retrieve the length of the root directory
   n = osStrlen(session->rootDir);
   //Retrieve the length of the specified pathname
   m = osStrlen(path);

   //Strip the root dir from the specified pathname
   if(n <= 1)
   {
      return path;
   }
   else if(n < m)
   {
      return path + n;
   }
   else
   {
      return defaultDir;
   }
}

#endif
