/**
 * @file sftp_server_misc.c
 * @brief Helper functions for SFTP server
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
#define TRACE_LEVEL SFTP_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_request.h"
#include "ssh/ssh_misc.h"
#include "sftp/sftp_server.h"
#include "sftp/sftp_server_file.h"
#include "sftp/sftp_server_directory.h"
#include "sftp/sftp_server_packet.h"
#include "sftp/sftp_server_misc.h"
#include "str.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SFTP_SERVER_SUPPORT == ENABLED)


/**
 * @brief Handle periodic operations
 * @param[in] context Pointer to the SFTP server context
 **/

void sftpServerTick(SftpServerContext *context)
{
}


/**
 * @brief SSH channel request callback
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] type Request type
 * @param[in] data Request-specific data
 * @param[in] length Length of the request-specific data, in bytes
 * @param[in] param Pointer to the SFTP server context
 * @return Error code
 **/

error_t sftpServerChannelRequestCallback(SshChannel *channel,
   const SshString *type, const uint8_t *data, size_t length,
   void *param)
{
   error_t error;
   SftpAccessStatus status;
   SftpServerContext *context;
   SftpServerSession *session;

   //Debug message
   TRACE_INFO("SFTP server: SSH channel request callback...\r\n");

   //Initialize status code
   error = NO_ERROR;

   //Point to the SFTP server context
   context = (SftpServerContext *) param;

   //Check request type
   if(sshCompareString(type, "subsystem"))
   {
      SshSubsystemParams requestParams;

      //This message executes a predefined subsystem
      error = sshParseSubsystemParams(data, length, &requestParams);
      //Any error to report?
      if(error)
         return error;

      //Check subsystem name
      if(sshCompareString(&requestParams.subsystemName, "sftp"))
      {
         //Retrieve the SFTP session that matches the channel number
         session = sftpServerFindSession(context, channel);

         //Any active session found?
         if(session != NULL)
         {
            //Only one of the "shell", "exec" and "subsystem" requests can
            //succeed per channel (refer to RFC 4254, section 6.5)
            return ERROR_WRONG_STATE;
         }
         else
         {
            //Open a new SFTP session
            session = sftpServerOpenSession(context, channel);
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
               if(status != SFTP_ACCESS_ALLOWED)
                  return ERROR_ACCESS_DENIED;
            }

            //Force the channel to operate in non-blocking mode
            error = sshSetChannelTimeout(channel, 0);
            //Any error to report?
            if(error)
               return error;

            //Set initial session state
            session->state = SFTP_SERVER_SESSION_STATE_RECEIVING;

            //Notify the SFTP server that the session is ready to accept data
            osSetEvent(&session->context->event);
         }
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
 * @brief Find the SFTP session that matches a given SSH channel
 * @param[in] context Pointer to the SFTP server context
 * @param[in] channel Handle referencing an SSH channel
 * @return Pointer to the matching SFTP session
 **/

SftpServerSession *sftpServerFindSession(SftpServerContext *context,
   SshChannel *channel)
{
   uint_t i;
   SftpServerSession *session;

   //Loop through SFTP sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Point to the current session
      session = &context->sessions[i];

      //Active session?
      if(session->state != SFTP_SERVER_SESSION_STATE_CLOSED)
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
 * @brief Open a new SFTP session
 * @param[in] context Pointer to the SFTP server context
 * @param[in] channel Handle referencing an SSH channel
 * @return Pointer to the newly created SFTP session
 **/

SftpServerSession *sftpServerOpenSession(SftpServerContext *context,
   SshChannel *channel)
{
   uint_t i;
   SftpServerSession *session;

   //Loop through SFTP sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Point to the current session
      session = &context->sessions[i];

      //Check whether the current session is free
      if(session->state == SFTP_SERVER_SESSION_STATE_CLOSED)
      {
         //Initialize session parameters
         osMemset(session, 0, sizeof(SftpServerSession));

         //Attach SFTP server context
         session->context = context;
         //Attach SSH channel
         session->channel = channel;

         //Set default user's root directory
         pathCopy(session->rootDir, context->rootDir,
            SFTP_SERVER_MAX_ROOT_DIR_LEN);

         //Set default user's home directory
         pathCopy(session->homeDir, context->rootDir,
            SFTP_SERVER_MAX_HOME_DIR_LEN);

         //Return session handle
         return session;
      }
   }

   //The session table runs out of space
   return NULL;
}


/**
 * @brief Close an SFTP session
 * @param[in] session Handle referencing an SFTP session
 **/

void sftpServerCloseSession(SftpServerSession *session)
{
   uint_t i;
   SftpServerContext *context;
   SftpFileObject *fileObject;

   //Debug message
   TRACE_INFO("Closing SFTP session...\r\n");

   //Point to the SFTP server context
   context = session->context;

   //Loop through file objects
   for(i = 0; i < context->numFileObjects; i++)
   {
      //Point to the current file object
      fileObject = &context->fileObjects[i];

      //Check whether the file object is currently in use
      if(fileObject->type != SSH_FILEXFER_TYPE_INVALID &&
         fileObject->session == session)
      {
         //Close file, if any
         if(fileObject->file != NULL)
         {
            fsCloseFile(fileObject->file);
            fileObject->file = NULL;
         }

         //Close directory, if any
         if(fileObject->dir != NULL)
         {
            fsCloseDir(fileObject->dir);
            fileObject->dir = NULL;
         }

         //Mark the entry as free
         fileObject->type = SSH_FILEXFER_TYPE_INVALID;
      }
   }

   //Close SSH channel
   sshCloseChannel(session->channel);
   session->channel = NULL;

   //Mark the current session as closed
   session->state = SFTP_SERVER_SESSION_STATE_CLOSED;
}


/**
 * @brief Register session events
 * @param[in] session Handle referencing an SFTP session
 * @param[in] eventDesc SSH channel events to be registered
 **/

void sftpServerRegisterSessionEvents(SftpServerSession *session,
   SshChannelEventDesc *eventDesc)
{
   //Check the state of the SFTP session
   if(session->state == SFTP_SERVER_SESSION_STATE_RECEIVING)
   {
      if(session->bufferPos < sizeof(SftpPacketHeader))
      {
         eventDesc->channel = session->channel;
         eventDesc->eventMask = SSH_CHANNEL_EVENT_RX_READY;
      }
      else if(session->bufferPos < session->bufferLen)
      {
         eventDesc->channel = session->channel;
         eventDesc->eventMask = SSH_CHANNEL_EVENT_RX_READY;
      }
      else
      {
         eventDesc->eventFlags |= SSH_CHANNEL_EVENT_RX_READY;
      }
   }
   else if(session->state == SFTP_SERVER_SESSION_STATE_SENDING)
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
   else if(session->state == SFTP_SERVER_SESSION_STATE_RECEIVING_DATA)
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
   else if(session->state == SFTP_SERVER_SESSION_STATE_SENDING_DATA)
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
   else
   {
      //Just for sanity
   }
}


/**
 * @brief Session event handler
 * @param[in] session Handle referencing an SFTP session
 **/

void sftpServerProcessSessionEvents(SftpServerSession *session)
{
   error_t error;
   size_t n;
   SshChannel *channel;

   //Initialize status code
   error = NO_ERROR;

   //Point to the SSH channel
   channel = session->channel;

   //Check the state of the SFTP session
   if(session->state == SFTP_SERVER_SESSION_STATE_RECEIVING)
   {
      //Receive SFTP packet
      if(session->bufferPos < sizeof(SftpPacketHeader))
      {
         //Receive more data
         error = sshReadChannel(channel, session->buffer + session->bufferPos,
            sizeof(SftpPacketHeader) - session->bufferPos, &n, 0);

         //Check status code
         if(!error)
         {
            //Advance data pointer
            session->bufferPos += n;

            //SFTP packet header successfully received?
            if(session->bufferPos >= sizeof(SftpPacketHeader))
            {
               //Parse SFTP packet header
               error = sftpServerParsePacketLength(session, session->buffer);
            }
         }
      }
      else if(session->bufferPos < session->bufferLen)
      {
         //Receive more data
         error = sshReadChannel(channel, session->buffer + session->bufferPos,
            session->bufferLen - session->bufferPos, &n, 0);

         //Check status code
         if(!error)
         {
            //Advance data pointer
            session->bufferPos += n;
         }
      }
      else
      {
         //Process SFTP packet
         error = sftpServerParsePacket(session, session->buffer,
            session->bufferLen, session->totalLen);
      }
   }
   else if(session->state == SFTP_SERVER_SESSION_STATE_SENDING)
   {
      //Send SFTP packet
      if(session->bufferPos < session->bufferLen)
      {
         //Send more data
         error = sshWriteChannel(channel, session->buffer + session->bufferPos,
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
         //Flush receive buffer
         session->bufferLen = 0;
         session->bufferPos = 0;

         //Wait for the next SFTP packet
         session->state = SFTP_SERVER_SESSION_STATE_RECEIVING;
      }
   }
   else if(session->state == SFTP_SERVER_SESSION_STATE_RECEIVING_DATA)
   {
      //Receive data payload
      if(session->bufferPos < session->bufferLen)
      {
         //Receive more data
         error = sshReadChannel(channel, session->buffer + session->bufferPos,
            session->bufferLen - session->bufferPos, &n, 0);

         //Check status code
         if(!error)
         {
            //Advance data pointer
            session->bufferPos += n;
         }
      }
      else
      {
         //Write the data to the specified file
         error = sftpServerWriteData(session);

         //Check status code
         if(!error)
         {
            //Check whether the data transfer is complete
            if(session->dataLen == 0)
            {
               //The server responds to a write request with an SSH_FXP_STATUS
               //message
               if(session->requestStatus == NO_ERROR)
               {
                  //Successful write operation
                  error = sftpFormatFxpStatus(session, session->requestId,
                     SSH_FX_OK, "Success");
               }
               else if(session->requestStatus == ERROR_INVALID_HANDLE)
               {
                  //The supplied handle is not valid
                  error = sftpFormatFxpStatus(session, session->requestId,
                     SSH_FX_FAILURE, "Invalid handle");
               }
               else
               {
                  //Generic error
                  error = sftpFormatFxpStatus(session, session->requestId,
                     SSH_FX_FAILURE, "Failed to write data");
               }
            }
         }
      }
   }
   else if(session->state == SFTP_SERVER_SESSION_STATE_SENDING_DATA)
   {
      //Send data payload
      if(session->bufferPos < session->bufferLen)
      {
         //Send more data
         error = sshWriteChannel(channel, session->buffer + session->bufferPos,
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
         //Flush receive buffer
         session->bufferLen = 0;
         session->bufferPos = 0;

         //Check whether the data transfer is in progress?
         if(session->dataLen > 0)
         {
            //Read data from the specified file
            error = sftpServerReadData(session);
         }
         else
         {
            //The data transfer is complete
            session->state = SFTP_SERVER_SESSION_STATE_RECEIVING;
         }
      }
   }
   else
   {
      //Invalid state
      error = ERROR_WRONG_STATE;
   }

   //Any communication error?
   if(error != NO_ERROR && error != ERROR_TIMEOUT)
   {
      //Close the SSH connection
      sftpServerCloseSession(session);
   }
}


/**
 * @brief Retrieve the length of an incoming SFTP packet
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to received SFTP packet
 * @return Error code
 **/

error_t sftpServerParsePacketLength(SftpServerSession *session,
   const uint8_t *packet)
{
   error_t error;
   const SftpPacketHeader *header;

   //Initialize status code
   error = NO_ERROR;

   //Point to the SSH packet header
   header = (SftpPacketHeader *) packet;

   //Convert the packet length to host byte order
   session->totalLen = ntohl(header->length);
   //The length of the packet does not include the packet_length field itself
   session->totalLen += sizeof(uint32_t);

   //Sanity check
   if(session->totalLen > ntohl(header->length))
   {
      //SSH_FXP_WRITE packet received?
      if(header->type == SSH_FXP_WRITE)
      {
         //Read as much data as possible
         session->bufferLen = MIN(session->totalLen, SFTP_SERVER_BUFFER_SIZE);
      }
      else
      {
         //Check the length of the packet
         if(session->totalLen <= SFTP_SERVER_BUFFER_SIZE)
         {
            //Save the total length of the packet
            session->bufferLen = session->totalLen;
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_LENGTH;
         }
      }
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_LENGTH;
   }

   //Return status code
   return error;
}


/**
 * @brief SFTP packet processing
 * @param[in] session Handle referencing an SFTP session
 * @param[in] packet Pointer to the received SFTP packet
 * @param[in] fragLen Number of bytes available on hand
 * @param[in] totalLen Total length of the packet, in bytes
 * @return Error code
 **/

error_t sftpServerParsePacket(SftpServerSession *session,
   const uint8_t *packet, size_t fragLen, size_t totalLen)
{
   error_t error;
   const SftpPacketHeader *header;

   //Debug message
   TRACE_DEBUG("SFTP packet received (%" PRIuSIZE " bytes)...\r\n", totalLen);
   TRACE_VERBOSE_ARRAY("  ", packet, fragLen);

   //Check the length of the received packet
   if(fragLen >= sizeof(SftpPacketHeader) && fragLen <= totalLen)
   {
      //Point to the SSH packet header
      header = (SftpPacketHeader *) packet;

      //Retrieve the length of the payload
      fragLen -= sizeof(SftpPacketHeader);
      totalLen -= sizeof(SftpPacketHeader);

      //When the file transfer protocol starts, the client first sends a
      //SSH_FXP_INIT (including its version number) packet to the server
      if(session->version == 0)
      {
         //Check message type
         if(header->type == SSH_FXP_INIT)
         {
            //The SSH_FXP_INIT message contains the client's version number
            error = sftpServerParseFxpInit(session, header->payload, fragLen);
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_TYPE;
         }
      }
      else
      {
         //Check message type
         if(header->type == SSH_FXP_OPEN)
         {
            //Files are opened and created using the SSH_FXP_OPEN message
            error = sftpServerParseFxpOpen(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_CLOSE)
         {
            //A file is closed by using the SSH_FXP_CLOSE request
            error = sftpServerParseFxpClose(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_READ)
         {
            //Once a file has been opened, it can be read using the SSH_FXP_READ
            //message
            error = sftpServerParseFxpRead(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_WRITE)
         {
            //Writing to a file is achieved using the SSH_FXP_WRITE message
            error = sftpServerParseFxpWrite(session, header->payload, fragLen,
               totalLen);
         }
         else if(header->type == SSH_FXP_LSTAT)
         {
            //The SSH_FXP_LSTAT request can be used retrieve the attributes
            //for a named file (SSH_FXP_LSTAT does not follow symbolic links)
            error = sftpServerParseFxpStat(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_FSTAT)
         {
            //SSH_FXP_FSTAT differs from SSH_FXP_STAT and SSH_FXP_LSTAT in that
            //it returns status information for an open file (identified by the
            //file handle)
            error = sftpServerParseFxpFstat(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_SETSTAT)
         {
            //File attributes may be modified using the SSH_FXP_SETSTAT request
            error = sftpServerParseFxpSetStat(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_FSETSTAT)
         {
            //The SSH_FXP_FSETSTAT request modifies the attributes of a file
            //which is already open
            error = sftpServerParseFxpSetFstat(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_OPENDIR)
         {
            //The SSH_FXP_OPENDIR opens a directory for reading
            error = sftpServerParseFxpOpenDir(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_READDIR)
         {
            //A directory can be listed using SSH_FXP_READDIR requests
            error = sftpServerParseFxpReadDir(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_REMOVE)
         {
            //Files can be removed using the SSH_FXP_REMOVE message
            error = sftpServerParseFxpRemove(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_MKDIR)
         {
            //New directories can be created using the SSH_FXP_MKDIR request
            error = sftpServerParseFxpMkDir(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_RMDIR)
         {
            //Directories can be removed using the SSH_FXP_RMDIR request
            error = sftpServerParseFxpRmDir(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_REALPATH)
         {
            //The SSH_FXP_REALPATH request can be used to have the server
            //canonicalize any given path name to an absolute path
            error = sftpServerParseFxpRealPath(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_STAT)
         {
            //The SSH_FXP_STAT request can be used retrieve the attributes
            //for a named file (SSH_FXP_STAT follows symbolic links)
            error = sftpServerParseFxpStat(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_RENAME)
         {
            //Files (and directories) can be renamed using the SSH_FXP_RENAME
            //message
            error = sftpServerParseFxpRename(session, header->payload, fragLen);
         }
         else if(header->type == SSH_FXP_EXTENDED)
         {
            //The SSH_FXP_EXTENDED request provides a generic extension
            //mechanism for adding vendor-specific commands
            error = sftpServerParseFxpExtended(session, header->payload, fragLen);
         }
         else
         {
            //Debug message
            TRACE_WARNING("Unknown SFTP packet type!\r\n");
            //Unknown packet type
            error = ERROR_INVALID_TYPE;
         }
      }
   }
   else
   {
      //Malformed SFTP packet
      error = ERROR_INVALID_LENGTH;
   }

   //Any error to report?
   if(error)
   {
      //Flush buffer
      session->bufferPos = 0;
      session->bufferLen = 0;
   }

   //Return status code
   return error;
}


/**
 * @brief Generate a unique handle
 * @param[in] session Handle referencing an SFTP session
 * @return Handle value
 **/

uint32_t sftpServerGenerateHandle(SftpServerSession *session)
{
   uint_t i;
   bool_t valid;
   SftpServerContext *context;
   SftpFileObject *fileObject;

   //Point to the SFTP server context
   context = session->context;

   //SSH_FXP_OPEN and SSH_FXP_OPENDIR requests return a handle which may be
   //used to access the file or the directory later
   for(valid = FALSE; !valid; )
   {
      //Generate a new handle value
      session->handle++;

      //Loop through file objects
      for(i = 0, valid = TRUE; i < context->numFileObjects && valid; i++)
      {
         //Point to the current file object
         fileObject = &context->fileObjects[i];

         //The handle can identify a file or a directory
         if(fileObject->type != SSH_FILEXFER_TYPE_INVALID &&
            fileObject->session == session)
         {
            //Compare handle values
            if(fileObject->handle == session->handle)
            {
               //The handle value is already in use
               valid = FALSE;
            }
         }
      }
   }

   //Return handle value
   return session->handle;
}


/**
 * @brief Get permissions for the specified file or directory
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Canonical path of the file
 * @return Access rights for the specified file
 **/

uint_t sftpServerGetFilePermissions(SftpServerSession *session,
   const char_t *path)
{
   size_t n;
   uint_t perm;
   SftpServerContext *context;

   //Point to the SFTP server context
   context = session->context;

   //Calculate the length of the root directory
   n = osStrlen(session->rootDir);

   //Make sure the pathname is valid
   if(!osStrncmp(path, session->rootDir, n))
   {
      //Strip root directory from the pathname
      path = sftpServerStripRootDir(session, path);

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
         perm = SFTP_FILE_PERM_LIST | SFTP_FILE_PERM_READ |
            SFTP_FILE_PERM_WRITE;
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
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path Relative or absolute path
 * @param[out] fullPath Resulting full path
 * @param[in] maxLen Maximum acceptable path length
 * @return Error code
 **/

error_t sftpServerGetPath(SftpServerSession *session, const SshString *path,
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
      pathAddSlash(fullPath, maxLen);

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
 * @param[in] session Handle referencing an SFTP session
 * @param[in] path input pathname
 * @return Resulting pathname with root dir stripped
 **/

const char_t *sftpServerStripRootDir(SftpServerSession *session,
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
