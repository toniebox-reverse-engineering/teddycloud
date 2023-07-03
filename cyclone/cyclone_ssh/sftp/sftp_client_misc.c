/**
 * @file sftp_client_misc.c
 * @brief Helper functions for SFTP client
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
#include "ssh/ssh_connection.h"
#include "ssh/ssh_request.h"
#include "ssh/ssh_misc.h"
#include "sftp/sftp_client.h"
#include "sftp/sftp_client_packet.h"
#include "sftp/sftp_client_misc.h"
#include "path.h"
#include "debug.h"

//Check SSH stack configuration
#if (SFTP_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Update SFTP client state
 * @param[in] context Pointer to the SFTP client context
 * @param[in] newState New state to switch to
 **/

void sftpClientChangeState(SftpClientContext *context,
   SftpClientState newState)
{
   //Switch to the new state
   context->state = newState;

   //Save current time
   context->timestamp = osGetSystemTime();
}


/**
 * @brief Open SSH connection
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientOpenConnection(SftpClientContext *context)
{
   error_t error;
   Socket *socket;
   SshConnection *connection;

   //Initialize SSH context
   error = sshInit(&context->sshContext, &context->sshConnection, 1,
      &context->sshChannel, 1);
   //Any error to report?
   if(error)
      return error;

   //Select client operation mode
   error = sshSetOperationMode(&context->sshContext, SSH_OPERATION_MODE_CLIENT);
   //Any error to report?
   if(error)
      return error;

   //Invoke user-defined callback, if any
   if(context->sshInitCallback != NULL)
   {
      //Perform SSH related initialization
      error = context->sshInitCallback(context, &context->sshContext);
      //Any error to report?
      if(error)
         return error;
   }

   //Open a TCP socket
   socket = socketOpen(SOCKET_TYPE_STREAM, SOCKET_IP_PROTO_TCP);

   //Valid socket handle
   if(socket != NULL)
   {
      //Associate the socket with the relevant interface
      socketBindToInterface(socket, context->interface);
      //Set timeout
      socketSetTimeout(socket, context->timeout);

      //Open a new SSH connection
      connection = sshOpenConnection(&context->sshContext, socket);

      //Failed to open connection?
      if(connection == NULL)
      {
         //Clean up side effects
         socketClose(socket);
         //Report an error
         error = ERROR_OPEN_FAILED;
      }
   }
   else
   {
      //Failed to open socket
      error = ERROR_OPEN_FAILED;
   }

   //Return status code
   return error;
}


/**
 * @brief Establish SSH connection
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientEstablishConnection(SftpClientContext *context)
{
   error_t error;
   SshConnection *connection;
   SshChannel *channel;

   //Point to the SSH connection
   connection = &context->sshConnection;
   //Point to the SSH channel
   channel = &context->sshChannel;

   //Check the state of the SSH connection
   if(context->sshConnection.state < SSH_CONN_STATE_OPEN)
   {
      //Perform SSH key exchange and user authentication
      error = sftpClientProcessEvents(context);
   }
   else if(context->sshConnection.state == SSH_CONN_STATE_OPEN)
   {
      //Check the state of the SFTP client
      if(context->state == SFTP_CLIENT_STATE_CHANNEL_OPEN)
      {
         //Allocate a new SSH channel
         channel = sshCreateChannel(connection);

         //Valid channel handle?
         if(channel != NULL)
         {
            //Force the channel to operate in non-blocking mode
            error = sshSetChannelTimeout(channel, 0);

            //Check status code
            if(!error)
            {
               //The client sends an SSH_MSG_CHANNEL_OPEN message to the server
               //in order to open a new channel
               error = sshSendChannelOpen(channel, "session", NULL);
            }

            //Check status code
            if(!error)
            {
               //Update SFTP client state
               sftpClientChangeState(context,
                  SFTP_CLIENT_STATE_CHANNEL_OPEN_REPLY);
            }
         }
         else
         {
            //Report an error
            error = ERROR_OPEN_FAILED;
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_CHANNEL_OPEN_REPLY)
      {
         //Wait for server's response
         error = sftpClientProcessEvents(context);

         //Check status code
         if(!error)
         {
            //Check the state of the channel
            if(channel->state == SSH_CHANNEL_STATE_RESERVED)
            {
               //Continue processing
            }
            else if(channel->state == SSH_CHANNEL_STATE_OPEN)
            {
               //An SSH_MSG_CHANNEL_OPEN_CONFIRMATION message has been received
               sftpClientChangeState(context, SFTP_CLIENT_STATE_CHANNEL_REQUEST);
            }
            else if(channel->state == SSH_CHANNEL_STATE_CLOSED)
            {
               //An SSH_MSG_CHANNEL_OPEN_FAILURE message has been received
               error = ERROR_OPEN_FAILED;
            }
            else
            {
               //Invalid state
               error = ERROR_WRONG_STATE;
            }
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_CHANNEL_REQUEST)
      {
         SshSubsystemParams requestParams;

         //Set "subsystem" request parameters
         requestParams.subsystemName.value = "sftp";
         requestParams.subsystemName.length = osStrlen("sftp");

         //Send an SSH_MSG_CHANNEL_REQUEST message to the server
         error = sshSendChannelRequest(channel, "subsystem", &requestParams,
            TRUE);

         //Check status code
         if(!error)
         {
            //Update SFTP client state
            sftpClientChangeState(context, SFTP_CLIENT_STATE_CHANNEL_REPLY);
         }
      }
      else if(context->state == SFTP_CLIENT_STATE_CHANNEL_REPLY)
      {
         //Wait for server's response
         error = sftpClientProcessEvents(context);

         //Check status code
         if(!error)
         {
            //Check the state of the channel request
            if(channel->requestState == SSH_REQUEST_STATE_PENDING)
            {
               //Continue processing
            }
            else if(channel->requestState == SSH_REQUEST_STATE_SUCCESS)
            {
               //An SSH_MSG_CHANNEL_SUCCESS message has been received
               sftpClientChangeState(context, SFTP_CLIENT_STATE_CHANNEL_DATA);
            }
            else if(channel->requestState == SSH_REQUEST_STATE_FAILURE)
            {
               //An SSH_MSG_CHANNEL_FAILURE message has been received
               error = ERROR_OPEN_FAILED;
            }
            else
            {
               //Invalid state
               error = ERROR_WRONG_STATE;
            }
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }
   else
   {
      //Invalid state
      error = ERROR_WRONG_STATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Close SSH connection
 * @param[in] context Pointer to the SFTP client context
 **/

void sftpClientCloseConnection(SftpClientContext *context)
{
   //Check the state of the SSH connection
   if(context->sshConnection.state != SSH_CONN_STATE_CLOSED)
   {
      //Close SSH connection
      sshCloseConnection(&context->sshConnection);
   }

   //Release SSH context
   sshDeinit(&context->sshContext);
}


/**
 * @brief Send SFTP request and wait for a response
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientSendCommand(SftpClientContext *context)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Send SFTP request and wait for the SFTP response to be received
   while(!error)
   {
      //Send SFTP request
      if(context->requestPos < context->requestLen)
      {
         //Send more data
         error = sshWriteChannel(&context->sshChannel,
            context->buffer + context->requestPos,
            context->requestLen - context->requestPos, &n, 0);

         //Check status code
         if(error == NO_ERROR || error == ERROR_TIMEOUT)
         {
            //Advance data pointer
            context->requestPos += n;
         }
      }
      else
      {
         //Receive SFTP response
         if(context->responsePos < sizeof(SftpPacketHeader))
         {
            //Receive more data
            error = sshReadChannel(&context->sshChannel,
               context->buffer + context->responsePos,
               sizeof(SftpPacketHeader) - context->responsePos, &n, 0);

            //Check status code
            if(!error)
            {
               //Advance data pointer
               context->responsePos += n;

               //SFTP packet header successfully received?
               if(context->responsePos >= sizeof(SftpPacketHeader))
               {
                  //Parse SFTP packet header
                  error = sftpClientParsePacketLength(context, context->buffer);
               }
            }
         }
         else if(context->responsePos < context->responseLen)
         {
            //Receive more data
            error = sshReadChannel(&context->sshChannel,
               context->buffer + context->responsePos,
               context->responseLen - context->responsePos, &n, 0);

            //Check status code
            if(!error)
            {
               //Advance data pointer
               context->responsePos += n;
            }
         }
         else
         {
            //Process SFTP packet
            error = sftpClientParsePacket(context, context->buffer,
               context->responseLen, context->responseTotalLen);

            //An SFTP response has been received
            break;
         }
      }

      //Check status code
      if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
      {
         //Process SSH connection events
         error = sftpClientProcessEvents(context);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Process SFTP client events
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientProcessEvents(SftpClientContext *context)
{
   error_t error;
   uint_t i;
   SshContext *sshContext;
   SshConnection *connection;

   //Point to the SSH context
   sshContext = &context->sshContext;

   //Clear event descriptor set
   osMemset(sshContext->eventDesc, 0, sizeof(sshContext->eventDesc));

   //Specify the events the application is interested in
   for(i = 0; i < sshContext->numConnections; i++)
   {
      //Point to the structure describing the current connection
      connection = &sshContext->connections[i];

      //Loop through active connections only
      if(connection->state != SSH_CONN_STATE_CLOSED)
      {
         //Register the events related to the current SSH connection
         sshRegisterConnectionEvents(sshContext, connection, &sshContext->eventDesc[i]);
      }
   }

   //Wait for one of the set of sockets to become ready to perform I/O
   error = socketPoll(sshContext->eventDesc, sshContext->numConnections,
      &sshContext->event, context->timeout);

   //Verify status code
   if(!error)
   {
      //Event-driven processing
      for(i = 0; i < sshContext->numConnections && !error; i++)
      {
         //Point to the structure describing the current connection
         connection = &sshContext->connections[i];

         //Loop through active connections only
         if(connection->state != SSH_CONN_STATE_CLOSED)
         {
            //Check whether the socket is ready to perform I/O
            if(sshContext->eventDesc[i].eventFlags != 0)
            {
               //Connection event handler
               error = sshProcessConnectionEvents(sshContext, connection);
            }
         }
      }
   }

   //Check status code
   if(error == ERROR_WOULD_BLOCK || error == ERROR_TIMEOUT)
   {
      //Check whether the timeout has elapsed
      error = sftpClientCheckTimeout(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Retrieve the length of an incoming SFTP packet
 * @param[in] context Pointer to the SFTP client context
 * @param[in] packet Pointer to received SFTP packet
 * @return Error code
 **/

error_t sftpClientParsePacketLength(SftpClientContext *context,
   const uint8_t *packet)
{
   error_t error;
   const SftpPacketHeader *header;

   //Initialize status code
   error = NO_ERROR;

   //Point to the SSH packet header
   header = (SftpPacketHeader *) packet;

   //Convert the packet length to host byte order
   context->responseTotalLen = ntohl(header->length);
   //The length of the packet does not include the packet_length field itself
   context->responseTotalLen += sizeof(uint32_t);

   //Sanity check
   if(context->responseTotalLen > ntohl(header->length))
   {
      //SSH_FXP_DATA or SSH_FXP_NAME packet received?
      if(header->type == SSH_FXP_DATA)
      {
         //Read only the header of the SSH_FXP_DATA packet
         context->responseLen = MIN(context->responseTotalLen,
            sizeof(SftpPacketHeader) + sizeof(SftpFxpDataHeader));
      }
      else if(header->type == SSH_FXP_NAME)
      {
         //Read as much data as possible
         context->responseLen = MIN(context->responseTotalLen,
            SFTP_CLIENT_BUFFER_SIZE);
      }
      else
      {
         //Check the length of the packet
         if(context->responseTotalLen <= SFTP_CLIENT_BUFFER_SIZE)
         {
            //Save the total length of the packet
            context->responseLen = context->responseTotalLen;
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
 * @param[in] context Pointer to the SFTP client context
 * @param[in] packet Pointer to received SFTP packet
 * @param[in] fragLen Number of bytes available on hand
 * @param[in] totalLen Total length of the packet, in bytes
 * @return Error code
 **/

error_t sftpClientParsePacket(SftpClientContext *context, const uint8_t *packet,
   size_t fragLen, size_t totalLen)
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

      //Check message type
      if(header->type == SSH_FXP_VERSION)
      {
         //Parse SSH_FXP_VERSION packet
         error = sftpClientParseFxpVersion(context, header->payload, fragLen);
      }
      else if(header->type == SSH_FXP_STATUS)
      {
         //Parse SSH_FXP_STATUS packet
         error = sftpClientParseFxpStatus(context, header->payload, fragLen);
      }
      else if(header->type == SSH_FXP_HANDLE)
      {
         //Parse SSH_FXP_HANDLE packet
         error = sftpClientParseFxpHandle(context, header->payload, fragLen);
      }
      else if(header->type == SSH_FXP_DATA)
      {
         //Parse SSH_FXP_DATA packet
         error = sftpClientParseFxpData(context, header->payload, fragLen,
            totalLen);
      }
      else if(header->type == SSH_FXP_NAME)
      {
         //Parse SSH_FXP_NAME packet
         error = sftpClientParseFxpName(context, header->payload, fragLen,
            totalLen);
      }
      else if(header->type == SSH_FXP_ATTRS)
      {
         //Parse SSH_FXP_ATTRS packet
         error = sftpClientParseFxpAttrs(context, header->payload, fragLen);
      }
      else
      {
         //Debug message
         TRACE_WARNING("Unknown SFTP packet type!\r\n");
         //Unknown packet type
         error = ERROR_INVALID_TYPE;
      }
   }
   else
   {
      //Malformed SFTP packet
      error = ERROR_INVALID_LENGTH;
   }

   //Return status code
   return error;
}


/**
 * @brief Determine whether a timeout error has occurred
 * @param[in] context Pointer to the SFTP client context
 * @return Error code
 **/

error_t sftpClientCheckTimeout(SftpClientContext *context)
{
   error_t error;
   systime_t time;

   //Get current time
   time = osGetSystemTime();

   //Check whether the timeout has elapsed
   if(timeCompare(time, context->timestamp + context->timeout) >= 0)
   {
      //Report a timeout error
      error = ERROR_TIMEOUT;
   }
   else
   {
#if (NET_RTOS_SUPPORT == ENABLED)
      //Successful operation
      error = NO_ERROR;
#else
      //The operation would block
      error = ERROR_WOULD_BLOCK;
#endif
   }

   //Return status code
   return error;
}


/**
 * @brief Format pathname
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path NULL-terminated string that contains the pathname
 * @param[out] p Output stream where to write the string
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sftpFormatPath(SftpClientContext *context, const char_t *path,
   uint8_t *p, size_t *written)
{
   size_t n;

   //Retrieve the full pathname
   sftpGetAbsolutePath(context, path, (char_t *) p + sizeof(uint32_t));

   //Get the length of the resulting string
   n = osStrlen((char_t *) p + sizeof(uint32_t));

   //A string is stored as a uint32 containing its length and zero or more
   //bytes that are the value of the string
   STORE32BE(n, p);

   //Total number of bytes that have been written
   *written = sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve the full pathname
 * @param[in] context Pointer to the SFTP client context
 * @param[in] path Absolute or relative path
 * @param[in] fullPath Output buffer where to store the resulting full pathname
 **/

void sftpGetAbsolutePath(SftpClientContext *context, const char_t *path,
   char_t *fullPath)
{
   //Relative or absolute path?
   if(pathIsRelative(path))
   {
      //Copy current working directory
      pathCopy(fullPath, context->currentDir, SFTP_CLIENT_MAX_PATH_LEN);
      //Append the relative path
      pathCombine(fullPath, path, SFTP_CLIENT_MAX_PATH_LEN);
   }
   else
   {
      //Copy absolute path
      pathCopy(fullPath, path, SFTP_CLIENT_MAX_PATH_LEN);
   }

   //Clean the resulting path
   pathCanonicalize(fullPath);
   pathRemoveSlash(fullPath);
}

#endif
