/**
 * @file ssh_request.c
 * @brief Global request and channel request handling
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
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_request.h"
#include "ssh/ssh_channel.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_GLOBAL_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] requestName NULL-terminated string containing the request name
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[in] wantReply This flag specifies whether a reply is expected
 * @return Error code
 **/

error_t sshSendGlobalRequest(SshConnection *connection,
   const char_t *requestName, const void *requestParams, bool_t wantReply)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_GLOBAL_REQUEST message
   error = sshFormatGlobalRequest(connection, requestName, requestParams,
      wantReply, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_GLOBAL_REQUEST message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Check whether a reply is expected from the other party
      if(wantReply)
      {
         //The recipient will respond with either SSH_MSG_REQUEST_SUCCESS or
         //SSH_MSG_REQUEST_FAILURE message
         connection->requestState = SSH_REQUEST_STATE_PENDING;
      }
      else
      {
         //The recipient will not respond to the request
         connection->requestState = SSH_REQUEST_STATE_IDLE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_REQUEST_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendRequestSuccess(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_REQUEST_SUCCESS message
   error = sshFormatRequestSuccess(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_REQUEST_SUCCESS message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_REQUEST_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendRequestFailure(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_REQUEST_FAILURE message
   error = sshFormatRequestFailure(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_REQUEST_FAILURE message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_REQUEST message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] requestType NULL-terminated string containing the request type
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[in] wantReply This flag specifies whether a reply is expected
 * @return Error code
 **/

error_t sshSendChannelRequest(SshChannel *channel, const char_t *requestType,
   const void *requestParams, bool_t wantReply)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_REQUEST message
   error = sshFormatChannelRequest(channel, requestType, requestParams,
      wantReply, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_REQUEST message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Check whether a reply is expected from the other party
      if(wantReply)
      {
         //The recipient will respond with either SSH_MSG_CHANNEL_SUCCESS or
         //SSH_MSG_CHANNEL_FAILURE message
         channel->requestState = SSH_REQUEST_STATE_PENDING;
      }
      else
      {
         //The recipient will not respond to the request
         channel->requestState = SSH_REQUEST_STATE_IDLE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_SUCCESS message
 * @param[in] channel Handle referencing an SSH channel
 * @return Error code
 **/

error_t sshSendChannelSuccess(SshChannel *channel)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_SUCCESS message
   error = sshFormatChannelSuccess(channel, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_SUCCESS message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //An SSH_MSG_CHANNEL_SUCCESS message has been successfully sent
      channel->channelSuccessSent = TRUE;
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_FAILURE message
 * @param[in] channel Handle referencing an SSH channel
 * @return Error code
 **/

error_t sshSendChannelFailure(SshChannel *channel)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_FAILURE message
   error = sshFormatChannelFailure(channel, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_FAILURE message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Format SSH_MSG_GLOBAL_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] requestName NULL-terminated string containing the request name
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[in] wantReply This flag specifies whether a reply is expected
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatGlobalRequest(SshConnection *connection,
   const char_t *requestName, const void *requestParams, bool_t wantReply,
   uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_GLOBAL_REQUEST;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set request name
   error = sshFormatString(requestName, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Set want_reply boolean
   p[0] = wantReply ? TRUE : FALSE;

   //Point to the next field
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Check request type
   if(!osStrcmp(requestName, "tcpip-forward"))
   {
      //Format "tcpip-forward" request specific data
      error = sshFormatTcpIpFwdParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestName, "cancel-tcpip-forward"))
   {
      //Format "cancel-tcpip-forward" request specific data
      error = sshFormatCancelTcpIpFwdParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestName, "elevation"))
   {
      //Format "elevation" request specific data
      error = sshFormatElevationParams(requestParams, p, &n);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_REQUEST;
   }

   //Check status code
   if(!error)
   {
      //Total length of the message
      *length += n;
   }

   //Return status code
   return error;
}


/**
 * @brief Format "tcpip-forward" global request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatTcpIpFwdParams(const SshTcpIpFwdParams *params,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the request specific data
   *written = 0;

   //The 'address to bind' field specifies the IP address on which connections
   //for forwarding are to be accepted
   error = sshFormatBinaryString(params->addrToBind.value,
      params->addrToBind.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The 'port number to bind' field specifies the port on which connections
   //for forwarding are to be accepted
   STORE32BE(params->portNumToBind, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "cancel-tcpip-forward" global request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatCancelTcpIpFwdParams(const SshCancelTcpIpFwdParams *params,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the request specific data
   *written = 0;

   //Set 'address to bind' field
   error = sshFormatBinaryString(params->addrToBind.value,
      params->addrToBind.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Set 'port number to bind' field
   STORE32BE(params->portNumToBind, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "elevation" global request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatElevationParams(const SshElevationParams *params,
   uint8_t *p, size_t *written)
{
   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //The server use the 'elevation performed' field to indicates to the client
   //whether elevation was done
   p[0] = params->elevationPerformed ? TRUE : FALSE;

   //Total number of bytes that have been written
   *written = sizeof(uint8_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_REQUEST_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatRequestSuccess(SshConnection *connection, uint8_t *p,
   size_t *length)
{
   //Set message type
   p[0] = SSH_MSG_REQUEST_SUCCESS;

   //Usually, the response specific data is non-existent (refer to RFC 4254,
   //section 4)
   *length = sizeof(uint8_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_REQUEST_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatRequestFailure(SshConnection *connection, uint8_t *p,
   size_t *length)
{
   //Set message type
   p[0] = SSH_MSG_REQUEST_FAILURE;

   //Total length of the message
   *length = sizeof(uint8_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_REQUEST message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] requestType NULL-terminated string containing the request type
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[in] wantReply This flag specifies whether a reply is expected
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelRequest(SshChannel *channel, const char_t *requestType,
   const void *requestParams, bool_t wantReply, uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_REQUEST;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel number
   STORE32BE(channel->remoteChannelNum, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set request type
   error = sshFormatString(requestType, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Set want_reply boolean
   p[0] = wantReply ? TRUE : FALSE;

   //Point to the next field
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Check request type
   if(!osStrcmp(requestType, "pty-req"))
   {
      //Format "pty-req" request specific data
      error = sshFormatPtyReqParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "shell"))
   {
      //The "shell" request does not contain type-specific data
      n = 0;
   }
   else if(!osStrcmp(requestType, "exec"))
   {
      //Format "exec" request specific data
      error = sshFormatExecParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "subsystem"))
   {
      //Format "subsystem" request specific data
      error = sshFormatSubsystemParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "window-change"))
   {
      //Format "window-change" request specific data
      error = sshFormatWindowChangeParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "signal"))
   {
      //Format "signal" request specific data
      error = sshFormatSignalParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "exit-status"))
   {
      //Format "exit-status" request specific data
      error = sshFormatExitStatusParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "break"))
   {
      //Format "break" request specific data
      error = sshFormatBreakParams(requestParams, p, &n);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_REQUEST;
   }

   //Check status code
   if(!error)
   {
      //Total length of the message
      *length += n;
   }

   //Return status code
   return error;
}


/**
 * @brief Format "pty-req" channel request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatPtyReqParams(const SshPtyReqParams *params,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the request specific data
   *written = 0;

   //Set terminal environment variables
   error = sshFormatBinaryString(params->termEnvVar.value,
      params->termEnvVar.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Set terminal width (in characters)
   STORE32BE(params->termWidthChars, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal height (in rows)
   STORE32BE(params->termHeightRows, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal width (in pixels)
   STORE32BE(params->termWidthPixels, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal height (in pixels)
   STORE32BE(params->termHeightPixels, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal environment variables
   error = sshFormatBinaryString(params->termModes.value,
      params->termModes.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "exec" channel request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatExecParams(const SshExecParams *params,
   uint8_t *p, size_t *written)
{
   error_t error;

   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set command line
   error = sshFormatBinaryString(params->command.value,
      params->command.length, p, written);

   //Return status code
   return error;
}


/**
 * @brief Format "subsystem" channel request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatSubsystemParams(const SshSubsystemParams *params,
   uint8_t *p, size_t *written)
{
   error_t error;

   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set subsystem name
   error = sshFormatBinaryString(params->subsystemName.value,
      params->subsystemName.length, p, written);

   //Return status code
   return error;
}


/**
 * @brief Format "window-change" channel request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatWindowChangeParams(const SshWindowChangeParams *params,
   uint8_t *p, size_t *written)
{
   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the request specific data
   *written = 0;

   //Set terminal width (in characters)
   STORE32BE(params->termWidthChars, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal height (in rows)
   STORE32BE(params->termHeightRows, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal width (in pixels)
   STORE32BE(params->termWidthPixels, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal height (in pixels)
   STORE32BE(params->termHeightPixels, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "signal" channel request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatSignalParams(const SshSignalParams *params,
   uint8_t *p, size_t *written)
{
   error_t error;

   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set signal name
   error = sshFormatBinaryString(params->signalName.value,
      params->signalName.length, p, written);

   //Return status code
   return error;
}


/**
 * @brief Format "exit-status" channel request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatExitStatusParams(const SshExitStatusParams *params,
   uint8_t *p, size_t *written)
{
   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set exit status
   STORE32BE(params->exitStatus, p);

   //Total number of bytes that have been written
   *written = sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "break" channel request parameters
 * @param[in] params Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatBreakParams(const SshBreakParams *params,
   uint8_t *p, size_t *written)
{
   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set break length (in milliseconds)
   STORE32BE(params->breakLen, p);

   //Total number of bytes that have been written
   *written = sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_SUCCESS message
 * @param[in] channel Handle referencing an SSH channel
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelSuccess(SshChannel *channel, uint8_t *p,
   size_t *length)
{
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_SUCCESS;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel
   STORE32BE(channel->remoteChannelNum, p);

   //Total length of the message
   *length += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_FAILURE message
 * @param[in] channel Handle referencing an SSH channel
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelFailure(SshChannel *channel, uint8_t *p,
   size_t *length)
{
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_FAILURE;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel
   STORE32BE(channel->remoteChannelNum, p);

   //Total length of the message
   *length += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_GLOBAL_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseGlobalRequest(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   uint_t i;
   const uint8_t *p;
   SshString requestName;
   SshBoolean wantReply;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Debug message
   TRACE_INFO("SSH_MSG_GLOBAL_REQUEST message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode the request name
   error = sshParseString(p, length, &requestName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + requestName.length;
   length -= sizeof(uint32_t) + requestName.length;

   //Malformed message?
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Decode want_reply field
   wantReply = p[0];

   //Point to the next field
   p += sizeof(uint8_t);
   length -= sizeof(uint8_t);

   //Initialize status code
   error = ERROR_UNKNOWN_REQUEST;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Multiple callbacks may be registered
   for(i = 0; i < SSH_MAX_GLOBAL_REQ_CALLBACKS &&
      error == ERROR_UNKNOWN_REQUEST; i++)
   {
      //Valid callback function?
      if(context->globalReqCallback[i] != NULL)
      {
         //Process global request
         error = context->globalReqCallback[i](connection, &requestName, p,
            length, context->globalReqParam[i]);
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Check the value of the want_reply boolean
   if(!wantReply)
   {
      //If want_reply is FALSE, no response will be sent to the request
      error = NO_ERROR;
   }
   else
   {
      //Otherwise, the recipient responds with either SSH_MSG_REQUEST_SUCCESS
      //or SSH_MSG_REQUEST_FAILURE
      if(!error)
      {
         //Send an SSH_MSG_REQUEST_SUCCESS response
         error = sshSendRequestSuccess(connection);
      }
      else
      {
         //If the recipient does not recognize or support the request, it simply
         //responds with SSH_MSG_REQUEST_FAILURE (refer to RFC 4254, section 4)
         error = sshSendRequestFailure(connection);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse "tcpip-forward" global request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseTcpIpFwdParams(const uint8_t *p, size_t length,
   SshTcpIpFwdParams *params)
{
   error_t error;

   //The 'address to bind' field specifies the IP address on which connections
   //for forwarding are to be accepted
   error = sshParseString(p, length, &params->addrToBind);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + params->addrToBind.length;
   length -= sizeof(uint32_t) + params->addrToBind.length;

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //The 'port number to bind' field specifies the port on which connections
   //for forwarding are to be accepted
   params->portNumToBind = LOAD32BE(p);

   //Invalid port number?
   if(params->portNumToBind > SSH_MAX_PORT_NUM)
      return ERROR_INVALID_PORT;

   //Debug message
   TRACE_INFO("  Address To Bind = %s\r\n", params->addrToBind.value);
   TRACE_INFO("  Port Number To Bind = %" PRIu32 "\r\n", params->portNumToBind);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "cancel-tcpip-forward" global request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseCancelTcpIpFwdParams(const uint8_t *p, size_t length,
   SshCancelTcpIpFwdParams *params)
{
   error_t error;

   //Parse 'address to bind' field
   error = sshParseString(p, length, &params->addrToBind);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + params->addrToBind.length;
   length -= sizeof(uint32_t) + params->addrToBind.length;

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Parse 'port number to bind' field
   params->portNumToBind = LOAD32BE(p);

   //Invalid port number?
   if(params->portNumToBind > SSH_MAX_PORT_NUM)
      return ERROR_INVALID_PORT;

   //Debug message
   TRACE_INFO("  Address To Bind = %s\r\n", params->addrToBind.value);
   TRACE_INFO("  Port Number To Bind = %" PRIu32 "\r\n", params->portNumToBind);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "elevation" global request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseElevationParams(const uint8_t *p, size_t length,
   SshElevationParams *params)
{
   //Malformed message?
   if(length != sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //The server use the 'elevation performed' field to indicates to the client
   //whether elevation was done
   params->elevationPerformed = p[0];

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_REQUEST_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseRequestSuccess(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   //Debug message
   TRACE_INFO("SSH_MSG_REQUEST_SUCCESS message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Check global request state
   if(connection->requestState != SSH_REQUEST_STATE_PENDING)
      return ERROR_UNEXPECTED_MESSAGE;

   //Update global request state
   connection->requestState = SSH_REQUEST_STATE_SUCCESS;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_REQUEST_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseRequestFailure(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   //Debug message
   TRACE_INFO("SSH_MSG_REQUEST_FAILURE message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Malformed message?
   if(length != sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Check global request state
   if(connection->requestState != SSH_REQUEST_STATE_PENDING)
      return ERROR_UNEXPECTED_MESSAGE;

   //Update global request state
   connection->requestState = SSH_REQUEST_STATE_FAILURE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_CHANNEL_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelRequest(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   uint_t i;
   const uint8_t *p;
   uint32_t recipientChannel;
   SshString requestType;
   SshBoolean wantReply;
   SshChannel *channel;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_REQUEST message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get recipient channel number
   recipientChannel = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Decode the request type
   error = sshParseString(p, length, &requestType);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + requestType.length;
   length -= sizeof(uint32_t) + requestType.length;

   //Malformed message?
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Decode want_reply field
   wantReply = p[0];

   //Point to the next field
   p += sizeof(uint8_t);
   length -= sizeof(uint8_t);

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->closeReceived)
      {
         //Initialize status code
         error = ERROR_UNKNOWN_REQUEST;

         //Multiple callbacks may be registered
         for(i = 0; i < SSH_MAX_CHANNEL_REQ_CALLBACKS &&
            error == ERROR_UNKNOWN_REQUEST; i++)
         {
            //Valid callback function?
            if(context->channelReqCallback[i] != NULL)
            {
               //Process channel request
               error = context->channelReqCallback[i](channel, &requestType, p,
                  length, context->channelReqParam[i]);
            }
         }

         //Check the value of the want_reply boolean
         if(!wantReply || channel->closeSent)
         {
            //If want_reply is FALSE, no response will be sent to the request
            error = NO_ERROR;
         }
         else
         {
            //Otherwise, the recipient responds with either SSH_MSG_CHANNEL_SUCCESS,
            //SSH_MSG_CHANNEL_FAILURE, or request-specific continuation messages
            if(!error)
            {
               //Send an SSH_MSG_CHANNEL_SUCCESS response
               error = sshSendChannelSuccess(channel);
            }
            else
            {
               //If the request is not recognized or is not supported for the
               //channel, SSH_MSG_CHANNEL_FAILURE is returned (refer to RFC 4254,
               //section 5.4)
               error = sshSendChannelFailure(channel);
            }
         }
      }
      else
      {
         //Invalid channel state
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //The recipient channel number is not valid
      error = ERROR_INVALID_CHANNEL;
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Parse "pty-req" channel request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParsePtyReqParams(const uint8_t *p, size_t length,
   SshPtyReqParams *params)
{
   error_t error;

   //Parse the terminal environment variable value
   error = sshParseString(p, length, &params->termEnvVar);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + params->termEnvVar.length;
   length -= sizeof(uint32_t) + params->termEnvVar.length;

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal width (in characters)
   params->termWidthChars = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal height (in rows)
   params->termHeightRows = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal width (in pixels)
   params->termWidthPixels = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal height (in pixels)
   params->termHeightPixels = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Parse the encoded terminal modes
   error = sshParseBinaryString(p, length, &params->termModes);
   //Any error to report?
   if(error)
      return error;

   //Malformed request?
   if(length != (sizeof(uint32_t) + params->termModes.length))
      return ERROR_INVALID_MESSAGE;

   //Debug message
   TRACE_INFO("  Term Width (chars) = %" PRIu32 "\r\n", params->termWidthChars);
   TRACE_INFO("  Term Height (rows) = %" PRIu32 "\r\n", params->termHeightRows);
   TRACE_INFO("  Term Width (pixels) = %" PRIu32 "\r\n", params->termWidthPixels);
   TRACE_INFO("  Term Height (pixels) = %" PRIu32 "\r\n", params->termHeightPixels);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "exec" channel request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseExecParams(const uint8_t *p, size_t length,
   SshExecParams *params)
{
   error_t error;

   //Parse command
   error = sshParseString(p, length, &params->command);
   //Any error to report?
   if(error)
      return error;

   //Malformed request?
   if(length != (sizeof(uint32_t) + params->command.length))
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve the specified argument from an "exec" request
 * @param[in] params Pointer to the "exec" request parameters
 * @param[in] index Zero-based index of the argument
 * @param[out] arg Value of the argument
 * @return TRUE if the index is valid, else FALSE
 **/

bool_t sshGetExecArg(const SshExecParams *params, uint_t index, SshString *arg)
{
   size_t i;
   size_t j;
   uint_t n;

   //Initialize variables
   i = 0;
   n = 0;

   //Parse the command line
   for(j = 0; j <= params->command.length; j++)
   {
      //Arguments are separated by whitespace characters
      if(j == params->command.length || osIsblank(params->command.value[j]))
      {
         //Non-empty string?
         if(i < j)
         {
            //Matching index?
            if(n++ == index)
            {
               //Point to first character of the argument
               arg->value = params->command.value + i;
               //Determine the length of the argument
               arg->length = j - i;

               //The index is valid
               return TRUE;
            }
         }

         //Point to the next argument of the list
         i = j + 1;
      }
   }

   //The index is out of range
   return FALSE;
}


/**
 * @brief Parse "subsystem" channel request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseSubsystemParams(const uint8_t *p, size_t length,
   SshSubsystemParams *params)
{
   error_t error;

   //Parse subsystem name
   error = sshParseString(p, length, &params->subsystemName);
   //Any error to report?
   if(error)
      return error;

   //Malformed request?
   if(length != (sizeof(uint32_t) + params->subsystemName.length))
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "window-change" channel request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseWindowChangeParams(const uint8_t *p, size_t length,
   SshWindowChangeParams *params)
{
   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal width (in characters)
   params->termWidthChars = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal height (in rows)
   params->termHeightRows = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal width (in pixels)
   params->termWidthPixels = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal height (in pixels)
   params->termHeightPixels = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Term Width (chars) = %" PRIu32 "\r\n", params->termWidthChars);
   TRACE_INFO("  Term Height (rows) = %" PRIu32 "\r\n", params->termHeightRows);
   TRACE_INFO("  Term Width (pixels) = %" PRIu32 "\r\n", params->termWidthPixels);
   TRACE_INFO("  Term Height (pixels) = %" PRIu32 "\r\n", params->termHeightPixels);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "signal" channel request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseSignalParams(const uint8_t *p, size_t length,
   SshSignalParams *params)
{
   error_t error;

   //Parse signal name
   error = sshParseString(p, length, &params->signalName);
   //Any error to report?
   if(error)
      return error;

   //Malformed request?
   if(length != (sizeof(uint32_t) + params->signalName.length))
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "exit-status" channel request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseExitStatusParams(const uint8_t *p, size_t length,
   SshExitStatusParams *params)
{
   //Malformed request?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get exit status
   params->exitStatus = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Exit status = %" PRIu32 "\r\n", params->exitStatus);

   //Successful processing
   return NO_ERROR;
}

/**
 * @brief Parse "break" channel request parameters
 * @param[in] p Pointer to the request specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseBreakParams(const uint8_t *p, size_t length,
   SshBreakParams *params)
{
   //Malformed request?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get break length (in milliseconds)
   params->breakLen = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Break Length (ms) = %" PRIu32 "\r\n", params->breakLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_CHANNEL_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelSuccess(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   SshChannel *channel;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_SUCCESS message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Decode the recipient channel
   recipientChannel = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Recipient Channel = %" PRIu32 "\r\n", recipientChannel);

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&connection->context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->closeReceived)
      {
         //Check channel request state
         if(channel->requestState == SSH_REQUEST_STATE_PENDING)
         {
            //Update channel request state
            channel->requestState = SSH_REQUEST_STATE_SUCCESS;

            //Successfull processing
            error = NO_ERROR;
         }
         else
         {
            //Invalid channel request state
            error = ERROR_UNEXPECTED_MESSAGE;
         }
      }
      else
      {
         //Invalid channel state
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //The recipient channel number is not valid
      error = ERROR_INVALID_CHANNEL;
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&connection->context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_MSG_CHANNEL_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelFailure(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   SshChannel *channel;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_FAILURE message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Decode the recipient channel
   recipientChannel = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Recipient Channel = %" PRIu32 "\r\n", recipientChannel);

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&connection->context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->closeReceived)
      {
         //Check channel request state
         if(channel->requestState == SSH_REQUEST_STATE_PENDING)
         {
            //Update channel request state
            channel->requestState = SSH_REQUEST_STATE_FAILURE;

            //Successfull processing
            error = NO_ERROR;
         }
         else
         {
            //Invalid channel request state
            error = ERROR_UNEXPECTED_MESSAGE;
         }
      }
      else
      {
         //Invalid channel state
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //The recipient channel number is not valid
      error = ERROR_INVALID_CHANNEL;
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&connection->context->mutex);

   //Return status code
   return error;
}

#endif
