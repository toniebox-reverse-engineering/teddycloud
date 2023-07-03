/**
 * @file ssh_transport.c
 * @brief SSH transport layer protocol
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
#include "ssh/ssh_transport.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Send identification string
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendIdString(SshConnection *connection)
{
   size_t length;

   //Check whether SSH operates as a client or a server
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Format V_C (client's identification string)
      length = osSprintf(connection->clientId, "SSH-2.0-CycloneSSH_%s",
         CYCLONE_SSH_VERSION_STRING);

      //Copy the resulting string
      osMemcpy(connection->buffer, connection->clientId, length);
   }
   else
   {
      //Format V_S (server's identification string)
      length = osSprintf(connection->serverId, "SSH-2.0-CycloneSSH_%s",
         CYCLONE_SSH_VERSION_STRING);

      //Copy the resulting string
      osMemcpy(connection->buffer, connection->serverId, length);
   }

   //The identification string must be terminated by a single CR and a
   //single LF character (refer to RFC 4253, section 4.2)
   connection->buffer[length++] = '\r';
   connection->buffer[length++] = '\n';

   //Save the length of the identification string
   connection->txBufferLen = length;
   connection->txBufferPos = 0;

   //Check whether SSH operates as a client or a server
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Debug message
      TRACE_INFO("Sending client ID string (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_INFO("  %s\r\n", connection->clientId);

      //Wait for the server's identification string
      connection->state = SSH_CONN_STATE_SERVER_ID;
   }
   else
   {
      //Debug message
      TRACE_INFO("Sending server ID string (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_INFO("  %s\r\n", connection->serverId);

      //Wait for the client's identification string
      connection->state = SSH_CONN_STATE_CLIENT_ID;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Send SSH_MSG_SERVICE_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendServiceRequest(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_SERVICE_REQUEST message
   error = sshFormatServiceRequest(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_SERVICE_REQUEST message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
#if (SSH_EXT_INFO_SUPPORT == ENABLED)
      //If the client offers "ext-info-c", it must be prepared to accept an
      //SSH_MSG_EXT_INFO message from the server
      connection->state = SSH_CONN_STATE_SERVER_EXT_INFO_1;
#else
      //If the server supports the service (and permits the client to use
      //it), it must respond with an SSH_MSG_SERVICE_ACCEPT message
      connection->state = SSH_CONN_STATE_SERVICE_ACCEPT;
#endif
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_SERVICE_ACCEPT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] serviceName NULL-terminating string that contains the service name
 * @return Error code
 **/

error_t sshSendServiceAccept(SshConnection *connection,
   const char_t *serviceName)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_SERVICE_ACCEPT message
   error = sshFormatServiceAccept(connection, serviceName, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_SERVICE_ACCEPT message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The authentication protocol is intended to be run over the SSH transport
      //layer protocol (refer to RFC 4252, section 1)
      connection->state = SSH_CONN_STATE_USER_AUTH_REQUEST;
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_DISCONNECT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] reasonCode Reason in a machine-readable format
 * @param[in] description Specific explanation in a human-readable form
 * @return Error code
 **/

error_t sshSendDisconnect(SshConnection *connection,
   uint32_t reasonCode, const char_t *description)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_DISCONNECT message
   error = sshFormatDisconnect(connection, reasonCode, description, message,
      &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_DISCONNECT message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //An SSH_MSG_DISCONNECT message has been successfully sent
      connection->disconnectSent = TRUE;

      //This message causes immediate termination of the connection
      connection->state = SSH_CONN_STATE_DISCONNECT;
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_UNIMPLEMENTED message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] packetSeqNum Packet sequence number of rejected message
 * @return Error code
 **/

error_t sshSendUnimplemented(SshConnection *connection,
   const uint8_t *packetSeqNum)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_UNIMPLEMENTED message
   error = sshFormatUnimplemented(connection, packetSeqNum, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_UNIMPLEMENTED message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Format SSH_MSG_SERVICE_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatServiceRequest(SshConnection *connection, uint8_t *p,
   size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_SERVICE_REQUEST;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Copy service name
   error = sshFormatString("ssh-userauth", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   *length += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_SERVICE_ACCEPT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] serviceName NULL-terminating string that contains the service name
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatServiceAccept(SshConnection *connection,
   const char_t *serviceName, uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_SERVICE_ACCEPT;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Copy service name
   error = sshFormatString(serviceName, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   *length += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_DISCONNECT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] reasonCode Reason in a machine-readable format
 * @param[in] description Specific explanation in a human-readable form
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatDisconnect(SshConnection *connection, uint32_t reasonCode,
   const char_t *description, uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_DISCONNECT;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Copy the reason code
   STORE32BE(reasonCode, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Copy description string
   error = sshFormatString(description, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Format language tag
   error = sshFormatString("en", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total length of the message
   *length += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_UNIMPLEMENTED message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] packetSeqNum Packet sequence number of rejected message
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatUnimplemented(SshConnection *connection,
   const uint8_t *packetSeqNum, uint8_t *p, size_t *length)
{
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_UNIMPLEMENTED;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Copy the packet sequence number of the rejected message
   osMemcpy(p, packetSeqNum, sizeof(uint32_t));

   //Total length of the message
   *length += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse identification string
 * @param[in] connection Pointer to the SSH connection
 * @param[in] id Pointer to the identification string
 * @param[in] length Length of the identification string
 * @return Error code
 **/

error_t sshParseIdString(SshConnection *connection, const uint8_t *id,
   size_t length)
{
   //Check the length of the client's identification string
   if(length < 2)
      return ERROR_WRONG_IDENTIFIER;

   //The identification string must be terminated by a single CR and a single
   //LF character (refer to RFC 4253, section 4.2). In practice, some SSH 2.0
   //implementations terminate the string with a LF character only
   if(id[length - 1] != '\n')
      return ERROR_WRONG_IDENTIFIER;

   //Trim the trailing LF character from the string
   length--;

   //Trim the trailing CR character from the string
   if(id[length - 1] == '\r')
   {
      length--;
   }

   //Sanity check
   if(length > SSH_MAX_ID_LEN)
      return ERROR_WRONG_IDENTIFIER;

   //Check whether SSH operates as a client or a server
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Copy the server's identification string
      osMemcpy(connection->serverId, id, length);
      //Properly terminate the string with a NULL character
      connection->serverId[length] = '\0';

      //Debug message
      TRACE_INFO("Server ID string received (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_INFO("  %s\r\n", connection->serverId);

      //Clients using protocol 2.0 must be able to identify protocol version
      //"1.99" as identical to "2.0" (refer to RFC 4253, section 5.1)
      if(osStrncmp(connection->serverId, "SSH-2.0-", 8) &&
         osStrncmp(connection->serverId, "SSH-1.99-", 9))
      {
         //The version advertised by the server is not supported
         return ERROR_WRONG_IDENTIFIER;
      }

      //Key exchange begins by each side sending a KEXINIT message
      connection->state = SSH_CONN_STATE_CLIENT_KEX_INIT;
   }
   else
   {
      //Copy the client's identification string
      osMemcpy(connection->clientId, id, length);
      //Properly terminate the string with a NULL character
      connection->clientId[length] = '\0';

      //Debug message
      TRACE_INFO("Client ID string received (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_INFO("  %s\r\n", connection->clientId);

      //Check protocol version
      if(osStrncmp(connection->clientId, "SSH-2.0-", 8) &&
         osStrncmp(connection->clientId, "SSH-1.99-", 9))
      {
         //The version advertised by the client is not supported
         return ERROR_WRONG_IDENTIFIER;
      }

      //Key exchange begins by each side sending a KEXINIT message
      connection->state = SSH_CONN_STATE_SERVER_KEX_INIT;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_SERVICE_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseServiceRequest(SshConnection *connection, const uint8_t *message,
   size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshString serviceName;

   //Debug message
   TRACE_INFO("SSH_MSG_SERVICE_REQUEST message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_SERVER)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_CLIENT_EXT_INFO &&
      connection->state != SSH_CONN_STATE_SERVICE_REQUEST)
   {
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode the service name
   error = sshParseString(p, length, &serviceName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + serviceName.length;
   length -= sizeof(uint32_t) + serviceName.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //The service is identified by a name
   if(sshCompareString(&serviceName, "ssh-userauth"))
   {
      //If the server supports the service (and permits the client to use it),
      //it must respond with an SSH_MSG_SERVICE_ACCEPT message
      error = sshSendServiceAccept(connection, "ssh-userauth");
   }
   else
   {
      //If the server rejects the service request, it should send an
      //appropriate SSH_MSG_DISCONNECT message and must disconnect
      error = sshSendDisconnect(connection, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
         "Service not available");
   }

   //Return status code
   return error;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse SSH_MSG_SERVICE_ACCEPT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseServiceAccept(SshConnection *connection, const uint8_t *message,
   size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshString serviceName;

   //Debug message
   TRACE_INFO("SSH_MSG_SERVICE_ACCEPT message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_SERVER_EXT_INFO_1 &&
      connection->state != SSH_CONN_STATE_SERVICE_ACCEPT)
   {
      return ERROR_UNEXPECTED_MESSAGE;
   }

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode service name
   error = sshParseString(p, length, &serviceName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + serviceName.length;
   length -= sizeof(uint32_t) + serviceName.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Check service name
   if(!sshCompareString(&serviceName, "ssh-userauth"))
      return ERROR_INVALID_MESSAGE;

   //The authentication protocol is intended to be run over the SSH transport
   //layer protocol (refer to RFC 4252, section 1)
   connection->state = SSH_CONN_STATE_USER_AUTH_REQUEST;

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse SSH_MSG_IGNORE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseIgnore(SshConnection *connection, const uint8_t *message,
   size_t length)
{
   error_t error;
   const uint8_t *p;
   SshString data;

   //Debug message
   TRACE_DEBUG("SSH_MSG_IGNORE message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode data field
   error = sshParseString(p, length, &data);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + data.length;
   length -= sizeof(uint32_t) + data.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //All implementations must understand (and ignore) this message at any time
   //after receiving the identification string. This message can be used as an
   //additional protection measure against advanced traffic analysis techniques
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_DEBUG message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseDebug(SshConnection *connection, const uint8_t *message,
   size_t length)
{
   error_t error;
   const uint8_t *p;
   SshBoolean alwaysDisplay;
   SshString debugMessage;
   SshString languageTag;

   //Debug message
   TRACE_INFO("SSH_MSG_DEBUG message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Decode always_display flag
   alwaysDisplay = p[0];
   //The value of this field is not used
   (void) alwaysDisplay;

   //Point to the next field
   p += sizeof(uint8_t);
   length -= sizeof(uint8_t);

   //Decode message
   error = sshParseString(p, length, &debugMessage);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + debugMessage.length;
   length -= sizeof(uint32_t) + debugMessage.length;

   //Decode language tag
   error = sshParseString(p, length, &languageTag);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + languageTag.length;
   length -= sizeof(uint32_t) + languageTag.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //All implementations must understand this message, but they are allowed
   //to ignore it. This message is used to transmit information that may help
   //debugging
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_DISCONNECT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseDisconnect(SshConnection *connection, const uint8_t *message,
   size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t reasonCode;
   SshString description;
   SshString languageTag;

   //Debug message
   TRACE_INFO("SSH_MSG_DISCONNECT message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

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

   //Get reason code
   reasonCode = LOAD32BE(p);
   //The value of this field is not used
   (void) reasonCode;

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Decode description string
   error = sshParseString(p, length, &description);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + description.length;
   length -= sizeof(uint32_t) + description.length;

   //Decode language tag
   error = sshParseString(p, length, &languageTag);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + languageTag.length;
   length -= sizeof(uint32_t) + languageTag.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //An SSH_MSG_DISCONNECT message has been successfully received
   connection->disconnectReceived = TRUE;

   //This message causes immediate termination of the connection
   connection->state = SSH_CONN_STATE_DISCONNECT;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_UNIMPLEMENTED message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseUnimplemented(SshConnection *connection, const uint8_t *message,
   size_t length)
{
   const uint8_t *p;
   uint32_t packetSeqNum;

   //Debug message
   TRACE_INFO("SSH_MSG_UNIMPLEMENTED message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

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

   //Get the packet sequence number of rejected message
   packetSeqNum = LOAD32BE(p);
   //The value of this field is not used
   (void) packetSeqNum;

   //Ignore SSH_MSG_UNIMPLEMENTED messages
   return NO_ERROR;
}


/**
 * @brief Parse unrecognized message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseUnrecognized(SshConnection *connection, const uint8_t *message,
   size_t length)
{
   error_t error;

   //Debug message
   TRACE_INFO("Unrecognized message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //An implementation must respond to all unrecognized messages with an
   //SSH_MSG_UNIMPLEMENTED message in the order in which the messages were
   //received (refer to RFC 4253, section 11.4)
   error = sshSendUnimplemented(connection, connection->decryptionEngine.seqNum);

   //Such messages must be otherwise ignored
   return error;
}

#endif
