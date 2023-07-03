/**
 * @file ssh_connection.c
 * @brief SSH connection protocol
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
#include "ssh/ssh_connection.h"
#include "ssh/ssh_channel.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_CHANNEL_OPEN message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] channelType NULL-terminated string containing the channel type
 * @param[in] channelParams Pointer to the channel specific parameters
 * @return Error code
 **/

error_t sshSendChannelOpen(SshChannel *channel, const char_t *channelType,
   const void *channelParams)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_OPEN message
   error = sshFormatChannelOpen(channel, channelType, channelParams, message,
      &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_OPEN message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_OPEN_CONFIRMATION message
 * @param[in] channel Handle referencing an SSH channel
 * @return Error code
 **/

error_t sshSendChannelOpenConfirmation(SshChannel *channel)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_OPEN_CONFIRMATION message
   error = sshFormatChannelOpenConfirmation(channel, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_OPEN_CONFIRMATION message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Update the state of the channel
      channel->state = SSH_CHANNEL_STATE_OPEN;
   }

   //Return status code
   return error;
}


/**
 * @brief Format SSH_MSG_CHANNEL_OPEN_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] recipientChannel Channel number given in the original open request
 * @param[in] reasonCode Reason code value
 * @param[in] description NULL-terminating description string
 * @return Error code
 **/

error_t sshSendChannelOpenFailure(SshConnection *connection,
   uint32_t recipientChannel, uint32_t reasonCode, const char_t *description)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_OPEN_FAILURE message
   error = sshFormatChannelOpenFailure(connection, recipientChannel, reasonCode,
      description, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_OPEN_FAILURE message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_WINDOW_ADJUST message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] windowSizeInc Number of bytes to add
 * @return Error code
 **/

error_t sshSendChannelWindowAdjust(SshChannel *channel, size_t windowSizeInc)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_WINDOW_ADJUST message
   error = sshFormatChannelWindowAdjust(channel, windowSizeInc, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("Sending SSH_MSG_CHANNEL_WINDOW_ADJUST message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_DATA message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] dataLen Length of the payload data, in bytes
 * @return Error code
 **/

error_t sshSendChannelData(SshChannel *channel, size_t dataLen)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_DATA message
   error = sshFormatChannelData(channel, dataLen, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_DEBUG("Sending SSH_MSG_CHANNEL_DATA message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_EOF message
 * @param[in] channel Handle referencing an SSH channel
 * @return Error code
 **/

error_t sshSendChannelEof(SshChannel *channel)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_EOF message
   error = sshFormatChannelEof(channel, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_EOF message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The channel remains open after this message, and more data may still
      //be sent in the other direction (refer to RFC 4254, section 5.3)
      channel->eofSent = TRUE;
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_CLOSE message
 * @param[in] channel Handle referencing an SSH channel
 * @return Error code
 **/

error_t sshSendChannelClose(SshChannel *channel)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_CLOSE message
   error = sshFormatChannelClose(channel, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_CLOSE message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //An SSH_MSG_CHANNEL_CLOSE message has been successfully sent
      channel->closeSent = TRUE;

      //Check whether an SSH_MSG_CHANNEL_CLOSE message has been received
      if(channel->closeReceived)
      {
         //The channel is considered closed for a party when it has both sent
         //and received SSH_MSG_CHANNEL_CLOSE (refer to RFC 4254, section 5.3)
         channel->state = SSH_CHANNEL_STATE_CLOSED;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format SSH_MSG_CHANNEL_OPEN message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] channelType NULL-terminated string containing the channel type
 * @param[in] channelParams Pointer to the channel specific parameters
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelOpen(SshChannel *channel, const char_t *channelType,
   const void *channelParams, uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_OPEN;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set channel type
   error = sshFormatString(channelType, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Set channel number
   STORE32BE(channel->localChannelNum, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set initial window size
   STORE32BE(SSH_CHANNEL_BUFFER_SIZE, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set maximum packet size
   STORE32BE(SSH_DEFAULT_MAX_PACKET_SIZE, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Check channel type
   if(!osStrcmp(channelType, "session"))
   {
      //A "session" channel does not specify any type-specific data
      n = 0;
   }
   else if(!osStrcmp(channelType, "forwarded-tcpip"))
   {
      //Format "forwarded-tcpip" channel specific data
      error = sshFormatForwardedTcpIpParams(channelParams, p, &n);
   }
   else if(!osStrcmp(channelType, "direct-tcpip"))
   {
      //Format "direct-tcpip" channel specific data
      error = sshFormatDirectTcpIpParams(channelParams, p, &n);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_TYPE;
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
 * @brief Format "forwarded-tcpip" channel parameters
 * @param[in] params Pointer to the channel specific parameters
 * @param[out] p Output stream where to write the channel specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatForwardedTcpIpParams(const SshForwardedTcpIpParams *params,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the channel specific data
   *written = 0;

   //Set 'address that was connected' field
   error = sshFormatBinaryString(params->addrConnected.value,
      params->addrConnected.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Set 'port that was connected' field
   STORE32BE(params->portConnected, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set 'originator IP address' field
   error = sshFormatBinaryString(params->originIpAddr.value,
      params->originIpAddr.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Set 'originator port' field
   STORE32BE(params->originPort, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "direct-tcpip" channel parameters
 * @param[in] params Pointer to the channel specific parameters
 * @param[out] p Output stream where to write the channel specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatDirectTcpIpParams(const SshDirectTcpIpParams *params,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the channel specific data
   *written = 0;

   //The 'host to connect' field specifies the TCP/IP host where the recipient
   //should connect the channel
   error = sshFormatBinaryString(params->hostToConnect.value,
      params->hostToConnect.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The 'port to connect' field specifies the port where the recipient should
   //connect the channel
   STORE32BE(params->portToConnect, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //The 'originator IP address' field is the numeric IP address of the machine
   //from where the connection request originates
   error = sshFormatBinaryString(params->originIpAddr.value,
      params->originIpAddr.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The 'originator port' field is the port on the host from where the
   //connection originated
   STORE32BE(params->originPort, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_OPEN_CONFIRMATION message
 * @param[in] channel Handle referencing an SSH channel
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelOpenConfirmation(SshChannel *channel, uint8_t *p,
   size_t *length)
{
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel
   STORE32BE(channel->remoteChannelNum, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set sender channel
   STORE32BE(channel->localChannelNum, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set initial window size
   STORE32BE(SSH_CHANNEL_BUFFER_SIZE, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set maximum packet size
   STORE32BE(SSH_DEFAULT_MAX_PACKET_SIZE, p);

   //Total length of the message
   *length += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_OPEN_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] recipientChannel Channel number given in the original open request
 * @param[in] reasonCode Reason code value
 * @param[in] description NULL-terminating description string
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelOpenFailure(SshConnection *connection,
   uint32_t recipientChannel, uint32_t reasonCode, const char_t *description,
   uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_OPEN_FAILURE;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel
   STORE32BE(recipientChannel, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set reason code
   STORE32BE(reasonCode, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set description string
   error = sshFormatString(description, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Set language tag
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
 * @brief Format SSH_MSG_CHANNEL_WINDOW_ADJUST message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] windowSizeInc Number of bytes to add
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelWindowAdjust(SshChannel *channel, size_t windowSizeInc,
   uint8_t *p, size_t *length)
{
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel
   STORE32BE(channel->remoteChannelNum, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set the number of bytes to add
   STORE32BE(windowSizeInc, p);

   //Total length of the message
   *length += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_DATA message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] dataLen Length of the payload data, in bytes
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelData(SshChannel *channel, size_t dataLen,
   uint8_t *p, size_t *length)
{
   SshChannelBuffer *txBuffer;

   //Point to the transmission buffer
   txBuffer = &channel->txBuffer;

   //Check the length of the payload data
   if((dataLen + SSH_CHANNEL_DATA_MSG_HEADER_SIZE) > SSH_MAX_PACKET_SIZE)
      return ERROR_INVALID_LENGTH;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_DATA;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel
   STORE32BE(channel->remoteChannelNum, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //The data is preceded by a uint32 containing its length
   STORE32BE(dataLen, p);

   //Point to the payload data
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Check whether the specified data crosses channel buffer boundaries
   if((txBuffer->readPos + dataLen) <= SSH_CHANNEL_BUFFER_SIZE)
   {
      //Copy the payload data
      osMemcpy(p, txBuffer->data + txBuffer->readPos, dataLen);
   }
   else
   {
      //Copy the first part of the payload data
      osMemcpy(p, txBuffer->data + txBuffer->readPos,
         SSH_CHANNEL_BUFFER_SIZE - txBuffer->readPos);

      //Wrap around to the beginning of the circular buffer
      osMemcpy(p + SSH_CHANNEL_BUFFER_SIZE - txBuffer->readPos,
         txBuffer->data, txBuffer->readPos + dataLen -
         SSH_CHANNEL_BUFFER_SIZE);
   }

   //Total length of the message
   *length += dataLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_EOF message
 * @param[in] channel Handle referencing an SSH channel
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelEof(SshChannel *channel, uint8_t *p, size_t *length)
{
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_EOF;

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
 * @brief Format SSH_MSG_CHANNEL_CLOSE message
 * @param[in] channel Handle referencing an SSH channel
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelClose(SshChannel *channel, uint8_t *p, size_t *length)
{
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_CLOSE;

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
 * @brief Parse SSH_MSG_CHANNEL_OPEN message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelOpen(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   uint_t i;
   const uint8_t *p;
   uint32_t senderChannel;
   uint32_t initialWindowSize;
   uint32_t maxPacketSize;
   SshString channelType;
   SshChannel *channel;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_OPEN message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Decode the channel type
   error = sshParseString(p, length, &channelType);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + channelType.length;
   length -= sizeof(uint32_t) + channelType.length;

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get sender channel number
   senderChannel = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get initial window size
   initialWindowSize = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get maximum packet size
   maxPacketSize = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Debug message
   TRACE_DEBUG("  Sender Channel = %" PRIu32 "\r\n", senderChannel);
   TRACE_DEBUG("  Initial Window Size = %" PRIu32 "\r\n", initialWindowSize);
   TRACE_DEBUG("  Max Packet Size = %" PRIu32 "\r\n", maxPacketSize);

   //Sanity check
   if(maxPacketSize == 0)
      return ERROR_ILLEGAL_PARAMETER;

   //Each side must associate a unique number to the channel
   if(!sshCheckRemoteChannelNum(connection, senderChannel))
      return ERROR_ILLEGAL_PARAMETER;

   //Check channel type
   if(sshCompareString(&channelType, "session"))
   {
      //A "session" channel does not specify any type-specific data
      if(length != 0)
         return ERROR_INVALID_MESSAGE;

      //Check whether SSH operates as a client or a server
      if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         //Client implementations should reject any session channel open
         //requests to make it more difficult for a corrupt server to attack
         //the client (refer to RFC 4254, section 6.1)
         error = sshSendChannelOpenFailure(connection, senderChannel,
            SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "Administratively prohibited");
      }
      else
      {
         //The server decides whether it can open the channel
         channel = sshCreateChannel(connection);

         //Valid channel handle?
         if(channel != NULL)
         {
            //Save the channel number allocated by the other side
            channel->remoteChannelNum = senderChannel;

            //Save channel's parameters
            channel->txWindowSize = initialWindowSize;
            channel->maxPacketSize = maxPacketSize;

            //Send an SSH_MSG_CHANNEL_OPEN_CONFIRMATION message to the client
            error = sshSendChannelOpenConfirmation(channel);
         }
         else
         {
            //Send an SSH_MSG_CHANNEL_OPEN_FAILURE message to the client
            error = sshSendChannelOpenFailure(connection, senderChannel,
               SSH_OPEN_RESOURCE_SHORTAGE, "Maximum number of channels exceeded");
         }
      }
   }
   else
   {
      //Initialize status code
      error = ERROR_UNKNOWN_TYPE;

      //Multiple callbacks may be registered
      for(i = 0; i < SSH_MAX_CHANNEL_OPEN_CALLBACKS &&
         error == ERROR_UNKNOWN_TYPE; i++)
      {
         //Valid callback function?
         if(context->channelOpenCallback[i] != NULL)
         {
            //Process channel open request
            error = context->channelOpenCallback[i](connection, &channelType,
               senderChannel, initialWindowSize, maxPacketSize, p, length,
               context->channelOpenParam[i]);
         }
      }

      //Check status code
      if(error == ERROR_UNKNOWN_TYPE)
      {
         //Send an SSH_MSG_CHANNEL_OPEN_FAILURE message to the peer
         error = sshSendChannelOpenFailure(connection, senderChannel,
            SSH_OPEN_UNKNOWN_CHANNEL_TYPE, "Unknown channel type");
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse "forwarded-tcpip" channel parameters
 * @param[in] p Pointer to the channel specific data
 * @param[in] length Length of the channel specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseForwardedTcpIpParams(const uint8_t *p, size_t length,
   SshForwardedTcpIpParams *params)
{
   error_t error;

   //Parse 'address that was connected' field
   error = sshParseString(p, length, &params->addrConnected);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + params->addrConnected.length;
   length -= sizeof(uint32_t) + params->addrConnected.length;

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Parse 'port that was connected' field
   params->portConnected = LOAD32BE(p);

   //Invalid port number?
   if(params->portConnected > SSH_MAX_PORT_NUM)
      return ERROR_INVALID_PORT;

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Parse 'originator IP address' field
   error = sshParseString(p, length, &params->originIpAddr);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + params->originIpAddr.length;
   length -= sizeof(uint32_t) + params->originIpAddr.length;

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Parse 'originator port' field
   params->originPort = LOAD32BE(p);

   //Invalid port number?
   if(params->originPort > SSH_MAX_PORT_NUM)
      return ERROR_INVALID_PORT;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "direct-tcpip" channel parameters
 * @param[in] p Pointer to the channel specific data
 * @param[in] length Length of the channel specific data, in bytes
 * @param[out] params Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseDirectTcpIpParams(const uint8_t *p, size_t length,
   SshDirectTcpIpParams *params)
{
   error_t error;

   //The 'host to connect' field specifies the TCP/IP host where the recipient
   //should connect the channel
   error = sshParseString(p, length, &params->hostToConnect);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + params->hostToConnect.length;
   length -= sizeof(uint32_t) + params->hostToConnect.length;

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //The 'port to connect' field specifies the port where the recipient should
   //connect the channel
   params->portToConnect = LOAD32BE(p);

   //Invalid port number?
   if(params->portToConnect > SSH_MAX_PORT_NUM)
      return ERROR_INVALID_PORT;

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //The 'originator IP address' field is the numeric IP address of the machine
   //from where the connection request originates
   error = sshParseString(p, length, &params->originIpAddr);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + params->originIpAddr.length;
   length -= sizeof(uint32_t) + params->originIpAddr.length;

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //The 'originator port' field is the port on the host from where the
   //connection originated
   params->originPort = LOAD32BE(p);

   //Invalid port number?
   if(params->originPort > SSH_MAX_PORT_NUM)
      return ERROR_INVALID_PORT;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_CHANNEL_OPEN_CONFIRMATION message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelOpenConfirmation(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   uint32_t senderChannel;
   uint32_t initialWindowSize;
   uint32_t maxPacketSize;
   SshChannel *channel;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_OPEN_CONFIRMATION message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Decode the recipient channel
   recipientChannel = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Decode the sender channel
   senderChannel = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Decode initial window size
   initialWindowSize = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Decode maximum packet size
   maxPacketSize = LOAD32BE(p);

   //Debug message
   TRACE_DEBUG("  Recipient Channel = %" PRIu32 "\r\n", recipientChannel);
   TRACE_DEBUG("  Sender Channel = %" PRIu32 "\r\n", senderChannel);
   TRACE_DEBUG("  Initial Window Size = %" PRIu32 "\r\n", initialWindowSize);
   TRACE_DEBUG("  Max Packet Size = %" PRIu32 "\r\n", maxPacketSize);

   //Sanity check
   if(maxPacketSize == 0)
      return ERROR_ILLEGAL_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&connection->context->mutex);

   //Each side must associate a unique number to the channel
   if(sshCheckRemoteChannelNum(connection, senderChannel))
   {
      //Point to the matching channel
      channel = sshGetChannel(connection, recipientChannel);

      //Valid channel?
      if(channel != NULL)
      {
         //Check channel state
         if(channel->state == SSH_CHANNEL_STATE_RESERVED)
         {
            //Save the channel number allocated by the other side
            channel->remoteChannelNum = senderChannel;

            //Save channel's parameters
            channel->txWindowSize = initialWindowSize;
            channel->maxPacketSize = maxPacketSize;

            //Update the state of the channel
            channel->state = SSH_CHANNEL_STATE_OPEN;
            //Update channel related events
            sshUpdateChannelEvents(channel);

            //Successfull processing
            error = NO_ERROR;
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
   }
   else
   {
      //The sender channel number is not valid
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&connection->context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_MSG_CHANNEL_OPEN_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelOpenFailure(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   uint32_t reasonCode;
   SshString description;
   SshString languageTag;
   SshChannel *channel;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_OPEN_FAILURE message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Decode the recipient channel
   recipientChannel = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Decode the reason code
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

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&connection->context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_RESERVED)
      {
         //Update the state of the channel
         channel->state = SSH_CHANNEL_STATE_CLOSED;
         //Update channel related events
         sshUpdateChannelEvents(channel);

         //Successfull processing
         error = NO_ERROR;
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
 * @brief Parse SSH_MSG_CHANNEL_WINDOW_ADJUST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelWindowAdjust(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   uint32_t windowSizeInc;
   SshChannel *channel;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Debug message
   TRACE_DEBUG("SSH_MSG_CHANNEL_WINDOW_ADJUST message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get the number of bytes to add
   windowSizeInc = LOAD32BE(p);

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
         //Check whether the window size increment is valid
         if((channel->txWindowSize + windowSizeInc) >= channel->txWindowSize)
         {
            //After receiving this message, the recipient may send the given
            //number of bytes more than it was previously allowed to send. The
            //window size is incremented (refer to RFC 4254, section 5.2)
            channel->txWindowSize += windowSizeInc;

            //Check whether another SSH_MSG_CHANNEL_DATA message can be sent
            sshNotifyEvent(context);

            //Successfull processing
            error = NO_ERROR;
         }
         else
         {
            //The window must not be increased above 2^32 - 1 bytes
            error = ERROR_FLOW_CONTROL;
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
 * @brief Parse SSH_MSG_CHANNEL_DATA message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelData(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   SshBinaryString data;
   SshChannel *channel;

   //Debug message
   TRACE_DEBUG("SSH_MSG_CHANNEL_DATA message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Decode the data field
   error = sshParseBinaryString(p, length, &data);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + data.length;
   length -= sizeof(uint32_t) + data.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&connection->context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->eofReceived &&
         !channel->closeReceived)
      {
         //Process payload data
         error = sshProcessChannelData(channel, data.value, data.length);
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
 * @brief Parse SSH_MSG_CHANNEL_EXTENDED_DATA message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelExtendedData(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   uint32_t dataType;
   SshBinaryString data;
   SshChannel *channel;

   //Debug message
   TRACE_DEBUG("SSH_MSG_CHANNEL_DATA message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get data type code
   dataType = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Decode the data field
   error = sshParseBinaryString(p, length, &data);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + data.length;
   length -= sizeof(uint32_t) + data.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&connection->context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->eofReceived &&
         !channel->closeReceived)
      {
         //Process extended data
         error = sshProcessChannelExtendedData(channel, dataType, data.value,
            data.length);
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
 * @brief Parse SSH_MSG_CHANNEL_EOF message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelEof(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   SshChannel *channel;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_EOF message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Get recipient channel number
   recipientChannel = LOAD32BE(p);

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&connection->context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->eofReceived &&
         !channel->closeReceived)
      {
         //The channel remains open after this message, and more data may still
         //be sent in the other direction (refer to RFC 4254, section 5.3)
         channel->eofReceived = TRUE;

         //Update channel related events
         sshUpdateChannelEvents(channel);

         //Successfull processing
         error = NO_ERROR;
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
 * @brief Parse SSH_MSG_CHANNEL_CLOSE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelClose(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   SshChannel *channel;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_CLOSE message received (%" PRIuSIZE " bytes)...\r\n", length);
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

   //Get recipient channel number
   recipientChannel = LOAD32BE(p);

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
         //An SSH_MSG_CHANNEL_CLOSE message has been successfully received
         channel->closeReceived = TRUE;

         //Upon receiving an SSH_MSG_CHANNEL_CLOSE message, a party must send
         //back an SSH_MSG_CHANNEL_CLOSE unless it has already sent this message
         //for the channel (refer to RFC 4254, section 5.3)
         if(!channel->closeSent)
         {
            //Send an SSH_MSG_CHANNEL_CLOSE message
            error = sshSendChannelClose(channel);
         }
         else
         {
            //The channel is considered closed for a party when it has both sent
            //and received SSH_MSG_CHANNEL_CLOSE
            channel->state = SSH_CHANNEL_STATE_CLOSED;

            //Successful processing
            error = NO_ERROR;
         }

         //Update channel related events
         sshUpdateChannelEvents(channel);
      }
      else
      {
         //Report an error
         error = ERROR_UNEXPECTED_MESSAGE;
      }

      //Check channel state
      if(connection->context->mode == SSH_OPERATION_MODE_SERVER &&
         channel->state == SSH_CHANNEL_STATE_CLOSED)
      {
         //Release SSH channel
         if(channel->closeRequest || !channel->channelSuccessSent)
         {
            channel->state = SSH_CHANNEL_STATE_UNUSED;
         }
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
