/**
 * @file ssh_channel.c
 * @brief SSH channel management
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
 * @brief Get the channel that matches the specified channel number
 * @param[in] connection Pointer to the SSH connection
 * @param[in] localChannelNum Local channel number
 * @return Handle referencing an SSH channel
 **/

SshChannel *sshGetChannel(SshConnection *connection, uint32_t localChannelNum)
{
   uint_t i;
   SshContext *context;
   SshChannel *channel;

   //Point to the SSH context
   context = connection->context;
   //Initialize handle
   channel = NULL;

   //Loop through SSH channels
   for(i = 0; i < context->numChannels; i++)
   {
      //Multiple channels can be multiplexed into a single connection
      if(context->channels[i].state != SSH_CHANNEL_STATE_UNUSED &&
         context->channels[i].connection == connection)
      {
         //Compare channel numbers
         if(context->channels[i].localChannelNum == localChannelNum)
         {
            //The current channel matches the specified channel number
            channel = &context->channels[i];
            break;
         }
      }
   }

   //Return channel handle
   return channel;
}


/**
 * @brief Generate a local channel number
 * @param[in] connection Pointer to the SSH connection
 * @return Channel number
 **/

uint32_t sshAllocateLocalChannelNum(SshConnection *connection)
{
   uint_t i;
   bool_t valid;
   SshContext *context;
   SshChannel *channel;

   //Point to the SSH context
   context = connection->context;

   //When the implementation wish to open a new channel, it allocates a
   //local number for the channel (refer to RFC 4254, section 5.1)
   for(valid = FALSE; !valid; )
   {
      //Generate a new channel number
      connection->localChannelNum++;

      //Loop through SSH channels
      for(i = 0, valid = TRUE; i < context->numChannels && valid; i++)
      {
         //Point to the current SSH channel
         channel = &context->channels[i];

         //Multiple channels can be multiplexed into a single connection
         if(channel->state != SSH_CHANNEL_STATE_UNUSED &&
            channel->connection == connection)
         {
            //Compare channel numbers
            if(channel->localChannelNum == connection->localChannelNum)
            {
               //The channel number is already in use
               valid = FALSE;
            }
         }
      }
   }

   //Return channel number
   return connection->localChannelNum;
}


/**
 * @brief Check remote channel number
 * @param[in] connection Pointer to the SSH connection
 * @param[in] remoteChannelNum Remote channel number
 * @return TRUE if the channel number is valid, else FALSE
 **/

bool_t sshCheckRemoteChannelNum(SshConnection *connection,
   uint32_t remoteChannelNum)
{
   uint_t i;
   bool_t valid;
   SshContext *context;
   SshChannel *channel;

   //Point to the SSH context
   context = connection->context;

   //Loop through SSH channels
   for(i = 0, valid = TRUE; i < context->numChannels && valid; i++)
   {
      //Point to the current SSH channel
      channel = &context->channels[i];

      //Check the state of the channel
      if(channel->state == SSH_CHANNEL_STATE_OPEN)
      {
         //Multiple channels can be multiplexed into a single connection
         if(channel->connection == connection)
         {
            //Each side must associate a unique number to the channel
            if(channel->remoteChannelNum == remoteChannelNum)
            {
               //The channel number is already in use
               valid = FALSE;
            }
         }
      }
   }

   //Return TRUE if the channel number is valid
   return valid;
}


/**
 * @brief Register channel events
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] eventDesc SSH channel events to be registered
 **/

void sshRegisterChannelEvents(SshChannel *channel, SocketEventDesc *eventDesc)
{
   //Acquire exclusive access to the SSH context
   osAcquireMutex(&channel->context->mutex);

   //Check the state of the channel
   if(channel->rxWindowSizeInc >= (SSH_CHANNEL_BUFFER_SIZE / 2))
   {
      //An SSH_MSG_CHANNEL_WINDOW_ADJUST message is pending for transmission
      eventDesc->eventMask = SOCKET_EVENT_TX_READY;
   }
   else if(channel->txBuffer.length > 0)
   {
      //Channels are flow-controlled. No data may be sent to a channel until
      //a message is received to indicate that window space is available
      if(channel->txWindowSize > 0)
      {
         //An SSH_MSG_CHANNEL_DATA message is pending for transmission
         eventDesc->eventMask = SOCKET_EVENT_TX_READY;
      }
   }
   else if(channel->eofRequest && !channel->eofSent)
   {
      //An SSH_MSG_CHANNEL_EOF message is pending for transmission
      eventDesc->eventMask = SOCKET_EVENT_TX_READY;
   }
   else if(channel->closeRequest && !channel->closeSent)
   {
      //An SSH_MSG_CHANNEL_CLOSE message is pending for transmission
      eventDesc->eventMask = SOCKET_EVENT_TX_READY;
   }
   else
   {
      //Just for sanity
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&channel->context->mutex);
}


/**
 * @brief Channel event handler
 * @param[in] channel Handle referencing an SSH channel
 * @return Error code
 **/

error_t sshProcessChannelEvents(SshChannel *channel)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&channel->context->mutex);

   //Check the state of the channel
   if(channel->rxWindowSizeInc >= (SSH_CHANNEL_BUFFER_SIZE / 2))
   {
      //Update flow-control window
      channel->rxWindowSize += channel->rxWindowSizeInc;

      //Send an SSH_MSG_CHANNEL_WINDOW_ADJUST message
      error = sshSendChannelWindowAdjust(channel, channel->rxWindowSizeInc);

      //Check status code
      if(!error)
      {
         //Clear window size increment
         channel->rxWindowSizeInc = 0;
      }
   }
   else if(channel->txBuffer.length > 0)
   {
      size_t n;
      SshChannelBuffer *txBuffer;

      //Point to the transmit buffer
      txBuffer = &channel->txBuffer;

      //Get the number of bytes available in the send buffer
      n = txBuffer->length;

      //Limit the number of bytes to send at a time
      n = MIN(n, SSH_MAX_PACKET_SIZE - SSH_CHANNEL_DATA_MSG_HEADER_SIZE);

      //The maximum amount of data allowed is determined by the maximum packet
      //size for the channel, and the current window size, whichever is smaller
      //(refer to RFC 4254, section 5.2)
      n = MIN(n, channel->maxPacketSize);
      n = MIN(n, channel->txWindowSize);

      //Channels are flow-controlled. No data may be sent to a channel until
      //a message is received to indicate that window space is available
      if(n > 0)
      {
         //Send an SSH_MSG_CHANNEL_DATA message
         error = sshSendChannelData(channel, n);

         //Check status code
         if(!error)
         {
            //Advance read pointer
            txBuffer->readPos += n;

            //Wrap around if necessary
            if(txBuffer->readPos >= SSH_CHANNEL_BUFFER_SIZE)
            {
               txBuffer->readPos -= SSH_CHANNEL_BUFFER_SIZE;
            }

            //Update buffer length
            txBuffer->length -= n;
            //Update flow-control window
            channel->txWindowSize -= n;

            //Update channel related events
            sshUpdateChannelEvents(channel);
         }
      }
   }
   else if(channel->eofRequest && !channel->eofSent)
   {
      //Send an SSH_MSG_CHANNEL_EOF message
      error = sshSendChannelEof(channel);
   }
   else if(channel->closeRequest && !channel->closeSent)
   {
      //Send an SSH_MSG_CHANNEL_CLOSE message
      error = sshSendChannelClose(channel);

      //Check status code
      if(!error)
      {
         //Update channel related events
         sshUpdateChannelEvents(channel);
      }
   }
   else
   {
      //Just for sanity
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&channel->context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Wait for a particular SSH channel event
 * @param[in] channel Pointer to the SSH channel
 * @param[in] eventMask Logic OR of all the events that will complete the wait
 * @param[in] timeout Maximum time to wait
 * @return Logic OR of all the events that satisfied the wait
 **/

uint_t sshWaitForChannelEvents(SshChannel *channel, uint_t eventMask,
   systime_t timeout)
{
   uint_t eventFlags = 0;

   //Valid channel?
   if(channel != NULL)
   {
      //Only one of the events listed here may complete the wait
      channel->eventMask = eventMask;

      //Update channel related events
      sshUpdateChannelEvents(channel);

      //No event is signaled?
      if(!channel->eventFlags)
      {
         //Reset the event object
         osResetEvent(&channel->event);
         //Release exclusive access to the SSH context
         osReleaseMutex(&channel->context->mutex);
         //Wait until an event is triggered
         osWaitForEvent(&channel->event, timeout);
         //Acquire exclusive access to the SSH context
         osAcquireMutex(&channel->context->mutex);
      }

      //Retrieve the list of events that satisfied the wait
      eventFlags = channel->eventFlags;
   }

   //Return active events
   return eventFlags;
}


/**
 * @brief Update SSH channel related events
 * @param[in] channel Pointer to the SSH channel
 **/

void sshUpdateChannelEvents(SshChannel *channel)
{
   //Valid channel?
   if(channel->state != SSH_CHANNEL_STATE_UNUSED)
   {
      //Clear event flags
      channel->eventFlags = 0;

      //Check whether the channel is closed
      if(channel->state == SSH_CHANNEL_STATE_CLOSED)
      {
         channel->eventFlags |= SSH_CHANNEL_EVENT_CLOSED;
      }

      //Handle TX specific events
      if(channel->state == SSH_CHANNEL_STATE_RESERVED)
      {
         //The channel is not writable
      }
      else if(channel->state == SSH_CHANNEL_STATE_OPEN)
      {
         //Check whether the send buffer is full or not
         if(channel->txBuffer.length < SSH_CHANNEL_BUFFER_SIZE)
         {
            channel->eventFlags |= SSH_CHANNEL_EVENT_TX_READY;
         }
      }
      else
      {
         //Unblock user task if the channel is closed
         channel->eventFlags |= SSH_CHANNEL_EVENT_TX_READY;
      }

      //Handle RX specific events
      if(channel->state == SSH_CHANNEL_STATE_RESERVED)
      {
         //The channel is not readable
      }
      else if(channel->state == SSH_CHANNEL_STATE_OPEN)
      {
         //Any data pending in the receive buffer?
         if(channel->rxBuffer.length > channel->rxBuffer.threshold ||
            channel->eofReceived)
         {
            channel->eventFlags |= SSH_CHANNEL_EVENT_RX_READY;
         }
      }
      else
      {
         //Unblock user task if the channel is closed
         channel->eventFlags |= SSH_CHANNEL_EVENT_RX_READY;
      }

      //Mask unused events
      channel->eventFlags &= channel->eventMask;

      //Any event to signal?
      if(channel->eventFlags)
      {
         //Unblock I/O operations currently in waiting state
         osSetEvent(&channel->event);

         //Set user event to signaled state if necessary
         if(channel->userEvent != NULL)
         {
            osSetEvent(channel->userEvent);
         }
      }
   }
}


/**
 * @brief Process incoming data
 * @param[in] channel Pointer to the SSH channel
 * @param[in] data Pointer to the payload data
 * @param[in] length Length of the payload data, in bytes
 * @return Error code
 **/

error_t sshProcessChannelData(SshChannel *channel, const uint8_t *data,
   size_t length)
{
   error_t error;
   SshChannelBuffer *rxBuffer;

   //Point to the receive buffer
   rxBuffer = &channel->rxBuffer;

   //Make sure the receiver is able to accept the data
   if(length > channel->rxWindowSize)
   {
      //Report a flow control error
      error = ERROR_FLOW_CONTROL;
   }
   else if((rxBuffer->length + length) > SSH_CHANNEL_BUFFER_SIZE)
   {
      //Report a flow control error
      error = ERROR_FLOW_CONTROL;
   }
   else
   {
      //Update channel flow-control window
      channel->rxWindowSize -= length;

      //Check whether the specified data crosses channel buffer boundaries
      if((rxBuffer->writePos + length) <= SSH_CHANNEL_BUFFER_SIZE)
      {
         //Copy the data
         osMemcpy(rxBuffer->data + rxBuffer->writePos, data, length);
      }
      else
      {
         //Copy the first part of the data
         osMemcpy(rxBuffer->data + rxBuffer->writePos, data,
            SSH_CHANNEL_BUFFER_SIZE - rxBuffer->writePos);

         //Wrap around to the beginning of the circular buffer
         osMemcpy(rxBuffer->data, data + SSH_CHANNEL_BUFFER_SIZE - rxBuffer->writePos,
            rxBuffer->writePos + length - SSH_CHANNEL_BUFFER_SIZE);
      }

      //Advance write position
      rxBuffer->writePos += length;

      //Wrap around if necessary
      if(rxBuffer->writePos >= SSH_CHANNEL_BUFFER_SIZE)
      {
         rxBuffer->writePos -= SSH_CHANNEL_BUFFER_SIZE;
      }

      //Update buffer length
      rxBuffer->length += length;

      //Update channel related events
      sshUpdateChannelEvents(channel);

      //Successful processing
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Process incoming extended data
 * @param[in] channel Pointer to the SSH channel
 * @param[in] type Extended data type
 * @param[in] data Pointer to the extended data
 * @param[in] length Length of the extended data, in bytes
 * @return Error code
 **/

error_t sshProcessChannelExtendedData(SshChannel *channel, uint32_t type,
   const uint8_t *data, size_t length)
{
   error_t error;

   //Make sure the receiver is able to accept the data
   if(length > channel->rxWindowSize)
   {
      //Report a flow control error
      error = ERROR_FLOW_CONTROL;
   }
   else
   {
      //Data sent with SSH_MSG_CHANNEL_EXTENDED_DATA messages consumes the
      //same window as ordinary data
      channel->rxWindowSize -= length;

      //Update flow-control window
      sshUpdateChannelWindow(channel, length);

      //Successful processing
      error = NO_ERROR;
   }

   //Return status code
   return error;
}


/**
 * @brief Update channel flow-control window
 * @param[in] channel Pointer to the SSH channel
 * @param[in] windowSizeInc Window size increment
 * @return Error code
 **/

error_t sshUpdateChannelWindow(SshChannel *channel, uint32_t windowSizeInc)
{
   //Update window size increment
   channel->rxWindowSizeInc += windowSizeInc;

   //Notify the SSH core that the flow-control window should be updated
   sshNotifyEvent(channel->context);

   //Return status code
   return NO_ERROR;
}

#endif
