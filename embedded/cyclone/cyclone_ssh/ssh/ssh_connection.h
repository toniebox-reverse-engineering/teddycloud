/**
 * @file ssh_connection.h
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

#ifndef _SSH_CONNECTION_H
#define _SSH_CONNECTION_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief "x11" channel specific parameters
 **/

typedef struct
{
   SshString originatorAddr;
   uint32_t originatorPort;
} SshX11ChannelParams;


/**
 * @brief "forwarded-tcpip" channel specific parameters
 **/

typedef struct
{
   SshString addrConnected;
   uint32_t portConnected;
   SshString originIpAddr;
   uint32_t originPort;
} SshForwardedTcpIpParams;


/**
 * @brief "direct-tcpip" channel specific parameters
 **/

typedef struct
{
   SshString hostToConnect;
   uint32_t portToConnect;
   SshString originIpAddr;
   uint32_t originPort;
} SshDirectTcpIpParams;


//SSH related functions
error_t sshSendChannelOpen(SshChannel *channel, const char_t *channelType,
   const void *channelParams);

error_t sshSendChannelOpenConfirmation(SshChannel *channel);

error_t sshSendChannelOpenFailure(SshConnection *connection,
   uint32_t recipientChannel, uint32_t reasonCode, const char_t *description);

error_t sshSendChannelWindowAdjust(SshChannel *channel, size_t windowSizeInc);
error_t sshSendChannelData(SshChannel *channel, size_t dataLen);
error_t sshSendChannelEof(SshChannel *channel);
error_t sshSendChannelClose(SshChannel *channel);

error_t sshFormatChannelOpen(SshChannel *channel, const char_t *channelType,
   const void *channelParams, uint8_t *p, size_t *length);

error_t sshFormatForwardedTcpIpParams(const SshForwardedTcpIpParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatDirectTcpIpParams(const SshDirectTcpIpParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatChannelOpenConfirmation(SshChannel *channel, uint8_t *p,
   size_t *length);

error_t sshFormatChannelOpenFailure(SshConnection *connection,
   uint32_t recipientChannel, uint32_t reasonCode, const char_t *description,
   uint8_t *p, size_t *length);

error_t sshFormatChannelWindowAdjust(SshChannel *channel, size_t windowSizeInc,
   uint8_t *p, size_t *length);

error_t sshFormatChannelData(SshChannel *channel, size_t dataLen,
   uint8_t *p, size_t *length);

error_t sshFormatChannelEof(SshChannel *channel, uint8_t *p, size_t *length);
error_t sshFormatChannelClose(SshChannel *channel, uint8_t *p, size_t *length);

error_t sshParseChannelOpen(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseForwardedTcpIpParams(const uint8_t *p, size_t length,
   SshForwardedTcpIpParams *params);

error_t sshParseDirectTcpIpParams(const uint8_t *p, size_t length,
   SshDirectTcpIpParams *params);

error_t sshParseChannelOpenConfirmation(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelOpenFailure(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelWindowAdjust(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelData(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelExtendedData(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelEof(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelClose(SshConnection *connection,
   const uint8_t *message, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
