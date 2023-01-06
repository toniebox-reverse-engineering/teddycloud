/**
 * @file ssh_channel.h
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

#ifndef _SSH_CHANNEL_H
#define _SSH_CHANNEL_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
SshChannel *sshGetChannel(SshConnection *connection, uint32_t localChannelNum);

uint32_t sshAllocateLocalChannelNum(SshConnection *connection);

bool_t sshCheckRemoteChannelNum(SshConnection *connection,
   uint32_t remoteChannelNum);

void sshRegisterChannelEvents(SshChannel *channel, SocketEventDesc *eventDesc);
error_t sshProcessChannelEvents(SshChannel *channel);

uint_t sshWaitForChannelEvents(SshChannel *channel, uint_t eventMask,
   systime_t timeout);

void sshUpdateChannelEvents(SshChannel *channel);

error_t sshProcessChannelData(SshChannel *channel, const uint8_t *data,
   size_t length);

error_t sshProcessChannelExtendedData(SshChannel *channel, uint32_t type,
   const uint8_t *data, size_t length);

error_t sshUpdateChannelWindow(SshChannel *channel, uint32_t windowSizeInc);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
