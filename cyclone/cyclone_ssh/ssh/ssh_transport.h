/**
 * @file ssh_transport.h
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

#ifndef _SSH_TRANSPORT_H
#define _SSH_TRANSPORT_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
error_t sshSendIdString(SshConnection *connection);
error_t sshSendServiceRequest(SshConnection *connection);

error_t sshSendServiceAccept(SshConnection *connection,
   const char_t *serviceName);

error_t sshSendDisconnect(SshConnection *connection,
   uint32_t reasonCode, const char_t *description);

error_t sshSendUnimplemented(SshConnection *connection,
   const uint8_t *packetSeqNum);

error_t sshFormatServiceRequest(SshConnection *connection, uint8_t *p,
   size_t *length);

error_t sshFormatServiceAccept(SshConnection *connection,
   const char_t *serviceName, uint8_t *p, size_t *length);

error_t sshFormatDisconnect(SshConnection *connection, uint32_t reasonCode,
   const char_t *description, uint8_t *p, size_t *length);

error_t sshFormatUnimplemented(SshConnection *connection,
   const uint8_t *packetSeqNum, uint8_t *p, size_t *length);

error_t sshParseIdString(SshConnection *connection, const uint8_t *id,
   size_t length);

error_t sshParseServiceRequest(SshConnection *connection, const uint8_t *message,
   size_t length);

error_t sshParseServiceAccept(SshConnection *connection, const uint8_t *message,
   size_t length);

error_t sshParseIgnore(SshConnection *connection, const uint8_t *message,
   size_t length);

error_t sshParseDebug(SshConnection *connection, const uint8_t *message,
   size_t length);

error_t sshParseDisconnect(SshConnection *connection, const uint8_t *message,
   size_t length);

error_t sshParseUnimplemented(SshConnection *connection, const uint8_t *message,
   size_t length);

error_t sshParseUnrecognized(SshConnection *connection, const uint8_t *message,
   size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
