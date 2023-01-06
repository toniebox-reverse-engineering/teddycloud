/**
 * @file ssh_packet.h
 * @brief SSH packet encryption/decryption
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

#ifndef _SSH_PACKET_H
#define _SSH_PACKET_H

//Dependencies
#include "ssh/ssh.h"

//SSH packet header size
#define SSH_PACKET_HEADER_SIZE 5
//Minimum SSH packet size
#define SSH_MIN_PACKET_SIZE 8
//Default maximum packet size
#define SSH_DEFAULT_MAX_PACKET_SIZE 32768
//Size of SSH_MSG_CHANNEL_DATA message header
#define SSH_CHANNEL_DATA_MSG_HEADER_SIZE 9

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
error_t sshSendPacket(SshConnection *connection, uint8_t *payload,
   size_t payloadLen);

error_t sshReceivePacket(SshConnection *connection);

error_t sshParsePacket(SshConnection *connection, uint8_t *packet,
   size_t length);

error_t sshEncryptPacket(SshConnection *connection, uint8_t *packet,
   size_t *length);

error_t sshDecryptPacket(SshConnection *connection, uint8_t *packet,
   size_t *length);

error_t sshParsePacketLength(SshConnection *connection, uint8_t *packet);
error_t sshDecryptPacketLength(SshConnection *connection, uint8_t *packet);

error_t sshParseMessage(SshConnection *connection, const uint8_t *message,
   size_t length);

void sshAppendMessageAuthCode(SshEncryptionEngine *encryptionEngine,
   uint8_t *packet, size_t length);

error_t sshVerifyMessageAuthCode(SshEncryptionEngine *decryptionEngine,
   const uint8_t *packet, size_t length);

void sshIncSequenceNumber(uint8_t *seqNum);
void sshIncInvocationCounter(uint8_t *iv);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
