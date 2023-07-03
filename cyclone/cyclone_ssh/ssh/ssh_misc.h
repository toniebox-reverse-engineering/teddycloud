/**
 * @file ssh_misc.h
 * @brief SSH helper functions
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

#ifndef _SSH_MISC_H
#define _SSH_MISC_H

//Dependencies
#include "ssh/ssh.h"
#include "mpi/mpi.h"

//Maximum port number
#define SSH_MAX_PORT_NUM 65535

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
SshConnection *sshOpenConnection(SshContext *context, Socket *socket);
void sshCloseConnection(SshConnection *connection);

void sshRegisterConnectionEvents(SshContext *context,
   SshConnection *connection, SocketEventDesc *eventDesc);

error_t sshProcessConnectionEvents(SshContext *context,
   SshConnection *connection);

void sshRegisterUserEvents(SshChannel *channel, OsEvent *event,
   uint_t eventMask);

void sshUnregisterUserEvents(SshChannel *channel);
uint_t sshGetUserEvents(SshChannel *channel);

void sshNotifyEvent(SshContext *context);

SshHostKey *sshGetHostKey(SshConnection *connection);
int_t sshSelectHostKey(SshContext *context, const char_t *hostKeyAlgo);
int_t sshSelectNextHostKey(SshConnection *connection);

error_t sshFormatHostKey(SshConnection *connection, uint8_t *p,
   size_t *written);

const EcCurveInfo *sshGetCurveInfo(const SshString *keyFormatId,
   const SshString *curveName);

error_t sshParseString(const uint8_t *p, size_t length, SshString *string);

error_t sshParseBinaryString(const uint8_t *p, size_t length,
   SshBinaryString *string);

error_t sshParseNameList(const uint8_t *p, size_t length,
   SshNameList *nameList);

int_t sshFindName(const SshNameList *nameList, const char_t *name);
bool_t sshGetName(const SshNameList *nameList, uint_t index, SshString *name);

error_t sshFormatString(const char_t *value, uint8_t *p, size_t *written);

error_t sshFormatBinaryString(const void *value, size_t valueLen, uint8_t *p,
   size_t *written);

error_t sshFormatNameList(const char_t *const nameList[], uint_t nameListLen,
   uint8_t *p, size_t *written);

error_t sshFormatMpint(const Mpi *value, uint8_t *p, size_t *written);

error_t sshConvertArrayToMpint(const uint8_t *value, size_t length, uint8_t *p,
   size_t *written);

bool_t sshCompareString(const SshString *string, const char_t *value);
bool_t sshCompareStrings(const SshString *string1, const SshString *string2);
bool_t sshCompareAlgo(const char_t *name1, const char_t *name2);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
