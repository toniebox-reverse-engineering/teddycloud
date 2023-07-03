/**
 * @file sftp_server_misc.h
 * @brief Helper functions for SFTP server
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

#ifndef _SFTP_SERVER_MISC_H
#define _SFTP_SERVER_MISC_H

//Dependencies
#include "sftp/sftp_server.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SFTP server related functions
void sftpServerTick(SftpServerContext *context);

error_t sftpServerChannelRequestCallback(SshChannel *channel,
   const SshString *type, const uint8_t *data, size_t length,
   void *param);

SftpServerSession *sftpServerFindSession(SftpServerContext *context,
   SshChannel *channel);

SftpServerSession *sftpServerOpenSession(SftpServerContext *context,
   SshChannel *channel);

void sftpServerCloseSession(SftpServerSession *session);

void sftpServerRegisterSessionEvents(SftpServerSession *session,
   SshChannelEventDesc *eventDesc);

void sftpServerProcessSessionEvents(SftpServerSession *session);

error_t sftpServerParsePacketLength(SftpServerSession *session,
   const uint8_t *packet);

error_t sftpServerParsePacket(SftpServerSession *session,
   const uint8_t *packet, size_t fragLen, size_t totalLen);

uint32_t sftpServerGenerateHandle(SftpServerSession *session);

uint_t sftpServerGetFilePermissions(SftpServerSession *session,
   const char_t *path);

error_t sftpServerGetPath(SftpServerSession *session, const SshString *path,
   char_t *fullPath, size_t maxLen);

const char_t *sftpServerStripRootDir(SftpServerSession *session,
   const char_t *path);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
