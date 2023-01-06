/**
 * @file sftp_server_packet.h
 * @brief SFTP packet parsing and formatting
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

#ifndef _SFTP_SERVER_PACKET_H
#define _SFTP_SERVER_PACKET_H

//Dependencies
#include "sftp/sftp_server.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SFTP server related functions
error_t sftpServerParseFxpInit(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpOpen(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpClose(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpRead(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpWrite(SftpServerSession *session,
   const uint8_t *packet, size_t fragLen, size_t totalLen);

error_t sftpServerParseFxpOpenDir(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpReadDir(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpRemove(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpMkDir(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpRmDir(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpRealPath(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpStat(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpFstat(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpSetStat(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpSetFstat(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpRename(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpServerParseFxpExtended(SftpServerSession *session,
   const uint8_t *packet, size_t length);

error_t sftpFormatFxpVersion(SftpServerSession *session, uint32_t version);

error_t sftpFormatFxpStatus(SftpServerSession *session, uint32_t id,
   uint32_t statusCode, const char_t *message);

error_t sftpFormatFxpHandle(SftpServerSession *session, uint32_t id,
   uint32_t handle);

error_t sftpFormatFxpData(SftpServerSession *session, uint32_t id,
   size_t dataLen);

error_t sftpFormatFxpName(SftpServerSession *session, uint32_t id,
   const SftpName *name);

error_t sftpFormatFxpAttrs(SftpServerSession *session, uint32_t id,
   const SftpFileAttrs *attributes);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
