/**
 * @file sftp_client_packet.h
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

#ifndef _SFTP_CLIENT_PACKET_H
#define _SFTP_CLIENT_PACKET_H

//Dependencies
#include "sftp/sftp_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SFTP client related functions
error_t sftpClientFormatFxpInit(SftpClientContext *context,
   uint32_t version);

error_t sftpClientFormatFxpOpen(SftpClientContext *context,
   const char_t *filename, uint32_t pflags);

error_t sftpClientFormatFxpClose(SftpClientContext *context,
   const uint8_t *handle, size_t handleLen);

error_t sftpClientFormatFxpRead(SftpClientContext *context,
   const uint8_t *handle, size_t handleLen, uint64_t offset, uint32_t dataLen);

error_t sftpClientFormatFxpWrite(SftpClientContext *context,
   const uint8_t *handle, size_t handleLen, uint64_t offset, uint32_t dataLen);

error_t sftpClientFormatFxpOpenDir(SftpClientContext *context,
   const char_t *path);

error_t sftpClientFormatFxpReadDir(SftpClientContext *context,
   const uint8_t *handle, size_t handleLen);

error_t sftpClientFormatFxpRemove(SftpClientContext *context,
   const char_t *filename);

error_t sftpClientFormatFxpMkDir(SftpClientContext *context,
   const char_t *path);

error_t sftpClientFormatFxpRmDir(SftpClientContext *context,
   const char_t *path);

error_t sftpClientFormatFxpRealPath(SftpClientContext *context,
   const char_t *path);

error_t sftpClientFormatFxpStat(SftpClientContext *context,
   const char_t *path);

error_t sftpClientFormatFxpRename(SftpClientContext *context,
   const char_t *oldPath, const char_t *newPath);

error_t sftpClientParseFxpVersion(SftpClientContext *context,
   const uint8_t *packet, size_t length);

error_t sftpClientParseFxpStatus(SftpClientContext *context,
   const uint8_t *packet, size_t length);

error_t sftpClientParseFxpHandle(SftpClientContext *context,
   const uint8_t *packet, size_t length);

error_t sftpClientParseFxpData(SftpClientContext *context,
   const uint8_t *packet, size_t fragLen, size_t totalLen);

error_t sftpClientParseFxpName(SftpClientContext *context,
   const uint8_t *packet, size_t fragLen, size_t totalLen);

error_t sftpClientParseFxpAttrs(SftpClientContext *context,
   const uint8_t *packet, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
