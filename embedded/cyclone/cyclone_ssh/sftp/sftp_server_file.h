/**
 * @file sftp_server_file.h
 * @brief File operations
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

#ifndef _SFTP_SERVER_FILE_H
#define _SFTP_SERVER_FILE_H

//Dependencies
#include "sftp/sftp_server.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SFTP server related functions
error_t sftpServerGetRealPath(SftpServerSession *session,
   const SshString *path, SftpName *name);

error_t sftpServerGetFileStat(SftpServerSession *session,
   const SshString *path, SftpFileAttrs *attributes);

error_t sftpServerGetFileStatEx(SftpServerSession *session,
   const SshBinaryString *handle, SftpFileAttrs *attributes);

error_t sftpServerSetFileStat(SftpServerSession *session,
   const SshString *path, const SftpFileAttrs *attributes);

error_t sftpServerSetFileStatEx(SftpServerSession *session,
   const SshBinaryString *handle, const SftpFileAttrs *attributes);

error_t sftpServerRemoveFile(SftpServerSession *session,
   const SshString *path);

error_t sftpServerRenameFile(SftpServerSession *session,
   const SshString *oldPath, const SshString *newPath);

error_t sftpServerOpenFile(SftpServerSession *session, const SshString *path,
   uint32_t pflags, const SftpFileAttrs *attributes, uint32_t *handle);

error_t sftpServerWriteFile(SftpServerSession *session,
   const SshBinaryString *handle, uint64_t offset, const uint8_t *data,
   uint32_t fragLen, uint32_t totalLen);

error_t sftpServerWriteData(SftpServerSession *session);

error_t sftpServerReadFile(SftpServerSession *session,
   const SshBinaryString *handle, uint64_t offset, uint32_t *length);

error_t sftpServerReadData(SftpServerSession *session);

error_t sftpServerCloseFile(SftpServerSession *session,
   const SshBinaryString *handle);

SftpFileObject *sftpServerFindFile(SftpServerSession *session,
   const SshBinaryString *handle);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
