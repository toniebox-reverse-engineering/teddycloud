/**
 * @file sftp_server_directory.h
 * @brief Directory operations
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

#ifndef _SFTP_SERVER_DIRECTORY_H
#define _SFTP_SERVER_DIRECTORY_H

//Dependencies
#include "sftp/sftp_server.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SFTP server related functions
error_t sftpServerCreateDir(SftpServerSession *session,
   const SshString *path, const SftpFileAttrs *attributes);

error_t sftpServerRemoveDir(SftpServerSession *session,
   const SshString *path);

error_t sftpServerOpenDir(SftpServerSession *session,
   const SshString *path, uint32_t *handle);

error_t sftpServerReadDir(SftpServerSession *session,
   const SshBinaryString *handle, SftpName *name);

error_t sftpServerCloseDir(SftpServerSession *session,
   const SshBinaryString *handle);

SftpFileObject *sftpServerFindDir(SftpServerSession *session,
   const SshBinaryString *handle);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
