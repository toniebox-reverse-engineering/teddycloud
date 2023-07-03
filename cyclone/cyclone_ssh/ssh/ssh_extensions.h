/**
 * @file ssh_extensions.h
 * @brief SSH extension negotiation
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

#ifndef _SSH_EXTENSIONS_H
#define _SSH_EXTENSIONS_H

//Dependencies
#include "ssh/ssh.h"

//Minimum size of SSH_MSG_EXT_INFO message
#define SSH_MSG_EXT_INFO_MIN_SIZE 5

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
error_t sshSendExtInfo(SshConnection *connection);

error_t sshFormatExtInfo(SshConnection *connection, uint8_t *message,
   size_t *length);

error_t sshFormatServerSigAlgsExt(SshConnection *connection, uint8_t *p,
   size_t *written);

error_t sshFormatGlobalRequestsOkExt(SshConnection *connection, uint8_t *p,
   size_t *written);

error_t sshParseExtInfo(SshConnection *connection, const uint8_t *message,
   size_t length);

error_t sshParseServerSigAlgsExt(SshConnection *connection, const char_t *p,
   size_t length);

error_t sshParseGlobalRequestsOkExt(SshConnection *connection, const char_t *p,
   size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
