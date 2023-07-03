/**
 * @file ssh_auth_public_key.h
 * @brief Public key authentication method
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

#ifndef _SSH_AUTH_PUBLIC_KEY_H
#define _SSH_AUTH_PUBLIC_KEY_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
error_t sshSendUserAuthPkOk(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKey);

error_t sshFormatPublicKeyAuthParams(SshConnection *connection,
   const uint8_t *message, size_t messageLen, uint8_t *p, size_t *written);

error_t sshFormatUserAuthPkOk(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKey,
   uint8_t *p, size_t *length);

error_t sshParsePublicKeyAuthParams(SshConnection *connection,
   const SshString *userName, const uint8_t *message, const uint8_t *p,
   size_t length);

error_t sshParseUserAuthPkOk(SshConnection *connection,
   const uint8_t *message, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
