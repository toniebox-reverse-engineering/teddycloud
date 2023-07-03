/**
 * @file ssh_exchange_hash.h
 * @brief Exchange hash calculation
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

#ifndef _SSH_EXCHANGE_HASH_H
#define _SSH_EXCHANGE_HASH_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
error_t sshInitExchangeHash(SshConnection *connection);

error_t sshUpdateExchangeHash(SshConnection *connection, const void *data,
   size_t length);

error_t sshFinalizeExchangeHash(SshConnection *connection, uint8_t *digest,
   size_t *digestLen);

error_t sshUpdateExchangeHashRaw(SshConnection *connection, const void *data,
   size_t length);

error_t sshGenerateExchangeHashSignature(SshConnection *connection,
   uint8_t *p, size_t *written);

error_t sshVerifyExchangeHashSignature(SshConnection *connection,
   const SshBinaryString *serverHostKey, const SshBinaryString *signature);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
