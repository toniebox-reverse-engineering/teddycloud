/**
 * @file ssh_key_material.h
 * @brief Key material generation
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

#ifndef _SSH_KEY_MATERIAL_H
#define _SSH_KEY_MATERIAL_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
error_t sshInitEncryptionEngine(SshConnection *connection,
   SshEncryptionEngine *encryptionEngine, const char_t *encAlgo,
   const char_t *macAlgo, uint8_t x);

void sshFreeEncryptionEngine(SshEncryptionEngine *encryptionEngine);

error_t sshSelectCipherAlgo(SshEncryptionEngine *encryptionEngine,
   const char_t *encAlgo);

error_t sshSelectHashAlgo(SshEncryptionEngine *encryptionEngine,
   const char_t *encAlgo, const char_t *macAlgo);

error_t sshDeriveKey(SshConnection *connection, uint8_t x, uint8_t *output,
   size_t outputLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
