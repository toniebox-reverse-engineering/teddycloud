/**
 * @file ssh_key_format.h
 * @brief SSH key formatting
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

#ifndef _SSH_KEY_FORMAT_H
#define _SSH_KEY_FORMAT_H

//Dependencies
#include "ssh_types.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ec.h"
#include "ecc/eddsa.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH key formatting functions
error_t sshFormatRsaPublicKey(const RsaPublicKey *publicKey,
   uint8_t *p, size_t *written);

error_t sshFormatDsaPublicKey(const DsaPublicKey *publicKey,
   uint8_t *p, size_t *written);

error_t sshFormatEcdsaPublicKey(const EcDomainParameters *params,
   const EcPublicKey *publicKey, uint8_t *p, size_t *written);

error_t sshFormatEd25519PublicKey(const EddsaPublicKey *publicKey,
   uint8_t *p, size_t *written);

error_t sshFormatEd448PublicKey(const EddsaPublicKey *publicKey,
   uint8_t *p, size_t *written);

error_t sshFormatOpenSshPrivateKeyHeader(uint8_t *p, size_t *written);

error_t sshFormatOpenSshRsaPrivateKey(const RsaPrivateKey *privateKey,
   uint8_t *p, size_t *written);

error_t sshFormatOpenSshDsaPrivateKey(const DsaPrivateKey *privateKey,
   const DsaPublicKey *publicKey, uint8_t *p, size_t *written);

error_t sshFormatOpenSshEcdsaPrivateKey(const EcDomainParameters *params,
   const EcPrivateKey *privateKey, const EcPublicKey *publicKey,
   uint8_t *p, size_t *written);

error_t sshFormatOpenSshEd25519PrivateKey(const EddsaPrivateKey *privateKey,
   const EddsaPublicKey *publicKey, uint8_t *p, size_t *written);

error_t sshFormatOpenSshEd448PrivateKey(const EddsaPrivateKey *privateKey,
   const EddsaPublicKey *publicKey, uint8_t *p, size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
