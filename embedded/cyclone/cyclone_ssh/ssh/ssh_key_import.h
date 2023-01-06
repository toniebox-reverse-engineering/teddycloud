/**
 * @file ssh_key_import.h
 * @brief SSH key file import functions
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

#ifndef _SSH_KEY_IMPORT_H
#define _SSH_KEY_IMPORT_H

//Dependencies
#include "ssh_types.h"
#include "ssh_key_parse.h"
#include "pkix/x509_common.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ec.h"
#include "ecc/eddsa.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SSH key type
 **/

typedef struct
{
   const char_t *identifier;
   X509KeyType type;
   const char_t *curveName;
} SshKeyType;


//SSH key file import functions
error_t sshImportRsaPublicKey(const char_t *input, size_t length,
   RsaPublicKey *publicKey);

error_t sshImportDsaPublicKey(const char_t *input, size_t length,
   DsaPublicKey *publicKey);

error_t sshImportEcdsaPublicKey(const char_t *input, size_t length,
   EcDomainParameters *params, EcPublicKey *publicKey);

error_t sshImportEd25519PublicKey(const char_t *input, size_t length,
   EddsaPublicKey *publicKey);

error_t sshImportEd448PublicKey(const char_t *input, size_t length,
   EddsaPublicKey *publicKey);

error_t sshImportRsaPrivateKey(const char_t *input, size_t length,
   RsaPrivateKey *privateKey);

error_t sshImportDsaPrivateKey(const char_t *input, size_t length,
   DsaPrivateKey *privateKey);

error_t sshImportEcdsaPrivateKey(const char_t *input, size_t length,
   EcPrivateKey *privateKey);

error_t sshImportEd25519PrivateKey(const char_t *input, size_t length,
   EddsaPrivateKey *privateKey);

error_t sshImportEd448PrivateKey(const char_t *input, size_t length,
   EddsaPrivateKey *privateKey);

error_t sshImportRsaHostKey(const SshRsaHostKey *hostKey,
   RsaPublicKey *publicKey);

error_t sshImportDsaHostKey(const SshDsaHostKey *hostKey,
   DsaPublicKey *publicKey);

error_t sshImportEcdsaHostKey(const SshEcdsaHostKey *hostKey,
   EcDomainParameters *params, EcPublicKey *publicKey);

error_t sshImportEd25519HostKey(const SshEddsaHostKey *hostKey,
   EddsaPublicKey *publicKey);

error_t sshImportEd448HostKey(const SshEddsaHostKey *hostKey,
   EddsaPublicKey *publicKey);

const char_t *sshGetPublicKeyType(const char_t *input, size_t length);

error_t sshDecodePublicKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen);

error_t sshDecodeSsh2PublicKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen);

error_t sshDecodeOpenSshPublicKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen);

error_t sshDecodeOpenSshPrivateKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen);

int_t sshSearchMarker(const char_t *s, size_t sLen, const char_t *marker,
   size_t markerLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
