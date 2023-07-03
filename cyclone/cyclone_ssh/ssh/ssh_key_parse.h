/**
 * @file ssh_key_parse.h
 * @brief SSH key parsing
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

#ifndef _SSH_KEY_PARSE_H
#define _SSH_KEY_PARSE_H

//Dependencies
#include "ssh_types.h"

//Magic identifier size
#define SSH_AUTH_MAGIC_SIZE 15


//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RSA host key
 **/

typedef struct
{
   SshString keyFormatId;
   SshBinaryString e;
   SshBinaryString n;
} SshRsaHostKey;


/**
 * @brief DSA host key
 **/

typedef struct
{
   SshString keyFormatId;
   SshBinaryString p;
   SshBinaryString q;
   SshBinaryString g;
   SshBinaryString y;
} SshDsaHostKey;


/**
 * @brief ECDSA host key
 **/

typedef struct
{
   SshString keyFormatId;
   SshString curveName;
   SshBinaryString q;
} SshEcdsaHostKey;


/**
 * @brief EdDSA host key
 **/

typedef struct
{
   SshString keyFormatId;
   SshBinaryString q;
} SshEddsaHostKey;


/**
 * @brief Private key header (OpenSSH format)
 **/

typedef struct
{
   SshString cipherName;
   SshString kdfName;
   SshBinaryString kdfOptions;
   uint32_t numKeys;
   SshBinaryString publicKey;
   SshBinaryString encrypted;
} SshPrivateKeyHeader;


/**
 * @brief RSA private key (OpenSSH format)
 **/

typedef struct
{
   uint32_t checkInt1;
   uint32_t checkInt2;
   SshString keyFormatId;
   SshBinaryString n;
   SshBinaryString e;
   SshBinaryString d;
   SshBinaryString qinv;
   SshBinaryString p;
   SshBinaryString q;
   SshString comment;
} SshRsaPrivateKey;


/**
 * @brief DSA private key (OpenSSH format)
 **/

typedef struct
{
   uint32_t checkInt1;
   uint32_t checkInt2;
   SshString keyFormatId;
   SshBinaryString p;
   SshBinaryString q;
   SshBinaryString g;
   SshBinaryString y;
   SshBinaryString x;
   SshString comment;
} SshDsaPrivateKey;


/**
 * @brief ECDSA private key (OpenSSH format)
 **/

typedef struct
{
   uint32_t checkInt1;
   uint32_t checkInt2;
   SshString keyFormatId;
   SshString curveName;
   SshBinaryString q;
   SshBinaryString d;
   SshString comment;
} SshEcdsaPrivateKey;


/**
 * @brief EdDSA private key (OpenSSH format)
 **/

typedef struct
{
   uint32_t checkInt1;
   uint32_t checkInt2;
   SshString keyFormatId;
   SshBinaryString q;
   SshBinaryString d;
   SshString comment;
} SshEddsaPrivateKey;


//SSH key parsing functions
error_t sshParseHostKey(const uint8_t *data, size_t length,
   SshString *keyFormatId);

error_t sshParseRsaHostKey(const uint8_t *data, size_t length,
   SshRsaHostKey *hostKey);

error_t sshParseDsaHostKey(const uint8_t *data, size_t length,
   SshDsaHostKey *hostKey);

error_t sshParseEcdsaHostKey(const uint8_t *data, size_t length,
   SshEcdsaHostKey *hostKey);

error_t sshParseEd25519HostKey(const uint8_t *data, size_t length,
   SshEddsaHostKey *hostKey);

error_t sshParseEd448HostKey(const uint8_t *data, size_t length,
   SshEddsaHostKey *hostKey);

error_t sshParseOpenSshPrivateKeyHeader(const uint8_t *data, size_t length,
   SshPrivateKeyHeader *privateKeyHeader);

error_t sshParseOpenSshRsaPrivateKey(const uint8_t *data, size_t length,
   SshRsaPrivateKey *privateKey);

error_t sshParseOpenSshDsaPrivateKey(const uint8_t *data, size_t length,
   SshDsaPrivateKey *privateKey);

error_t sshParseOpenSshEcdsaPrivateKey(const uint8_t *data, size_t length,
   SshEcdsaPrivateKey *privateKey);

error_t sshParseOpenSshEd25519PrivateKey(const uint8_t *data, size_t length,
   SshEddsaPrivateKey *privateKey);

error_t sshParseOpenSshEd448PrivateKey(const uint8_t *data, size_t length,
   SshEddsaPrivateKey *privateKey);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
