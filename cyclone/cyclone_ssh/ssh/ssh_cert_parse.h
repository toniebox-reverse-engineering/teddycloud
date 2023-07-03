/**
 * @file ssh_cert_parse.h
 * @brief SSH certificate parsing
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

#ifndef _SSH_CERT_PARSE_H
#define _SSH_CERT_PARSE_H

//Dependencies
#include "ssh_types.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SSH certificate types
 **/

typedef enum
{
   SSH_CERT_TYPE_USER = 1,
   SSH_CERT_TYPE_HOST = 2
} SshCertType;


/**
 * @brief RSA public key
 **/

typedef struct
{
   SshBinaryString e;
   SshBinaryString n;
} SshRsaCertPublicKey;


/**
 * @brief DSA public key
 **/

typedef struct
{
   SshBinaryString p;
   SshBinaryString q;
   SshBinaryString g;
   SshBinaryString y;
} SshDsaCertPublicKey;


/**
 * @brief ECDSA public key
 **/

typedef struct
{
   SshString curveName;
   SshBinaryString q;
} SshEcdsaCertPublicKey;


/**
 * @brief Ed25519 public key
 **/

typedef struct
{
   SshBinaryString q;
} SshEd25519CertPublicKey;


/**
 * @brief Public key
 **/

typedef union
{
   SshRsaCertPublicKey rsaPublicKey;
   SshDsaCertPublicKey dsaPublicKey;
   SshEcdsaCertPublicKey ecdsaPublicKey;
   SshEd25519CertPublicKey ed25519PublicKey;
} SshCertPublicKey;


/**
 * @brief SSH certificate (OpenSSH format)
 **/

typedef struct
{
   SshString keyFormatId;
   SshBinaryString nonce;
   SshCertPublicKey publicKey;
   uint64_t serial;
   uint32_t type;
   SshString keyId;
   SshBinaryString validPrincipals;
   uint64_t validAfter;
   uint64_t validBefore;
   SshBinaryString criticalOptions;
   SshBinaryString extensions;
   SshBinaryString reserved;
   SshBinaryString signatureKey;
   SshBinaryString signature;
} SshCertificate;


//SSH certificate parsing functions
error_t sshParseCertificate(const uint8_t *data, size_t length,
   SshCertificate *cert);

error_t sshParseRsaCertPublicKey(const uint8_t *data, size_t length,
   size_t *consumed, SshRsaCertPublicKey *publicKey);

error_t sshParseDsaCertPublicKey(const uint8_t *data, size_t length,
   size_t *consumed, SshDsaCertPublicKey *publicKey);

error_t sshParseEcdsaCertPublicKey(const uint8_t *data, size_t length,
   size_t *consumed, SshEcdsaCertPublicKey *publicKey);

error_t sshParseEd25519CertPublicKey(const uint8_t *data, size_t length,
   size_t *consumed, SshEd25519CertPublicKey *publicKey);

error_t sshParseValidPrincipals(const uint8_t *data, size_t length,
   SshBinaryString *validPrincipals);

error_t sshParseCriticalOptions(const uint8_t *data, size_t length,
   SshBinaryString *criticalOptions);

error_t sshParseExtensions(const uint8_t *data, size_t length,
   SshBinaryString *extensions);

bool_t sshGetValidPrincipal(const SshCertificate *cert, uint_t index,
   SshString *name);

bool_t sshGetCriticalOption(const SshCertificate *cert, uint_t index,
   SshString *name, SshBinaryString *data);

bool_t sshGetExtension(const SshCertificate *cert, uint_t index,
   SshString *name, SshBinaryString *data);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
