/**
 * @file ssh_signature.h
 * @brief RSA/DSA/ECDSA/EdDSA signature generation and verification
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

#ifndef _SSH_SIGNATURE_H
#define _SSH_SIGNATURE_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ECDSA signature
 **/

typedef struct
{
   SshBinaryString r;
   SshBinaryString s;
} SshEcdsaSignature;


//SSH related functions
error_t sshGenerateSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written);

error_t sshGenerateRsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written);

error_t sshGenerateDsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written);

error_t sshGenerateEcdsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written);

error_t sshGenerateEd25519Signature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written);

error_t sshGenerateEd448Signature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written);

error_t sshVerifySignature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   const SshBinaryString *signature);

error_t sshVerifyRsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

error_t sshVerifyDsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

error_t sshVerifyEcdsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

error_t sshVerifyEd25519Signature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

error_t sshVerifyEd448Signature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

error_t sshFormatEcdsaSignature(const SshEcdsaSignature *signature,
   uint8_t *p, size_t *written);

error_t sshParseEcdsaSignature(const uint8_t *data, size_t length,
   SshEcdsaSignature *signature);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
