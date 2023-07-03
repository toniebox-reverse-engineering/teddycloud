/**
 * @file tls_signature.h
 * @brief RSA/DSA/ECDSA/EdDSA signature generation and verification (TLS 1.3)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSL Open.
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

#ifndef _TLS_SIGNATURE_H
#define _TLS_SIGNATURE_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS related functions
error_t tlsSelectSignatureScheme(TlsContext *context, const TlsCertDesc *cert,
   const TlsSignHashAlgos *supportedSignAlgos);

error_t tlsGenerateSignature(TlsContext *context, uint8_t *p,
   size_t *length);

error_t tlsVerifySignature(TlsContext *context, const uint8_t *p,
   size_t length);

error_t tls12GenerateSignature(TlsContext *context, uint8_t *p,
   size_t *length);

error_t tls12VerifySignature(TlsContext *context, const uint8_t *p,
   size_t length);

error_t tlsGenerateRsaSignature(const RsaPrivateKey *key,
   const uint8_t *digest, uint8_t *signature, size_t *signatureLen);

error_t tlsVerifyRsaSignature(const RsaPublicKey *key,
   const uint8_t *digest, const uint8_t *signature, size_t signatureLen);

error_t tlsVerifyRsaEm(const uint8_t *digest, const uint8_t *em, size_t emLen);

error_t tlsGenerateDsaSignature(TlsContext *context, const uint8_t *digest,
   size_t digestLen, uint8_t *signature, size_t *signatureLen);

error_t tlsVerifyDsaSignature(TlsContext *context, const uint8_t *digest,
   size_t digestLen, const uint8_t *signature, size_t signatureLen);

error_t tlsGenerateEcdsaSignature(TlsContext *context, const uint8_t *digest,
   size_t digestLen, uint8_t *signature, size_t *signatureLen);

error_t tlsVerifyEcdsaSignature(TlsContext *context, const uint8_t *digest,
   size_t digestLen, const uint8_t *signature, size_t signatureLen);

error_t tlsGenerateEddsaSignature(TlsContext *context,
   const EddsaMessageChunk *messageChunks, uint8_t *signature,
   size_t *signatureLen);

error_t tlsVerifyEddsaSignature(TlsContext *context,
   const EddsaMessageChunk *messageChunks, const uint8_t *signature,
   size_t signatureLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
