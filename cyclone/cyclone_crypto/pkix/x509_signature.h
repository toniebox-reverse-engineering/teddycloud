/**
 * @file x509_signature.h
 * @brief RSA/DSA/ECDSA/EdDSA signature generation and verification
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
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

#ifndef _X509_SIGNATURE_H
#define _X509_SIGNATURE_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//Signature generation/verification callback functions
#ifndef X509_SIGN_CALLBACK_SUPPORT
   #define X509_SIGN_CALLBACK_SUPPORT DISABLED
#elif (X509_SIGN_CALLBACK_SUPPORT != ENABLED && X509_SIGN_CALLBACK_SUPPORT != DISABLED)
   #error X509_SIGN_CALLBACK_SUPPORT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Signature generation callback function
 **/

typedef error_t (*X509SignGenCallback)(const PrngAlgo *prngAlgo,
   void *prngContext, const uint8_t *tbsCert, size_t tbsCertLen,
   const X509SignatureAlgoId *signatureAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo, const void *privateKey,
   uint8_t *output, size_t *written);


/**
 * @brief Signature verification callback function
 **/

typedef error_t (*X509SignVerifyCallback)(const uint8_t *tbsCert,
   size_t tbsCertLen, const X509SignatureAlgoId *signatureAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue);


//X.509 related functions
error_t x509RegisterSignGenCallback(X509SignGenCallback callback);
error_t x509RegisterSignVerifyCallback(X509SignVerifyCallback callback);

error_t x509GenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *tbsCert, size_t tbsCertLen, const X509SignatureAlgoId *signatureAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo, const void *privateKey,
   uint8_t *output, size_t *written);

error_t x509GenerateRsaSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, const RsaPrivateKey *privateKey, uint8_t *output,
   size_t *written);

error_t x509GenerateRsaPssSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *tbsCert, size_t tbsCertLen, const HashAlgo *hashAlgo,
   size_t saltLen, const RsaPrivateKey *privateKey, uint8_t *output,
   size_t *written);

error_t x509GenerateDsaSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *tbsCert, size_t tbsCertLen, const HashAlgo *hashAlgo,
   const DsaPrivateKey *privateKey, uint8_t *output, size_t *written);

error_t x509GenerateEcdsaSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *tbsCert, size_t tbsCertLen, const HashAlgo *hashAlgo,
   const X509SubjectPublicKeyInfo *publicKeyInfo, const EcPrivateKey *privateKey,
   uint8_t *output, size_t *written);

error_t x509GenerateEd25519Signature(const uint8_t *tbsCert, size_t tbsCertLen,
   const EddsaPrivateKey *privateKey, uint8_t *output, size_t *written);

error_t x509GenerateEd448Signature(const uint8_t *tbsCert, size_t tbsCertLen,
   const EddsaPrivateKey *privateKey, uint8_t *output, size_t *written);

error_t x509VerifySignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const X509SignatureAlgoId *signatureAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue);

error_t x509VerifyRsaSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue);

error_t x509VerifyRsaPssSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, size_t saltLen,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue);

error_t x509VerifyDsaSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue);

error_t x509VerifyEcdsaSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue);

error_t x509VerifyEd25519Signature(const uint8_t *tbsCert, size_t tbsCertLen,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue);

error_t x509VerifyEd448Signature(const uint8_t *tbsCert, size_t tbsCertLen,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
