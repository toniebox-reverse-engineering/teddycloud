/**
 * @file x509_key_format.h
 * @brief Formatting of ASN.1 encoded keys
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

#ifndef _X509_KEY_FORMAT_H
#define _X509_KEY_FORMAT_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Key formatting functions
error_t x509FormatSubjectPublicKeyInfo(const X509SubjectPublicKeyInfo *publicKeyInfo,
   const void *publicKey, uint8_t *keyId, uint8_t *output, size_t *written);

error_t x509FormatAlgorithmIdentifier(const X509SubjectPublicKeyInfo *publicKeyInfo,
   const void *params, uint8_t *output, size_t *written);

error_t x509FormatRsaPublicKey(const X509RsaPublicKey *rsaPublicKey,
   uint8_t *output, size_t *written);

error_t x509FormatRsaPssParameters(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written);

error_t x509FormatRsaPssHashAlgo(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written);

error_t x509FormatRsaPssMaskGenAlgo(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written);

error_t x509FormatRsaPssMaskGenHashAlgo(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written);

error_t x509FormatRsaPssSaltLength(const X509RsaPssParameters *rsaPssParams,
   uint8_t *output, size_t *written);

error_t x509FormatDsaPublicKey(const X509DsaPublicKey *dsaPublicKey,
   uint8_t *output, size_t *written);

error_t x509FormatDsaParameters(const X509DsaParameters *dsaParams,
   uint8_t *output, size_t *written);

error_t x509FormatEcPublicKey(const X509EcPublicKey *ecPublicKey,
   uint8_t *output, size_t *written);

error_t x509FormatEcParameters(const X509EcParameters *ecParams,
   uint8_t *output, size_t *written);

error_t x509ExportRsaPublicKey(const RsaPublicKey *publicKey,
   uint8_t *output, size_t *written);

error_t x509ExportRsaPrivateKey(const RsaPrivateKey *privateKey,
   uint8_t *output, size_t *written);

error_t x509ExportDsaPublicKey(const DsaPublicKey *publicKey,
   uint8_t *output, size_t *written);

error_t x509ExportDsaPrivateKey(const DsaPrivateKey *privateKey,
   uint8_t *output, size_t *written);

error_t x509ExportDsaParameters(const DsaDomainParameters *params,
   uint8_t *output, size_t *written);

error_t x509ExportEcPublicKey(const X509SubjectPublicKeyInfo *publicKeyInfo,
   const EcPoint *publicKey, uint8_t *output, size_t *written);

error_t x509ExportEddsaPublicKey(const EddsaPublicKey *publicKey,
   size_t publicKeyLen, uint8_t *output, size_t *written);

error_t x509ExportEddsaPrivateKey(const EddsaPrivateKey *privateKey,
   size_t privateKeyLen, uint8_t *output, size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
