/**
 * @file x509_csr_create.h
 * @brief CSR (Certificate Signing Request) generation
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

#ifndef _X509_CSR_CREATE_H
#define _X509_CSR_CREATE_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//CSR related functions
error_t x509CreateCsr(const PrngAlgo *prngAlgo, void *prngContext,
   const X509CertRequestInfo *certReqInfo, const void *subjectPublicKey,
   const X509SignatureAlgoId *signatureAlgo, const void *signerPrivateKey,
   uint8_t *output, size_t *written);

error_t x509FormatCertRequestInfo(const X509CertRequestInfo *certReqInfo,
   const void *publicKey, uint8_t *output, size_t *written);

error_t x509FormatAttributes(const X509Attributes *attributes,
   uint8_t *output, size_t *written);

error_t x509FormatChallengePassword(const X509ChallengePassword *challengePwd,
   uint8_t *output, size_t *written);

error_t x509FormatExtensionRequest(const X509Extensions *extensionReq,
   uint8_t *output, size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
