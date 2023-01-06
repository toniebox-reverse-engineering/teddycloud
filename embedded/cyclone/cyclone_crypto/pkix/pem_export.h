/**
 * @file pem_export.h
 * @brief PEM file export functions
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

#ifndef _PEM_EXPORT_H
#define _PEM_EXPORT_H

//Dependencies
#include "core/crypto.h"
#include "pkc/dh.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ec.h"
#include "ecc/eddsa.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PEM related functions
error_t pemExportCertificate(const uint8_t *cert, size_t certLen,
   char_t *output, size_t *written);

error_t pemExportCrl(const uint8_t *crl, size_t crlLen,
   char_t *output, size_t *written);

error_t pemExportCsr(const uint8_t *csr, size_t csrLen,
   char_t *output, size_t *written);

error_t pemExportRsaPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written);

error_t pemExportRsaPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written);

error_t pemExportRsaPssPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written);

error_t pemExportRsaPssPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written);

error_t pemExportDsaPublicKey(const DsaPublicKey *publicKey,
   char_t *output, size_t *written);

error_t pemExportDsaPrivateKey(const DsaPrivateKey *privateKey,
   char_t *output, size_t *written);

error_t pemExportEcParameters(const EcCurveInfo *curveInfo,
   char_t *output, size_t *written);

error_t pemExportEcPublicKey(const EcCurveInfo *curveInfo,
   const EcPublicKey *publicKey, char_t *output, size_t *written);

error_t pemExportEcPrivateKey(const EcCurveInfo *curveInfo,
   const EcPrivateKey *privateKey, const EcPublicKey *publicKey,
   char_t *output, size_t *written);

error_t pemExportEddsaPublicKey(const EcCurveInfo *curveInfo,
   const EddsaPublicKey *publicKey, char_t *output, size_t *written);

error_t pemExportEddsaPrivateKey(const EcCurveInfo *curveInfo,
   const EddsaPrivateKey *privateKey, char_t *output, size_t *written);

error_t pemEncodeFile(const void *input, size_t inputLen, const char_t *label,
   char_t *output, size_t *outputLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
