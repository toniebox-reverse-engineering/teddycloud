/**
 * @file pkcs8_key_format.h
 * @brief PKCS #8 key formatting
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

#ifndef _PKCS8_KEY_FORMAT_H
#define _PKCS8_KEY_FORMAT_H

//Dependencies
#include "core/crypto.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ec.h"
#include "ecc/eddsa.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Key formatting functions
error_t pkcs8FormatRsaPrivateKey(const RsaPrivateKey *privateKey,
   uint8_t *output, size_t *written);

error_t pkcs8FormatDsaPrivateKey(const DsaPrivateKey *privateKey,
   uint8_t *output, size_t *written);

error_t pkcs8FormatEcPrivateKey(const EcCurveInfo *curveInfo,
   const EcPrivateKey *privateKey, const EcPublicKey *publicKey,
   uint8_t *output, size_t *written);

error_t pkcs8FormatEcPublicKey(const EcCurveInfo *curveInfo,
   const EcPublicKey *publicKey, uint8_t *output, size_t *written);

error_t pkcs8FormatEddsaPrivateKey(const EcCurveInfo *curveInfo,
   const EddsaPrivateKey *privateKey, uint8_t *output, size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
