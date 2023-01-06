/**
 * @file acme_client_jose.h
 * @brief JOSE (JSON Object Signing and Encryption)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneACME Open.
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

#ifndef _ACME_CLIENT_JOSE_H
#define _ACME_CLIENT_JOSE_H

//Dependencies
#include "acme/acme_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//JOSE related functions
error_t jwkExportRsaPublicKey(const RsaPublicKey *publicKey, char_t *buffer,
   size_t *written, bool_t sort);

error_t jwkExportEcPublicKey(const EcDomainParameters *params,
   const EcPublicKey *publicKey, char_t *buffer, size_t *written, bool_t sort);

error_t jwkExportEddsaPublicKey(const char_t *crv,
   const EddsaPublicKey *publicKey, char_t *buffer, size_t *written,
   bool_t sort);

error_t jwsCreate(const PrngAlgo *prngAlgo, void *prngContext,
   const char_t *protected, const char_t *payload, const char_t *alg,
   const char_t *crv, const void *privateKey, char_t *buffer, size_t *written);

error_t jwsGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const char_t *alg, const char_t *crv, const void *privateKey,
   const char_t *input, size_t inputLen, uint8_t *output, size_t *outputLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
