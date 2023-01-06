/**
 * @file tls_key_material.h
 * @brief Key material generation
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

#ifndef _TLS_KEY_MATERIAL_H
#define _TLS_KEY_MATERIAL_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS related functions
error_t tlsGenerateSessionKeys(TlsContext *context);
error_t tlsGenerateMasterSecret(TlsContext *context);
error_t tlsGenerateExtendedMasterSecret(TlsContext *context);
error_t tlsGeneratePskPremasterSecret(TlsContext *context);
error_t tlsGenerateKeyBlock(TlsContext *context, size_t keyBlockLen);

error_t tlsExportKeyingMaterial(TlsContext *context, const char_t *label,
   bool_t useContextValue, const uint8_t *contextValue,
   size_t contextValueLen, uint8_t *output, size_t outputLen);

error_t tlsPrf(const uint8_t *secret, size_t secretLen, const char_t *label,
   const uint8_t *seed, size_t seedLen, uint8_t *output, size_t outputLen);

error_t tls12Prf(const HashAlgo *hash, const uint8_t *secret, size_t secretLen,
   const char_t *label, const uint8_t *seed, size_t seedLen, uint8_t *output,
   size_t outputLen);

void tlsDumpSecret(TlsContext *context, const char_t *label,
   const uint8_t *secret, size_t secretLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
