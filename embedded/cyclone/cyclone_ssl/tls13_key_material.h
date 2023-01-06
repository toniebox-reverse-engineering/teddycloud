/**
 * @file tls13_key_material.h
 * @brief TLS 1.3 key schedule
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

#ifndef _TLS13_KEY_MATERIAL_H
#define _TLS13_KEY_MATERIAL_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS 1.3 related functions
error_t tls13HkdfExpandLabel(TlsTransportProtocol transportProtocol,
   const HashAlgo *hash, const uint8_t *secret, size_t secretLen,
   const char_t *label, const uint8_t *context, size_t contextLen,
   uint8_t *output, size_t outputLen);

error_t tls13DeriveSecret(TlsContext *context, const uint8_t *secret,
   size_t secretLen, const char_t *label, const char_t *message,
   size_t messageLen, uint8_t *output, size_t outputLen);

error_t tls13GenerateEarlyTrafficKeys(TlsContext *context);
error_t tls13GenerateHandshakeTrafficKeys(TlsContext *context);
error_t tls13GenerateServerAppTrafficKeys(TlsContext *context);
error_t tls13GenerateClientAppTrafficKeys(TlsContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
