/**
 * @file acme_client_misc.h
 * @brief Helper functions for ACME client
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

#ifndef _ACME_CLIENT_MISC_H
#define _ACME_CLIENT_MISC_H

//Dependencies
#include "acme/acme_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//ACME client related functions
error_t acmeClientLoadKeyPair(AcmeKeyPair *keyPair, const char_t *publicKey,
   size_t publicKeyLen, const char_t *privateKey, size_t privateKeyLen);

void acmeClientUnloadKeyPair(AcmeKeyPair *keyPair);

error_t acmeClientSendRequest(AcmeClientContext *context);

error_t acmeClientFormatRequestHeader(AcmeClientContext *context,
   const char_t *method, const char_t *url);

error_t acmeClientFormatJwsProtectedHeader(const AcmeKeyPair *keyPair,
   const char_t *kid, const char_t *nonce, const char_t *url,
   char_t *buffer, size_t *written);

error_t acmeClientFormatJwk(const AcmeKeyPair *keyPair, char_t *buffer,
   size_t *written, bool_t sort);

error_t acmeClientGenerateCsr(AcmeClientContext *context, uint8_t *buffer,
   size_t *written);

error_t acmeClientParseResponseHeader(AcmeClientContext *context);
error_t acmeClientParseProblemDetails(AcmeClientContext *context);

const char_t *acmeClientGetPath(const char_t *url);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
