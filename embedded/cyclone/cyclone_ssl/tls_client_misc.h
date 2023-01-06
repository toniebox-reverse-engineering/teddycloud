/**
 * @file tls_client_misc.h
 * @brief Helper functions for TLS client
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

#ifndef _TLS_CLIENT_MISC_H
#define _TLS_CLIENT_MISC_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS client specific functions
error_t tlsFormatInitialClientHello(TlsContext *context);

error_t tlsFormatSessionId(TlsContext *context, uint8_t *p,
   size_t *written);

error_t tlsFormatCipherSuites(TlsContext *context, uint_t *cipherSuiteTypes,
   uint8_t *p, size_t *written);

error_t tlsFormatCompressMethods(TlsContext *context, uint8_t *p,
   size_t *written);

error_t tlsFormatPskIdentity(TlsContext *context, uint8_t *p,
   size_t *written);

error_t tlsFormatClientKeyParams(TlsContext *context, uint8_t *p,
   size_t *written);

error_t tlsParsePskIdentityHint(TlsContext *context, const uint8_t *p,
   size_t length, size_t *consumed);

error_t tlsParseServerKeyParams(TlsContext *context, const uint8_t *p,
   size_t length, size_t *consumed);

error_t tlsVerifyServerKeySignature(TlsContext *context,
   const TlsDigitalSignature *signature, size_t length,
   const uint8_t *params, size_t paramsLen, size_t *consumed);

error_t tls12VerifyServerKeySignature(TlsContext *context,
   const Tls12DigitalSignature *signature, size_t length,
   const uint8_t *params, size_t paramsLen, size_t *consumed);

error_t tlsSelectClientVersion(TlsContext *context,
   const TlsServerHello *message, const TlsHelloExtensions *extensions);

error_t tlsResumeSession(TlsContext *context, const uint8_t *sessionId,
   size_t sessionIdLen, uint16_t cipherSuite);

bool_t tlsIsTicketValid(TlsContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
