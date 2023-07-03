/**
 * @file tls_server_misc.h
 * @brief Helper functions for TLS server
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

#ifndef _TLS_SERVER_MISC_H
#define _TLS_SERVER_MISC_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS server specific functions
error_t tlsFormatPskIdentityHint(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerKeyParams(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsGenerateServerKeySignature(TlsContext *context,
   TlsDigitalSignature *signature, const uint8_t *params,
   size_t paramsLen, size_t *written);

error_t tls12GenerateServerKeySignature(TlsContext *context,
   Tls12DigitalSignature *signature, const uint8_t *params,
   size_t paramsLen, size_t *written);

error_t tlsCheckSignalingCipherSuiteValues(TlsContext *context,
   const TlsCipherSuites *cipherSuites);

error_t tlsResumeStatefulSession(TlsContext *context, const uint8_t *sessionId,
   size_t sessionIdLen, const TlsCipherSuites *cipherSuites,
   const TlsHelloExtensions *extensions);

error_t tlsResumeStatelessSession(TlsContext *context, const uint8_t *sessionId,
   size_t sessionIdLen, const TlsCipherSuites *cipherSuites,
   const TlsHelloExtensions *extensions);

error_t tlsNegotiateVersion(TlsContext *context, uint16_t clientVersion,
   const TlsSupportedVersionList *supportedVersionList);

error_t tlsNegotiateCipherSuite(TlsContext *context, const HashAlgo *hashAlgo,
   const TlsCipherSuites *cipherSuites, TlsHelloExtensions *extensions);

error_t tlsSelectGroup(TlsContext *context,
   const TlsSupportedGroupList *groupList);

error_t tlsSelectEcdheGroup(TlsContext *context,
   const TlsSupportedGroupList *groupList);

error_t tlsSelectCertificate(TlsContext *context,
   const TlsHelloExtensions *extensions);

error_t tlsParseCompressMethods(TlsContext *context,
   const TlsCompressMethods *compressMethods);

error_t tlsParsePskIdentity(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed);

error_t tlsParseClientKeyParams(TlsContext *context,
   const uint8_t *p, size_t length, size_t *consumed);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
