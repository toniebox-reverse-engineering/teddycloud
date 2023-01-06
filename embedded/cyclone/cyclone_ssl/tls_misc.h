/**
 * @file tls_misc.h
 * @brief TLS helper functions
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

#ifndef _TLS_MISC_H
#define _TLS_MISC_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS related functions
void tlsProcessError(TlsContext *context, error_t errorCode);

error_t tlsGenerateRandomValue(TlsContext *context, uint8_t *random);
error_t tlsGenerateSessionId(TlsContext *context, size_t length);

error_t tlsSelectVersion(TlsContext *context, uint16_t version);
error_t tlsSelectCipherSuite(TlsContext *context, uint16_t identifier);

error_t tlsSaveSessionId(const TlsContext *context,
   TlsSessionState *session);

error_t tlsSaveSessionTicket(const TlsContext *context,
   TlsSessionState *session);

error_t tlsRestoreSessionId(TlsContext *context,
   const TlsSessionState *session);

error_t tlsRestoreSessionTicket(TlsContext *context,
   const TlsSessionState *session);

error_t tlsInitEncryptionEngine(TlsContext *context,
   TlsEncryptionEngine *encryptionEngine, TlsConnectionEnd entity,
   const uint8_t *secret);

void tlsFreeEncryptionEngine(TlsEncryptionEngine *encryptionEngine);

error_t tlsWriteMpi(const Mpi *a, uint8_t *data, size_t *length);
error_t tlsReadMpi(Mpi *a, const uint8_t *data, size_t size, size_t *length);

error_t tlsWriteEcPoint(const EcDomainParameters *params,
   const EcPoint *a, uint8_t *data, size_t *length);

error_t tlsReadEcPoint(const EcDomainParameters *params,
   EcPoint *a, const uint8_t *data, size_t size, size_t *length);

const char_t *tlsGetVersionName(uint16_t version);
const HashAlgo *tlsGetHashAlgo(uint8_t hashAlgoId);
const EcCurveInfo *tlsGetCurveInfo(TlsContext *context, uint16_t namedCurve);
TlsNamedGroup tlsGetNamedCurve(const uint8_t *oid, size_t length);

size_t tlsComputeEncryptionOverhead(TlsEncryptionEngine *encryptionEngine,
   size_t payloadLen);

bool_t tlsCheckDnsHostname(const char_t *name, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
