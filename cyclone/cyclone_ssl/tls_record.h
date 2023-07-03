/**
 * @file tls_record.h
 * @brief TLS record protocol
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

#ifndef _TLS_RECORD_H
#define _TLS_RECORD_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS related functions
error_t tlsWriteProtocolData(TlsContext *context,
   const uint8_t *data, size_t length, TlsContentType contentType);

error_t tlsReadProtocolData(TlsContext *context,
   uint8_t **data, size_t *length, TlsContentType *contentType);

error_t tlsWriteRecord(TlsContext *context, const uint8_t *data,
   size_t length, TlsContentType contentType);

error_t tlsReadRecord(TlsContext *context, uint8_t *data,
   size_t size, size_t *length, TlsContentType *contentType);

error_t tlsProcessRecord(TlsContext *context, TlsRecord *record);

void tlsSetRecordType(TlsContext *context, void *record, uint8_t type);
uint8_t tlsGetRecordType(TlsContext *context, void *record);
void tlsSetRecordLength(TlsContext *context, void *record, size_t length);
size_t tlsGetRecordLength(TlsContext *context, void *record);
uint8_t *tlsGetRecordData(TlsContext *context, void *record);

void tlsFormatAad(TlsContext *context, TlsEncryptionEngine *encryptionEngine,
   const void *record, uint8_t *aad, size_t *aadLen);

void tlsFormatNonce(TlsContext *context, TlsEncryptionEngine *encryptionEngine,
   const void *record, const uint8_t *recordIv, uint8_t *nonce, size_t *nonceLen);

void tlsIncSequenceNumber(TlsSequenceNumber *seqNum);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
