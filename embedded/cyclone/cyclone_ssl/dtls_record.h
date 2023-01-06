/**
 * @file dtls_record.h
 * @brief DTLS record protocol
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

#ifndef _DTLS_RECORD_H
#define _DTLS_RECORD_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//DTLS related functions
error_t dtlsWriteProtocolData(TlsContext *context,
   const uint8_t *data, size_t length, TlsContentType contentType);

error_t dtlsReadProtocolData(TlsContext *context,
   uint8_t **data, size_t *length, TlsContentType *contentType);

error_t dtlsWriteRecord(TlsContext *context, const uint8_t *data,
   size_t length, TlsContentType contentType);

error_t dtlsReadRecord(TlsContext *context);
error_t dtlsProcessRecord(TlsContext *context);

error_t dtlsSendFlight(TlsContext *context);

error_t dtlsFragmentHandshakeMessage(TlsContext *context, uint16_t version,
   TlsEncryptionEngine *encryptionEngine, const DtlsHandshake *message);

error_t dtlsReassembleHandshakeMessage(TlsContext *context,
   const DtlsHandshake *message);

error_t dtlsReadDatagram(TlsContext *context, uint8_t *data,
   size_t size, size_t *length);

error_t dtlsTick(TlsContext *context);

void dtlsIncSequenceNumber(DtlsSequenceNumber *seqNum);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
