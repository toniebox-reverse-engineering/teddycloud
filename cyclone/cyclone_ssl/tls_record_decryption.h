/**
 * @file tls_record_decryption.h
 * @brief TLS record decryption
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

#ifndef _TLS_RECORD_DECRYPTION_H
#define _TLS_RECORD_DECRYPTION_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS related functions
error_t tlsDecryptRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record);

error_t tlsDecryptAeadRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record);

error_t tlsDecryptCbcRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record);

error_t tlsDecryptStreamRecord(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record);

error_t tlsVerifyMessageAuthCode(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, void *record);

uint32_t tlsVerifyPadding(const uint8_t *data, size_t dataLen,
   size_t *paddingLen);

uint32_t tlsVerifyMac(TlsContext *context,
   TlsEncryptionEngine *decryptionEngine, const void *record,
   const uint8_t *data, size_t dataLen, size_t maxDataLen, const uint8_t *mac);

uint32_t tlsExtractMac(TlsEncryptionEngine *decryptionEngine,
   const uint8_t *data, size_t dataLen, size_t maxDataLen, uint8_t *mac);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
