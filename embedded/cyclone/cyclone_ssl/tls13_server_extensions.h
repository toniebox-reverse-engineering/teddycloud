/**
 * @file tls13_server_extensions.h
 * @brief Formatting and parsing of extensions (TLS 1.3 server)
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

#ifndef _TLS13_SERVER_EXTENSIONS_H
#define _TLS13_SERVER_EXTENSIONS_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS 1.3 server specific functions
error_t tls13FormatServerSupportedVersionsExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tls13FormatSelectedGroupExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tls13FormatServerKeyShareExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tls13FormatServerPreSharedKeyExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tls13FormatServerEarlyDataExtension(TlsContext *context,
   TlsMessageType msgType, uint8_t *p, size_t *written);

error_t tls13ParseClientKeyShareExtension(TlsContext *context,
   const Tls13KeyShareList *keyShareList);

error_t tls13ParsePskKeModesExtension(TlsContext *context,
   const Tls13PskKeModeList *pskKeModeList);

error_t tls13ParseClientPreSharedKeyExtension(TlsContext *context,
   const TlsClientHello *clientHello, size_t clientHelloLen,
   const Tls13PskIdentityList *identityList, const Tls13PskBinderList *binderList);

error_t tls13ParseClientEarlyDataExtension(TlsContext *context,
   const TlsExtension *earlyDataIndication);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
