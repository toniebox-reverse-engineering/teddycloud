/**
 * @file tls_client.h
 * @brief Handshake message processing (TLS client)
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

#ifndef _TLS_CLIENT_H
#define _TLS_CLIENT_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS client specific functions
error_t tlsSendClientHello(TlsContext *context);
error_t tlsSendClientKeyExchange(TlsContext *context);

error_t tlsFormatClientHello(TlsContext *context,
   TlsClientHello *message, size_t *length);

error_t tlsFormatClientKeyExchange(TlsContext *context,
   TlsClientKeyExchange *message, size_t *length);

error_t tlsParseHelloRequest(TlsContext *context,
   const TlsHelloRequest *message, size_t length);

error_t tlsParseServerHello(TlsContext *context,
   const TlsServerHello *message, size_t length);

error_t tlsParseServerKeyExchange(TlsContext *context,
   const TlsServerKeyExchange *message, size_t length);

error_t tlsParseCertificateRequest(TlsContext *context,
   const TlsCertificateRequest *message, size_t length);

error_t tlsParseServerHelloDone(TlsContext *context,
   const TlsServerHelloDone *message, size_t length);

error_t tlsParseNewSessionTicket(TlsContext *context,
   const TlsNewSessionTicket *message, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
