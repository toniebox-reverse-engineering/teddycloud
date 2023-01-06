/**
 * @file tls_server.h
 * @brief Handshake message processing (TLS server)
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

#ifndef _TLS_SERVER_H
#define _TLS_SERVER_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS server specific functions
error_t tlsSendServerHello(TlsContext *context);
error_t tlsSendServerKeyExchange(TlsContext *context);
error_t tlsSendCertificateRequest(TlsContext *context);
error_t tlsSendServerHelloDone(TlsContext *context);
error_t tlsSendNewSessionTicket(TlsContext *context);

error_t tlsFormatServerHello(TlsContext *context,
   TlsServerHello *message, size_t *length);

error_t tlsFormatServerKeyExchange(TlsContext *context,
   TlsServerKeyExchange *message, size_t *length);

error_t tlsFormatCertificateRequest(TlsContext *context,
   TlsCertificateRequest *message, size_t *length);

error_t tlsFormatServerHelloDone(TlsContext *context,
   TlsServerHelloDone *message, size_t *length);

error_t tlsFormatNewSessionTicket(TlsContext *context,
   TlsNewSessionTicket *message, size_t *length);

error_t tlsParseClientHello(TlsContext *context,
   const TlsClientHello *message, size_t length);

error_t tlsParseClientKeyExchange(TlsContext *context,
   const TlsClientKeyExchange *message, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
