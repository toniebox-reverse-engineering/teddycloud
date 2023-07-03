/**
 * @file tls_server_extensions.h
 * @brief Formatting and parsing of extensions (TLS server)
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

#ifndef _TLS_SERVER_EXTENSIONS_H
#define _TLS_SERVER_EXTENSIONS_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS server specific functions
error_t tlsFormatServerSniExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerMaxFragLenExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerRecordSizeLimitExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerEcPointFormatsExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerAlpnExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatClientCertTypeExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerCertTypeExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerEmsExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerSessionTicketExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsFormatServerRenegoInfoExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsParseClientSupportedVersionsExtension(TlsContext *context,
   const TlsSupportedVersionList *supportedVersionList);

error_t tlsParseClientSniExtension(TlsContext *context,
   const TlsServerNameList *serverNameList);

error_t tlsParseClientMaxFragLenExtension(TlsContext *context,
   const TlsExtension *maxFragLen);

error_t tlsParseClientRecordSizeLimitExtension(TlsContext *context,
   const TlsExtension *recordSizeLimit);

error_t tlsParseClientEcPointFormatsExtension(TlsContext *context,
   const TlsEcPointFormatList *ecPointFormatList);

error_t tlsParseClientAlpnExtension(TlsContext *context,
   const TlsProtocolNameList *protocolNameList);

error_t tlsParseClientCertTypeListExtension(TlsContext *context,
   const TlsCertTypeList *clientCertTypeList);

error_t tlsParseServerCertTypeListExtension(TlsContext *context,
   const TlsCertTypeList *serverCertTypeList);

error_t tlsParseClientEmsExtension(TlsContext *context,
   const TlsExtension *extendedMasterSecret);

error_t tlsParseClientSessionTicketExtension(TlsContext *context,
   const TlsExtension *sessionTicket);

error_t tlsParseClientRenegoInfoExtension(TlsContext *context,
   const TlsHelloExtensions *extensions);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
