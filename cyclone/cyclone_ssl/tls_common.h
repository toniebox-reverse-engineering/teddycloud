/**
 * @file tls_common.h
 * @brief Handshake message processing (TLS client and server)
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

#ifndef _TLS_COMMON_H
#define _TLS_COMMON_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS related functions
error_t tlsSendCertificate(TlsContext *context);
error_t tlsSendCertificateVerify(TlsContext *context);
error_t tlsSendChangeCipherSpec(TlsContext *context);
error_t tlsSendFinished(TlsContext *context);
error_t tlsSendAlert(TlsContext *context, uint8_t level, uint8_t description);

error_t tlsFormatCertificate(TlsContext *context,
   TlsCertificate *message, size_t *length);

error_t tlsFormatCertificateVerify(TlsContext *context,
   TlsCertificateVerify *message, size_t *length);

error_t tlsFormatChangeCipherSpec(TlsContext *context,
   TlsChangeCipherSpec *message, size_t *length);

error_t tlsFormatFinished(TlsContext *context,
   TlsFinished *message, size_t *length);

error_t tlsFormatAlert(TlsContext *context, uint8_t level,
   uint8_t description, TlsAlert *message, size_t *length);

error_t tlsFormatSignatureAlgorithmsExtension(TlsContext *context,
   uint_t cipherSuiteTypes, uint8_t *p, size_t *written);

error_t tlsFormatSignatureAlgorithmsCertExtension(TlsContext *context,
   uint8_t *p, size_t *written);

error_t tlsParseCertificate(TlsContext *context,
   const TlsCertificate *message, size_t length);

error_t tlsParseCertificateVerify(TlsContext *context,
   const TlsCertificateVerify *message, size_t length);

error_t tlsParseChangeCipherSpec(TlsContext *context,
   const TlsChangeCipherSpec *message, size_t length);

error_t tlsParseFinished(TlsContext *context,
   const TlsFinished *message, size_t length);

error_t tlsParseAlert(TlsContext *context,
   const TlsAlert *message, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
