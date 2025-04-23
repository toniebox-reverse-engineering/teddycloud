/**
 * @file tls_certificate.h
 * @brief X.509 certificate handling
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.4.4
 **/

#ifndef _TLS_CERTIFICATE_H
#define _TLS_CERTIFICATE_H

//Dependencies
#include "tls.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS related functions
error_t tlsFormatCertificateList(TlsContext *context, uint8_t *p,
   size_t *written);

error_t tlsFormatRawPublicKey(TlsContext *context, uint8_t *p,
   size_t *written);

error_t tlsParseCertificateList(TlsContext *context, const uint8_t *p,
   size_t length);

error_t tlsParseRawPublicKey(TlsContext *context, const uint8_t *p,
   size_t length);

bool_t tlsIsCertificateAcceptable(TlsContext *context,
   const TlsCertDesc *cert, const uint8_t *certTypes, size_t numCertTypes,
   const TlsSupportedGroupList *curveList,
   const TlsSignSchemeList *certSignAlgoList,
   const TlsCertAuthorities *certAuthorities);

error_t tlsValidateCertificate(TlsContext *context,
   const X509CertInfo *certInfo, uint_t pathLen, const char_t *subjectName);

error_t tlsGetCertificateType(const X509CertInfo *certInfo,
   TlsCertificateType *certType, TlsNamedGroup *namedCurve);

error_t tlsGetCertificateSignAlgo(const X509CertInfo *certInfo,
   TlsSignatureScheme *signScheme);

error_t tlsReadSubjectPublicKey(TlsContext *context,
   const X509SubjectPublicKeyInfo *subjectPublicKeyInfo);

error_t tlsCheckKeyUsage(const X509CertInfo *certInfo,
   TlsConnectionEnd entity, TlsKeyExchMethod keyExchMethod);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
