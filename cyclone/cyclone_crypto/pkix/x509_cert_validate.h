/**
 * @file x509_cert_validate.h
 * @brief X.509 certificate validation
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
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

#ifndef _X509_CERT_VALIDATE_H
#define _X509_CERT_VALIDATE_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//X.509 related functions
error_t x509ValidateCertificate(const X509CertificateInfo *certInfo,
   const X509CertificateInfo *issuerCertInfo, uint_t pathLen);

error_t x509CheckSubjectName(const X509CertificateInfo *certInfo,
   const char_t *fqdn);

error_t x509CheckNameConstraints(const char_t *subjectName,
   const X509CertificateInfo *certInfo);

bool_t x509CompareName(const uint8_t *name1, size_t nameLen1,
   const uint8_t *name2, size_t nameLen2);

bool_t x509CompareSubjectName(const char_t *subjectName,
   size_t subjectNameLen, const char_t *fqdn);

bool_t x509CompareSubtree(const char_t *subjectName,
   const char_t *subtree, size_t subtreeLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
