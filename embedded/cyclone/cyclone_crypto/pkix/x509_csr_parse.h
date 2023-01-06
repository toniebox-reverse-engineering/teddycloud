/**
 * @file x509_csr_parse.h
 * @brief CSR (Certificate Signing Request) parsing
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

#ifndef _X509_CSR_PARSE_H
#define _X509_CSR_PARSE_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//CSR related functions
error_t x509ParseCsr(const uint8_t *data, size_t length,
   X509CsrInfo *csrInfo);

error_t x509ParseCertRequestInfo(const uint8_t *data, size_t length,
   size_t *totalLength, X509CertRequestInfo *certReqInfo);

error_t x509ParseAttributes(const uint8_t *data, size_t length,
   size_t *totalLength, X509Attributes *attributes);

error_t x509ParseAttribute(const uint8_t *data, size_t length,
   size_t *totalLength, X509Attribute *attribute);

error_t x509ParseChallengePassword(const uint8_t *data, size_t length,
   X509ChallengePassword *challengePwd);

error_t x509ParseExtensionRequest(const uint8_t *data, size_t length,
   X509Extensions *extensionReq);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
