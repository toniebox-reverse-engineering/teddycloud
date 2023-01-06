/**
 * @file x509_csr_validate.c
 * @brief CSR validation
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_csr_validate.h"
#include "pkix/x509_signature.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)


/**
 * @brief CSR validation
 * @param[in] csrInfo Pointer to the CSR to be verified
 * @return Error code
 **/

error_t x509ValidateCsr(const X509CsrInfo *csrInfo)
{
   error_t error;

   //Check parameters
   if(csrInfo == NULL)
      return ERROR_INVALID_PARAMETER;

   //The ASN.1 DER-encoded certificationRequestInfo is used as the input
   //to the signature function
   error = x509VerifySignature(csrInfo->certReqInfo.rawData,
      csrInfo->certReqInfo.rawDataLen, &csrInfo->signatureAlgo,
      &csrInfo->certReqInfo.subjectPublicKeyInfo, &csrInfo->signatureValue);

   //Return status code
   return error;
}

#endif
