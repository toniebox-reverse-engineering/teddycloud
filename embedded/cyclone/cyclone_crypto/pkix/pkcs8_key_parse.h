/**
 * @file pkcs8_key_parse.h
 * @brief PKCS #8 key parsing
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

#ifndef _PKCS8_KEY_PARSE_H
#define _PKCS8_KEY_PARSE_H

//Dependencies
#include "core/crypto.h"
#include "pkix/x509_common.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief RSA private key
 **/

typedef struct
{
   int32_t version;
   const uint8_t *n;
   size_t nLen;
   const uint8_t *e;
   size_t eLen;
   const uint8_t *d;
   size_t dLen;
   const uint8_t *p;
   size_t pLen;
   const uint8_t *q;
   size_t qLen;
   const uint8_t *dp;
   size_t dpLen;
   const uint8_t *dq;
   size_t dqLen;
   const uint8_t *qinv;
   size_t qinvLen;
} Pkcs8RsaPrivateKey;


/**
 * @brief DSA private key
 **/

typedef struct
{
   const uint8_t *x;
   size_t xLen;
} Pkcs8DsaPrivateKey;


/**
 * @brief EC private key
 **/

typedef struct
{
   int32_t version;
   const uint8_t *d;
   size_t dLen;
} Pkcs8EcPrivateKey;


/**
 * @brief EdDSA private key
 **/

typedef struct
{
   const uint8_t *d;
   size_t dLen;
} Pkcs8EddsaPrivateKey;


/**
 * @brief Private key information
 **/

typedef struct
{
   int32_t version;
   const uint8_t *oid;
   size_t oidLen;
#if (RSA_SUPPORT == ENABLED)
   Pkcs8RsaPrivateKey rsaPrivateKey;
#endif
#if (DSA_SUPPORT == ENABLED)
   X509DsaParameters dsaParams;
   Pkcs8DsaPrivateKey dsaPrivateKey;
#endif
#if (EC_SUPPORT == ENABLED)
   X509EcParameters ecParams;
   Pkcs8EcPrivateKey ecPrivateKey;
#endif
#if (ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   Pkcs8EddsaPrivateKey eddsaPrivateKey;
#endif
} Pkcs8PrivateKeyInfo;


//Key parsing functions
error_t pkcs8ParsePrivateKeyInfo(const uint8_t *data, size_t length,
   Pkcs8PrivateKeyInfo *privateKeyInfo);

error_t pkcs8ParsePrivateKeyAlgo(const uint8_t *data, size_t length,
   size_t *totalLength, Pkcs8PrivateKeyInfo *privateKeyInfo);

error_t pkcs8ParseRsaPrivateKey(const uint8_t *data, size_t length,
   Pkcs8RsaPrivateKey *rsaPrivateKey);

error_t pkcs8ParseDsaPrivateKey(const uint8_t *data, size_t length,
   X509DsaParameters *dsaParams, Pkcs8DsaPrivateKey *dsaPrivateKey);

error_t pkcs8ParseEcPrivateKey(const uint8_t *data, size_t length,
   X509EcParameters *ecParams, Pkcs8EcPrivateKey *ecPrivateKey);

error_t pkcs8ParseEddsaPrivateKey(const uint8_t *data, size_t length,
   Pkcs8EddsaPrivateKey *eddsaPrivateKey);

error_t pkcs8ImportRsaPrivateKey(const Pkcs8PrivateKeyInfo *privateKeyInfo,
   RsaPrivateKey *privateKey);

error_t pkcs8ImportDsaPrivateKey(const Pkcs8PrivateKeyInfo *privateKeyInfo,
   DsaPrivateKey *privateKey);

error_t pkcs8ImportEcPrivateKey(const Pkcs8PrivateKeyInfo *privateKeyInfo,
   EcPrivateKey *privateKey);

error_t pkcs8ImportEddsaPrivateKey(const Pkcs8PrivateKeyInfo *privateKeyInfo,
   EddsaPrivateKey *privateKey);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
