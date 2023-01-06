/**
 * @file ec.h
 * @brief ECC (Elliptic Curve Cryptography)
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

#ifndef _EC_H
#define _EC_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ec_curves.h"

//Error code checking
#define EC_CHECK(f) if((error = f) != NO_ERROR) goto end

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief EC point format
 **/

typedef enum
{
   EC_POINT_FORMAT_COMPRESSED_EVEN = 0x02,
   EC_POINT_FORMAT_COMPRESSED_ODD  = 0x03,
   EC_POINT_FORMAT_UNCOMPRESSED    = 0x04
} EcPointFormat;


/**
 * @brief EC point
 **/

typedef struct
{
   Mpi x; ///<x-coordinate
   Mpi y; ///<y-coordinate
   Mpi z; ///<z-coordinate
} EcPoint;


/**
 * @brief EC domain parameters
 **/

typedef struct
{
   const char_t *name; ///<Curve name
   EcCurveType type;   ///<Curve type
   Mpi p;              ///<Prime
   Mpi a;              ///<Curve parameter a
   Mpi b;              ///<Curve parameter b
   EcPoint g;          ///<Base point G
   Mpi q;              ///<Order of the point G
   uint32_t h;         ///<Cofactor h
   EcFastModAlgo mod;  ///<Fast modular reduction
} EcDomainParameters;


/**
 * @brief EC public key
 **/

typedef struct
{
   EcPoint q; ///<Public key
} EcPublicKey;


/**
 * @brief EC private key
 **/

typedef struct
{
   Mpi d;      ///<Private key
   int_t slot; ///<Private key slot
} EcPrivateKey;


//EC related constants
extern const uint8_t EC_PUBLIC_KEY_OID[7];

//EC related functions
void ecInitDomainParameters(EcDomainParameters *params);
void ecFreeDomainParameters(EcDomainParameters *params);

error_t ecLoadDomainParameters(EcDomainParameters *params,
   const EcCurveInfo *curveInfo);

void ecInitPublicKey(EcPublicKey *key);
void ecFreePublicKey(EcPublicKey *key);

void ecInitPrivateKey(EcPrivateKey *key);
void ecFreePrivateKey(EcPrivateKey *key);

error_t ecGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, EcPrivateKey *privateKey,
   EcPublicKey *publicKey);

error_t ecGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, EcPrivateKey *privateKey);

error_t ecGeneratePublicKey(const EcDomainParameters *params,
   const EcPrivateKey *privateKey, EcPublicKey *publicKey);

void ecInit(EcPoint *r);
void ecFree(EcPoint *r);

error_t ecCopy(EcPoint *r, const EcPoint *s);

error_t ecImport(const EcDomainParameters *params, EcPoint *r,
   const uint8_t *data, size_t length);

error_t ecExport(const EcDomainParameters *params, const EcPoint *a,
   uint8_t *data, size_t *length);

error_t ecProjectify(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s);

error_t ecAffinify(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s);

bool_t ecIsPointAffine(const EcDomainParameters *params, const EcPoint *s);

error_t ecDouble(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s);

error_t ecAdd(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s, const EcPoint *t);

error_t ecFullAdd(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s, const EcPoint *t);

error_t ecFullSub(const EcDomainParameters *params, EcPoint *r,
   const EcPoint *s, const EcPoint *t);

error_t ecMult(const EcDomainParameters *params, EcPoint *r, const Mpi *d,
   const EcPoint *s);

error_t ecTwinMult(const EcDomainParameters *params, EcPoint *r,
   const Mpi *d0, const EcPoint *s, const Mpi *d1, const EcPoint *t);

error_t ecAddMod(const EcDomainParameters *params, Mpi *r, const Mpi *a,
   const Mpi *b);

error_t ecSubMod(const EcDomainParameters *params, Mpi *r, const Mpi *a,
   const Mpi *b);

error_t ecMulMod(const EcDomainParameters *params, Mpi *r, const Mpi *a,
   const Mpi *b);

error_t ecSqrMod(const EcDomainParameters *params, Mpi *r, const Mpi *a);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
