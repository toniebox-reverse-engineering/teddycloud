/**
 * @file ec_curves.h
 * @brief Elliptic curves
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

#ifndef _EC_CURVES_H
#define _EC_CURVES_H

//Dependencies
#include "core/crypto.h"
#include "mpi/mpi.h"

//secp112r1 elliptic curve support
#ifndef SECP112R1_SUPPORT
   #define SECP112R1_SUPPORT DISABLED
#elif (SECP112R1_SUPPORT != ENABLED && SECP112R1_SUPPORT != DISABLED)
   #error SECP112R1_SUPPORT parameter is not valid
#endif

//secp112r2 elliptic curve support
#ifndef SECP112R2_SUPPORT
   #define SECP112R2_SUPPORT DISABLED
#elif (SECP112R2_SUPPORT != ENABLED && SECP112R2_SUPPORT != DISABLED)
   #error SECP112R2_SUPPORT parameter is not valid
#endif

//secp128r1 elliptic curve support
#ifndef SECP128R1_SUPPORT
   #define SECP128R1_SUPPORT DISABLED
#elif (SECP128R1_SUPPORT != ENABLED && SECP128R1_SUPPORT != DISABLED)
   #error SECP128R1_SUPPORT parameter is not valid
#endif

//secp128r2 elliptic curve support
#ifndef SECP128R2_SUPPORT
   #define SECP128R2_SUPPORT DISABLED
#elif (SECP128R2_SUPPORT != ENABLED && SECP128R2_SUPPORT != DISABLED)
   #error SECP128R2_SUPPORT parameter is not valid
#endif

//secp160k1 elliptic curve support
#ifndef SECP160K1_SUPPORT
   #define SECP160K1_SUPPORT DISABLED
#elif (SECP160K1_SUPPORT != ENABLED && SECP160K1_SUPPORT != DISABLED)
   #error SECP160K1_SUPPORT parameter is not valid
#endif

//secp160r1 elliptic curve support
#ifndef SECP160R1_SUPPORT
   #define SECP160R1_SUPPORT DISABLED
#elif (SECP160R1_SUPPORT != ENABLED && SECP160R1_SUPPORT != DISABLED)
   #error SECP160R1_SUPPORT parameter is not valid
#endif

//secp160r2 elliptic curve support
#ifndef SECP160R2_SUPPORT
   #define SECP160R2_SUPPORT DISABLED
#elif (SECP160R2_SUPPORT != ENABLED && SECP160R2_SUPPORT != DISABLED)
   #error SECP160R2_SUPPORT parameter is not valid
#endif

//secp192k1 elliptic curve support
#ifndef SECP192K1_SUPPORT
   #define SECP192K1_SUPPORT DISABLED
#elif (SECP192K1_SUPPORT != ENABLED && SECP192K1_SUPPORT != DISABLED)
   #error SECP192K1_SUPPORT parameter is not valid
#endif

//secp192r1 elliptic curve support (NIST P-192)
#ifndef SECP192R1_SUPPORT
   #define SECP192R1_SUPPORT DISABLED
#elif (SECP192R1_SUPPORT != ENABLED && SECP192R1_SUPPORT != DISABLED)
   #error SECP192R1_SUPPORT parameter is not valid
#endif

//secp224k1 elliptic curve support
#ifndef SECP224K1_SUPPORT
   #define SECP224K1_SUPPORT DISABLED
#elif (SECP224K1_SUPPORT != ENABLED && SECP224K1_SUPPORT != DISABLED)
   #error SECP224K1_SUPPORT parameter is not valid
#endif

//secp224r1 elliptic curve support (NIST P-224)
#ifndef SECP224R1_SUPPORT
   #define SECP224R1_SUPPORT ENABLED
#elif (SECP224R1_SUPPORT != ENABLED && SECP224R1_SUPPORT != DISABLED)
   #error SECP224R1_SUPPORT parameter is not valid
#endif

//secp256k1 elliptic curve support
#ifndef SECP256K1_SUPPORT
   #define SECP256K1_SUPPORT DISABLED
#elif (SECP256K1_SUPPORT != ENABLED && SECP256K1_SUPPORT != DISABLED)
   #error SECP256K1_SUPPORT parameter is not valid
#endif

//secp256r1 elliptic curve support (NIST P-256)
#ifndef SECP256R1_SUPPORT
   #define SECP256R1_SUPPORT ENABLED
#elif (SECP256R1_SUPPORT != ENABLED && SECP256R1_SUPPORT != DISABLED)
   #error SECP256R1_SUPPORT parameter is not valid
#endif

//secp384r1 elliptic curve support (NIST P-384)
#ifndef SECP384R1_SUPPORT
   #define SECP384R1_SUPPORT ENABLED
#elif (SECP384R1_SUPPORT != ENABLED && SECP384R1_SUPPORT != DISABLED)
   #error SECP384R1_SUPPORT parameter is not valid
#endif

//secp521r1 elliptic curve support (NIST P-521)
#ifndef SECP521R1_SUPPORT
   #define SECP521R1_SUPPORT ENABLED
#elif (SECP521R1_SUPPORT != ENABLED && SECP521R1_SUPPORT != DISABLED)
   #error SECP521R1_SUPPORT parameter is not valid
#endif

//brainpoolP160r1 elliptic curve support
#ifndef BRAINPOOLP160R1_SUPPORT
   #define BRAINPOOLP160R1_SUPPORT DISABLED
#elif (BRAINPOOLP160R1_SUPPORT != ENABLED && BRAINPOOLP160R1_SUPPORT != DISABLED)
   #error BRAINPOOLP160R1_SUPPORT parameter is not valid
#endif

//brainpoolP192r1 elliptic curve support
#ifndef BRAINPOOLP192R1_SUPPORT
   #define BRAINPOOLP192R1_SUPPORT DISABLED
#elif (BRAINPOOLP192R1_SUPPORT != ENABLED && BRAINPOOLP192R1_SUPPORT != DISABLED)
   #error BRAINPOOLP192R1_SUPPORT parameter is not valid
#endif

//brainpoolP224r1 elliptic curve support
#ifndef BRAINPOOLP224R1_SUPPORT
   #define BRAINPOOLP224R1_SUPPORT DISABLED
#elif (BRAINPOOLP224R1_SUPPORT != ENABLED && BRAINPOOLP224R1_SUPPORT != DISABLED)
   #error BRAINPOOLP224R1_SUPPORT parameter is not valid
#endif

//brainpoolP256r1 elliptic curve support
#ifndef BRAINPOOLP256R1_SUPPORT
   #define BRAINPOOLP256R1_SUPPORT DISABLED
#elif (BRAINPOOLP256R1_SUPPORT != ENABLED && BRAINPOOLP256R1_SUPPORT != DISABLED)
   #error BRAINPOOLP256R1_SUPPORT parameter is not valid
#endif

//brainpoolP320r1 elliptic curve support
#ifndef BRAINPOOLP320R1_SUPPORT
   #define BRAINPOOLP320R1_SUPPORT DISABLED
#elif (BRAINPOOLP320R1_SUPPORT != ENABLED && BRAINPOOLP320R1_SUPPORT != DISABLED)
   #error BRAINPOOLP320R1_SUPPORT parameter is not valid
#endif

//brainpoolP384r1 elliptic curve support
#ifndef BRAINPOOLP384R1_SUPPORT
   #define BRAINPOOLP384R1_SUPPORT DISABLED
#elif (BRAINPOOLP384R1_SUPPORT != ENABLED && BRAINPOOLP384R1_SUPPORT != DISABLED)
   #error BRAINPOOLP384R1_SUPPORT parameter is not valid
#endif

//brainpoolP512r1 elliptic curve support
#ifndef BRAINPOOLP512R1_SUPPORT
   #define BRAINPOOLP512R1_SUPPORT DISABLED
#elif (BRAINPOOLP512R1_SUPPORT != ENABLED && BRAINPOOLP512R1_SUPPORT != DISABLED)
   #error BRAINPOOLP512R1_SUPPORT parameter is not valid
#endif

//Curve25519 elliptic curve support
#ifndef X25519_SUPPORT
   #define X25519_SUPPORT DISABLED
#elif (X25519_SUPPORT != ENABLED && X25519_SUPPORT != DISABLED)
   #error X25519_SUPPORT parameter is not valid
#endif

//Curve448 elliptic curve support
#ifndef X448_SUPPORT
   #define X448_SUPPORT DISABLED
#elif (X448_SUPPORT != ENABLED && X448_SUPPORT != DISABLED)
   #error X448_SUPPORT parameter is not valid
#endif

//Ed25519 elliptic curve support
#ifndef ED25519_SUPPORT
   #define ED25519_SUPPORT DISABLED
#elif (ED25519_SUPPORT != ENABLED && ED25519_SUPPORT != DISABLED)
   #error ED25519_SUPPORT parameter is not valid
#endif

//Ed448 elliptic curve support
#ifndef ED448_SUPPORT
   #define ED448_SUPPORT DISABLED
#elif (ED448_SUPPORT != ENABLED && ED448_SUPPORT != DISABLED)
   #error ED448_SUPPORT parameter is not valid
#endif

//SECG curves
#define SECP112R1_CURVE (&secp112r1Curve)
#define SECP112R2_CURVE (&secp112r2Curve)
#define SECP128R1_CURVE (&secp128r1Curve)
#define SECP128R2_CURVE (&secp128r2Curve)
#define SECP160K1_CURVE (&secp160k1Curve)
#define SECP160R1_CURVE (&secp160r1Curve)
#define SECP160R2_CURVE (&secp160r2Curve)
#define SECP192K1_CURVE (&secp192k1Curve)
#define SECP192R1_CURVE (&secp192r1Curve)
#define SECP224K1_CURVE (&secp224k1Curve)
#define SECP224R1_CURVE (&secp224r1Curve)
#define SECP256K1_CURVE (&secp256k1Curve)
#define SECP256R1_CURVE (&secp256r1Curve)
#define SECP384R1_CURVE (&secp384r1Curve)
#define SECP521R1_CURVE (&secp521r1Curve)

//Brainpool curves
#define BRAINPOOLP160R1_CURVE (&brainpoolP160r1Curve)
#define BRAINPOOLP192R1_CURVE (&brainpoolP192r1Curve)
#define BRAINPOOLP224R1_CURVE (&brainpoolP224r1Curve)
#define BRAINPOOLP256R1_CURVE (&brainpoolP256r1Curve)
#define BRAINPOOLP320R1_CURVE (&brainpoolP320r1Curve)
#define BRAINPOOLP384R1_CURVE (&brainpoolP384r1Curve)
#define BRAINPOOLP512R1_CURVE (&brainpoolP512r1Curve)

//Montgomery curves
#define X25519_CURVE (&x25519Curve)
#define X448_CURVE (&x448Curve)

//Edwards curves
#define ED25519_CURVE (&ed25519Curve)
#define ED448_CURVE (&ed448Curve)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Elliptic curve type
 **/

typedef enum
{
   EC_CURVE_TYPE_NONE          = 0,
   EC_CURVE_TYPE_SECT_K1       = 1,
   EC_CURVE_TYPE_SECT_R1       = 2,
   EC_CURVE_TYPE_SECT_R2       = 3,
   EC_CURVE_TYPE_SECP_K1       = 4,
   EC_CURVE_TYPE_SECP_R1       = 5,
   EC_CURVE_TYPE_SECP_R2       = 6,
   EC_CURVE_TYPE_BRAINPOOLP_R1 = 7,
   EC_CURVE_TYPE_X25519        = 8,
   EC_CURVE_TYPE_X448          = 9,
   EC_CURVE_TYPE_ED25519       = 10,
   EC_CURVE_TYPE_ED448         = 11
} EcCurveType;


/**
 * @brief Fast modular reduction
 **/

typedef error_t (*EcFastModAlgo)(Mpi *a, const Mpi *p);


/**
 * @brief Elliptic curve parameters
 **/

typedef struct
{
   const char_t *name;   ///<Curve name
   const uint8_t *oid;   ///<Object identifier
   size_t oidSize;       ///<OID size
   EcCurveType type;     ///<Curve type
   const uint8_t p[66];  ///<Prime modulus p
   size_t pLen;          ///<Length of p
   const uint8_t a[66];  ///<Curve parameter a
   size_t aLen;          ///<Length of a
   const uint8_t b[66];  ///<Curve parameter b
   size_t bLen;          ///<Length of b
   const uint8_t gx[66]; ///<x-coordinate of the base point G
   size_t gxLen;         ///<Length of Gx
   const uint8_t gy[66]; ///<y-coordinate of the base point G
   size_t gyLen;         ///<Length of Gy
   const uint8_t q[66];  ///<Order of the base point G
   size_t qLen;          ///<Length of q
   uint32_t h;           ///<Cofactor h
   EcFastModAlgo mod;    ///<Fast modular reduction
} EcCurveInfo;


//Constants
extern const uint8_t SECP112R1_OID[5];
extern const uint8_t SECP112R2_OID[5];
extern const uint8_t SECP128R1_OID[5];
extern const uint8_t SECP128R2_OID[5];
extern const uint8_t SECP160K1_OID[5];
extern const uint8_t SECP160R1_OID[5];
extern const uint8_t SECP160R2_OID[5];
extern const uint8_t SECP192K1_OID[5];
extern const uint8_t SECP192R1_OID[8];
extern const uint8_t SECP224K1_OID[5];
extern const uint8_t SECP224R1_OID[5];
extern const uint8_t SECP256K1_OID[5];
extern const uint8_t SECP256R1_OID[8];
extern const uint8_t SECP384R1_OID[5];
extern const uint8_t SECP521R1_OID[5];
extern const uint8_t BRAINPOOLP160R1_OID[9];
extern const uint8_t BRAINPOOLP192R1_OID[9];
extern const uint8_t BRAINPOOLP224R1_OID[9];
extern const uint8_t BRAINPOOLP256R1_OID[9];
extern const uint8_t BRAINPOOLP320R1_OID[9];
extern const uint8_t BRAINPOOLP384R1_OID[9];
extern const uint8_t BRAINPOOLP512R1_OID[9];
extern const uint8_t X25519_OID[3];
extern const uint8_t X448_OID[3];
extern const uint8_t ED25519_OID[3];
extern const uint8_t ED448_OID[3];

extern const EcCurveInfo secp112r1Curve;
extern const EcCurveInfo secp112r2Curve;
extern const EcCurveInfo secp128r1Curve;
extern const EcCurveInfo secp128r2Curve;
extern const EcCurveInfo secp160k1Curve;
extern const EcCurveInfo secp160r1Curve;
extern const EcCurveInfo secp160r2Curve;
extern const EcCurveInfo secp192k1Curve;
extern const EcCurveInfo secp192r1Curve;
extern const EcCurveInfo secp224k1Curve;
extern const EcCurveInfo secp224r1Curve;
extern const EcCurveInfo secp256k1Curve;
extern const EcCurveInfo secp256r1Curve;
extern const EcCurveInfo secp384r1Curve;
extern const EcCurveInfo secp521r1Curve;
extern const EcCurveInfo brainpoolP160r1Curve;
extern const EcCurveInfo brainpoolP192r1Curve;
extern const EcCurveInfo brainpoolP224r1Curve;
extern const EcCurveInfo brainpoolP256r1Curve;
extern const EcCurveInfo brainpoolP320r1Curve;
extern const EcCurveInfo brainpoolP384r1Curve;
extern const EcCurveInfo brainpoolP512r1Curve;
extern const EcCurveInfo x25519Curve;
extern const EcCurveInfo x448Curve;
extern const EcCurveInfo ed25519Curve;
extern const EcCurveInfo ed448Curve;

//Fast modular reduction
error_t secp128r1Mod(Mpi *a, const Mpi *p);
error_t secp128r2Mod(Mpi *a, const Mpi *p);
error_t secp160k1Mod(Mpi *a, const Mpi *p);
error_t secp160r1Mod(Mpi *a, const Mpi *p);
error_t secp160r2Mod(Mpi *a, const Mpi *p);
error_t secp192k1Mod(Mpi *a, const Mpi *p);
error_t secp192r1Mod(Mpi *a, const Mpi *p);
error_t secp224k1Mod(Mpi *a, const Mpi *p);
error_t secp224r1Mod(Mpi *a, const Mpi *p);
error_t secp256k1Mod(Mpi *a, const Mpi *p);
error_t secp256r1Mod(Mpi *a, const Mpi *p);
error_t secp384r1Mod(Mpi *a, const Mpi *p);
error_t secp521r1Mod(Mpi *a, const Mpi *p);

const EcCurveInfo *ecGetCurveInfo(const uint8_t *oid, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
