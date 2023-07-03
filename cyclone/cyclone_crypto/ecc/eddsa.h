/**
 * @file eddsa.h
 * @brief EdDSA (Edwards-Curve Digital Signature Algorithm)
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

#ifndef _EDDSA_H
#define _EDDSA_H

//Dependencies
#include "core/crypto.h"
#include "ecc/ec.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief EdDSA public key
 **/

typedef struct
{
   Mpi q; ///<Public key
} EddsaPublicKey;


/**
 * @brief EdDSA private key
 **/

typedef struct
{
   Mpi d;      ///<Private key
   Mpi q;      ///<Public key
   int_t slot; ///<Private key slot
} EddsaPrivateKey;


/**
 * @brief Message chunk descriptor
 **/

typedef struct
{
   const void *buffer;
   size_t length;
} EddsaMessageChunk;


//EdDSA related functions
void eddsaInitPublicKey(EddsaPublicKey *key);
void eddsaFreePublicKey(EddsaPublicKey *key);

void eddsaInitPrivateKey(EddsaPrivateKey *key);
void eddsaFreePrivateKey(EddsaPrivateKey *key);

error_t eddsaGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurveInfo *curveInfo, EddsaPrivateKey *privateKey,
   EddsaPublicKey *publicKey);

error_t eddsaGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   const EcCurveInfo *curveInfo, EddsaPrivateKey *privateKey);

error_t eddsaGeneratePublicKey(const EcCurveInfo *curveInfo,
   const EddsaPrivateKey *privateKey, EddsaPublicKey *publicKey);

//C++ guard
#ifdef __cplusplus
}
#endif

//Ed25519 supported?
#if (ED25519_SUPPORT == ENABLED)
   #include "ecc/ed25519.h"
#endif

//Ed448 supported?
#if (ED448_SUPPORT == ENABLED)
   #include "ecc/ed448.h"
#endif

#endif
