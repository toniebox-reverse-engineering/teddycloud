/**
 * @file ed448.h
 * @brief Ed448 elliptic curve (constant-time implementation)
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

#ifndef _ED448_H
#define _ED448_H

//Dependencies
#include "core/crypto.h"
#include "ecc/eddsa.h"
#include "xof/shake.h"

//Length of EdDSA private keys
#define ED448_PRIVATE_KEY_LEN 57
//Length of EdDSA public keys
#define ED448_PUBLIC_KEY_LEN 57
//Length of EdDSA signatures
#define ED448_SIGNATURE_LEN 114

//Ed448ph flag
#define ED448_PH_FLAG 1
//Prehash function output size
#define ED448_PH_SIZE 64

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Projective point representation
 **/

typedef struct
{
   uint32_t x[14];
   uint32_t y[14];
   uint32_t z[14];
} Ed448Point;


/**
 * @brief Ed448 working state
 **/

typedef struct
{
   ShakeContext shakeContext;
   uint8_t k[114];
   uint8_t p[57];
   uint8_t r[57];
   uint8_t s[57];
   uint8_t t[57];
   Ed448Point ka;
   Ed448Point rb;
   Ed448Point sb;
   Ed448Point u;
   Ed448Point v;
   uint32_t a[14];
   uint32_t b[14];
   uint32_t c[14];
   uint32_t d[14];
   uint32_t e[14];
   uint32_t f[14];
   uint32_t g[14];
} Ed448State;


//Ed448 related functions
error_t ed448GenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey, uint8_t *publicKey);

error_t ed448GeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey);

error_t ed448GeneratePublicKey(const uint8_t *privateKey, uint8_t *publicKey);

error_t ed448GenerateSignature(const uint8_t *privateKey,
   const uint8_t *publicKey, const void *message, size_t messageLen,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature);

error_t ed448GenerateSignatureEx(const uint8_t *privateKey,
   const uint8_t *publicKey, const EddsaMessageChunk *messageChunks,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature);

error_t ed448VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen, uint8_t flag,
   const uint8_t *signature);

error_t ed448VerifySignatureEx(const uint8_t *publicKey,
   const EddsaMessageChunk *messageChunks, const void *context,
   uint8_t contextLen, uint8_t flag, const uint8_t *signature);

void ed448Mul(Ed448State *state, Ed448Point *r, const uint8_t *k,
   const Ed448Point *p);

void ed448Add(Ed448State *state, Ed448Point *r, const Ed448Point *p,
   const Ed448Point *q);

void ed448Double(Ed448State *state, Ed448Point *r, const Ed448Point *p);

void ed448Encode(Ed448Point *p, uint8_t *data);
uint32_t ed448Decode(Ed448Point *p, const uint8_t *data);

void ed448RedInt(uint8_t *r, const uint8_t *a);

void ed448AddInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n);
uint8_t ed448SubInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n);

void ed448MulInt(uint8_t *rl, uint8_t *rh, const uint8_t *a,
   const uint8_t *b, uint_t n);

void ed448CopyInt(uint8_t *a, const uint8_t *b, uint_t n);

void ed448SelectInt(uint8_t *r, const uint8_t *a, const uint8_t *b,
   uint8_t c, uint_t n);

uint8_t ed448CompInt(const uint8_t *a, const uint8_t *b, uint_t n);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
