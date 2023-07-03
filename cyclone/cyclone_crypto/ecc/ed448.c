/**
 * @file ed448.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "ecc/ec_curves.h"
#include "ecc/curve448.h"
#include "ecc/ed448.h"
#include "debug.h"

//Check crypto library configuration
#if (ED448_SUPPORT == ENABLED)

//Base point B
static const Ed448Point ED448_B =
{
   {
      0xC70CC05E, 0x2626A82B, 0x8B00938E, 0x433B80E1, 0x2AB66511, 0x12AE1AF7, 0xA3D3A464,
      0xEA6DE324, 0x470F1767, 0x9E146570, 0x22BF36DA, 0x221D15A6, 0x6BED0DED, 0x4F1970C6
   },
   {
      0xF230FA14, 0x9808795B, 0x4ED7C8AD, 0xFDBD132C, 0xE67C39C4, 0x3AD3FF1C, 0x05A0C2D7,
      0x87789C1E, 0x6CA39840, 0x4BEA7373, 0x56C9C762, 0x88762037, 0x6EB6BC24, 0x693F4671
   },
   {
      0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
   }
};

//Zero (constant)
static const uint32_t ED448_ZERO[14] =
{
   0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
};

//Curve parameter d
static const uint32_t ED448_D[14] =
{
   0xFFFF6756, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
   0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

//Order of the base point L
static const uint8_t ED448_L[60] =
{
   0xF3, 0x44, 0x58, 0xAB, 0x92, 0xC2, 0x78, 0x23, 0x55, 0x8F, 0xC5, 0x8D, 0x72, 0xC2, 0x6C, 0x21,
   0x90, 0x36, 0xD6, 0xAE, 0x49, 0xDB, 0x4E, 0xC4, 0xE9, 0x23, 0xCA, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00, 0x00, 0x00, 0x00
};

//Pre-computed value of mu = b^(2 * k) / L with b = 2^24 and k = 19
static const uint8_t ED448_MU[60] =
{
   0x0A, 0xD0, 0xE0, 0xB0, 0x7B, 0x4A, 0xD5, 0xD6, 0x73, 0xC8, 0xAD, 0x0A, 0xA7, 0x23, 0xD7, 0xD8,
   0x33, 0xE9, 0xFD, 0x96, 0x9C, 0x12, 0x65, 0x4B, 0x12, 0xBB, 0x63, 0xC1, 0x5D, 0x33, 0x08, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00
};


/**
 * @brief EdDSA key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[out] privateKey EdDSA private key (57 bytes)
 * @param[out] publicKey EdDSA public key (57 bytes)
 * @return Error code
 **/

error_t ed448GenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey, uint8_t *publicKey)
{
   error_t error;

   //Generate a private key
   error = ed448GeneratePrivateKey(prngAlgo, prngContext, privateKey);

   //Check status code
   if(!error)
   {
      //Derive the public key from the private key
      error = ed448GeneratePublicKey(privateKey, publicKey);
   }

   //Return status code
   return error;
}


/**
 * @brief EdDSA private key generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[out] privateKey EdDSA private key (57 bytes)
 * @return Error code
 **/

error_t ed448GeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey)
{
   error_t error;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL || privateKey == NULL )
      return ERROR_INVALID_PARAMETER;

   //The private key is 57 octets of cryptographically secure random data
   error = prngAlgo->read(prngContext, privateKey, ED448_PRIVATE_KEY_LEN);

   //Return status code
   return error;
}


/**
 * @brief Derive the public key from an EdDSA private key
 * @param[in] privateKey EdDSA private key (57 bytes)
 * @param[out] publicKey EdDSA public key (57 bytes)
 * @return Error code
 **/

error_t ed448GeneratePublicKey(const uint8_t *privateKey, uint8_t *publicKey)
{
   uint8_t s[57];
   Ed448State *state;

   //Check parameters
   if(privateKey == NULL || publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Allocate working state
   state = cryptoAllocMem(sizeof(Ed448State));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Hash the 57-byte private key using SHAKE256(x, 57)
   shakeInit(&state->shakeContext, 256);
   shakeAbsorb(&state->shakeContext, privateKey, ED448_PRIVATE_KEY_LEN);
   shakeFinal(&state->shakeContext);

   //Only the lower 57 bytes are used for generating the public key. Interpret
   //the buffer as the little-endian integer, forming a secret scalar s
   shakeSqueeze(&state->shakeContext, s, 57);

   //The two least significant bits of the first octet are cleared, all eight
   //bits the last octet are cleared, and the highest bit of the second to
   //last octet is set
   s[0] &= 0xFC;
   s[56] = 0x00;
   s[55] |= 0x80;

   //Perform a fixed-base scalar multiplication s * B
   ed448Mul(state, &state->sb, s, &ED448_B);
   //The public key A is the encoding of the point s * B
   ed448Encode(&state->sb, publicKey);

   //Erase working state
   osMemset(state, 0, sizeof(Ed448State));
   //Release working state
   cryptoFreeMem(state);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief EdDSA signature generation
 * @param[in] privateKey Signer's EdDSA private key (57 bytes)
 * @param[in] publicKey Signer's EdDSA public key (57 bytes)
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed448ph scheme
 * @param[out] signature EdDSA signature (114 bytes)
 * @return Error code
 **/

error_t ed448GenerateSignature(const uint8_t *privateKey,
   const uint8_t *publicKey, const void *message, size_t messageLen,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature)
{
   error_t error;
   EddsaMessageChunk messageChunks[2];

   //The message fits in a single chunk
   messageChunks[0].buffer = message;
   messageChunks[0].length = messageLen;
   messageChunks[1].buffer = NULL;
   messageChunks[1].length = 0;

   //Ed448 signature generation
   error = ed448GenerateSignatureEx(privateKey, publicKey, messageChunks,
      context, contextLen, flag, signature);

   //Return status code
   return error;
}


/**
 * @brief EdDSA signature generation
 * @param[in] privateKey Signer's EdDSA private key (57 bytes)
 * @param[in] publicKey Signer's EdDSA public key (57 bytes)
 * @param[in] messageChunks Collection of chunks representing the message to
 *   be signed
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed448ph scheme
 * @param[out] signature EdDSA signature (114 bytes)
 * @return Error code
 **/

error_t ed448GenerateSignatureEx(const uint8_t *privateKey,
   const uint8_t *publicKey, const EddsaMessageChunk *messageChunks,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature)
{
   uint_t i;
   uint8_t c;
   Ed448State *state;

   //Check parameters
   if(privateKey == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;
   if(messageChunks == NULL)
      return ERROR_INVALID_PARAMETER;
   if(context == NULL && contextLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Allocate working state
   state = cryptoAllocMem(sizeof(Ed448State));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Hash the private key, 57 octets, using SHAKE256(x, 114). Let h denote
   //the resulting digest
   shakeInit(&state->shakeContext, 256);
   shakeAbsorb(&state->shakeContext, privateKey, ED448_PRIVATE_KEY_LEN);
   shakeFinal(&state->shakeContext);

   //Construct the secret scalar s from the first half of the digest
   shakeSqueeze(&state->shakeContext, state->s, 57);

   //The two least significant bits of the first octet are cleared, all eight
   //bits the last octet are cleared, and the highest bit of the second to
   //last octet is set
   state->s[0] &= 0xFC;
   state->s[56] = 0x00;
   state->s[55] |= 0x80;

   //The public key is optional
   if(publicKey == NULL)
   {
      //Perform a fixed-base scalar multiplication s * B
      ed448Mul(state, &state->sb, state->s, &ED448_B);
      //The public key A is the encoding of the point s * B
      ed448Encode(&state->sb, state->t);
      //Point to the resulting public key
      publicKey = state->t;
   }

   //Let prefix denote the second half of the hash digest
   shakeSqueeze(&state->shakeContext, state->p, 57);

   //Initialize SHAKE256 context
   shakeInit(&state->shakeContext, 256);

   //Absorb dom4(F, C) || prefix
   shakeAbsorb(&state->shakeContext, "SigEd448", 8);
   shakeAbsorb(&state->shakeContext, &flag, sizeof(uint8_t));
   shakeAbsorb(&state->shakeContext, &contextLen, sizeof(uint8_t));
   shakeAbsorb(&state->shakeContext, context, contextLen);
   shakeAbsorb(&state->shakeContext, state->p, 57);

   //The message is split over multiple chunks
   for(i = 0; messageChunks[i].buffer != NULL; i++)
   {
      //Absorb current chunk
      shakeAbsorb(&state->shakeContext, messageChunks[i].buffer,
         messageChunks[i].length);
   }

   //Compute SHAKE256(dom4(F, C) || prefix || PH(M), 114)
   shakeFinal(&state->shakeContext);
   shakeSqueeze(&state->shakeContext, state->k, 114);

   //Reduce the 114-octet digest as a little-endian integer r
   ed448RedInt(state->r, state->k);
   //Compute the point r * B
   ed448Mul(state, &state->rb, state->r, &ED448_B);
   //Let the string R be the encoding of this point
   ed448Encode(&state->rb, signature);

   //Initialize SHAKE256 context
   shakeInit(&state->shakeContext, 256);

   //Absorb dom4(F, C) || R || A
   shakeAbsorb(&state->shakeContext, "SigEd448", 8);
   shakeAbsorb(&state->shakeContext, &flag, sizeof(uint8_t));
   shakeAbsorb(&state->shakeContext, &contextLen, sizeof(uint8_t));
   shakeAbsorb(&state->shakeContext, context, contextLen);
   shakeAbsorb(&state->shakeContext, signature, ED448_SIGNATURE_LEN / 2);
   shakeAbsorb(&state->shakeContext, publicKey, ED448_PUBLIC_KEY_LEN);

   //The message is split over multiple chunks
   for(i = 0; messageChunks[i].buffer != NULL; i++)
   {
      //Absorb current chunk
      shakeAbsorb(&state->shakeContext, messageChunks[i].buffer,
         messageChunks[i].length);
   }

   //Compute SHAKE256(dom4(F, C) || R || A || PH(M), 114) and interpret the
   //114-octet digest as a little-endian integer k
   shakeFinal(&state->shakeContext);
   shakeSqueeze(&state->shakeContext, state->k, 114);

   //Compute S = (r + k * s) mod L. For efficiency, reduce k modulo L first
   ed448RedInt(state->p, state->k);
   ed448MulInt(state->k, state->k + 57, state->p, state->s, 57);
   ed448RedInt(state->p, state->k);
   ed448AddInt(state->s, state->p, state->r, 57);

   //Perform modular reduction
   c = ed448SubInt(state->p, state->s, ED448_L, 57);
   ed448SelectInt(signature + 57, state->p, state->s, c, 57);

   //Erase working state
   osMemset(state, 0, sizeof(Ed448State));
   //Release working state
   cryptoFreeMem(state);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief EdDSA signature verification
 * @param[in] publicKey Signer's EdDSA public key (57 bytes)
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed448ph scheme
 * @param[in] signature EdDSA signature (114 bytes)
 * @return Error code
 **/

error_t ed448VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen, uint8_t flag,
   const uint8_t *signature)
{
   error_t error;
   EddsaMessageChunk messageChunks[2];

   //The message fits in a single chunk
   messageChunks[0].buffer = message;
   messageChunks[0].length = messageLen;
   messageChunks[1].buffer = NULL;
   messageChunks[1].length = 0;

   //Ed448 signature verification
   error = ed448VerifySignatureEx(publicKey, messageChunks, context,
      contextLen, flag, signature);

   //Return status code
   return error;
}


/**
 * @brief EdDSA signature verification
 * @param[in] publicKey Signer's EdDSA public key (57 bytes)
 * @param[in] messageChunks Collection of chunks representing the message
 *   whose signature is to be verified
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed448ph scheme
 * @param[in] signature EdDSA signature (114 bytes)
 * @return Error code
 **/

error_t ed448VerifySignatureEx(const uint8_t *publicKey,
   const EddsaMessageChunk *messageChunks, const void *context,
   uint8_t contextLen, uint8_t flag, const uint8_t *signature)
{
   uint_t i;
   uint32_t ret;
   Ed448State *state;

   //Check parameters
   if(publicKey == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;
   if(messageChunks == NULL)
      return ERROR_INVALID_PARAMETER;
   if(context == NULL && contextLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Allocate working state
   state = cryptoAllocMem(sizeof(Ed448State));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;

   //First split the signature into two 32-octet halves. Decode the first
   //half as a point R
   osMemcpy(state->r, signature, ED448_SIGNATURE_LEN / 2);

   //Decode the second half as an integer S, in the range 0 <= s < L
   osMemcpy(state->s, signature + ED448_SIGNATURE_LEN / 2,
      ED448_SIGNATURE_LEN / 2);

   //Ed448 signatures are not malleable due to the verification check that
   //decoded S is smaller than L (refer to RFC 8032, section 8.4)
   ret = 1 ^ ed448SubInt(state->p, state->s, ED448_L, ED448_SIGNATURE_LEN / 2);

   //Decode the public key A as point A'
   ret |= ed448Decode(&state->ka, publicKey);

   //Initialize SHAKE256 context
   shakeInit(&state->shakeContext, 256);

   //Absorb dom4(F, C) || R || A
   shakeAbsorb(&state->shakeContext, "SigEd448", 8);
   shakeAbsorb(&state->shakeContext, &flag, sizeof(uint8_t));
   shakeAbsorb(&state->shakeContext, &contextLen, sizeof(uint8_t));
   shakeAbsorb(&state->shakeContext, context, contextLen);
   shakeAbsorb(&state->shakeContext, state->r, ED448_SIGNATURE_LEN / 2);
   shakeAbsorb(&state->shakeContext, publicKey, ED448_PUBLIC_KEY_LEN);

   //The message is split over multiple chunks
   for(i = 0; messageChunks[i].buffer != NULL; i++)
   {
      //Absorb current chunk
      shakeAbsorb(&state->shakeContext, messageChunks[i].buffer,
         messageChunks[i].length);
   }

   //Compute SHAKE256(dom4(F, C) || R || A || PH(M), 114) and interpret the
   //114-octet digest as a little-endian integer k
   shakeFinal(&state->shakeContext);
   shakeSqueeze(&state->shakeContext, state->k, 114);

   //For efficiency, reduce k modulo L first
   ed448RedInt(state->k, state->k);

   //Compute the point P = s * B - k * A'
   curve448Sub(state->ka.x, ED448_ZERO, state->ka.x);
   ed448Mul(state, &state->sb, state->s, &ED448_B);
   ed448Mul(state, &state->ka, state->k, &state->ka);
   ed448Add(state, &state->ka, &state->sb, &state->ka);

   //Encode of the resulting point P
   ed448Encode(&state->ka, state->p);

   //If P = R, then the signature is verified. If P does not equal R,
   //then the message or the signature may have been modified
   ret |= ed448CompInt(state->p, signature, ED448_SIGNATURE_LEN / 2);

   //Erase working state
   osMemset(state, 0, sizeof(Ed448State));
   //Release working state
   cryptoFreeMem(state);

   //Return status code
   return (ret == 0) ? NO_ERROR : ERROR_INVALID_SIGNATURE;
}


/**
 * @brief Scalar multiplication on Ed448 curve
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = d * S
 * @param[in] k Input scalar
 * @param[in] p Input point
 **/

void ed448Mul(Ed448State *state, Ed448Point *r, const uint8_t *k,
   const Ed448Point *p)
{
   int_t i;
   uint8_t b;

   //The neutral element is represented by (0, 1, 1)
   curve448SetInt(state->u.x, 0);
   curve448SetInt(state->u.y, 1);
   curve448SetInt(state->u.z, 1);

   //Perform scalar multiplication
   for(i = CURVE448_BIT_LEN - 1; i >= 0; i--)
   {
      //The scalar is processed in a left-to-right fashion
      b = (k[i / 8] >> (i % 8)) & 1;

      //Compute U = 2 * U
      ed448Double(state, &state->u, &state->u);
      //Compute V = U + P
      ed448Add(state, &state->v, &state->u, p);

      //If b is set, then U = V
      curve448Select(state->u.x, state->u.x, state->v.x, b);
      curve448Select(state->u.y, state->u.y, state->v.y, b);
      curve448Select(state->u.z, state->u.z, state->v.z, b);
   }

   //Copy result
   curve448Copy(r->x, state->u.x);
   curve448Copy(r->y, state->u.y);
   curve448Copy(r->z, state->u.z);
}


/**
 * @brief Point addition
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = P + Q
 * @param[in] p First operand
 * @param[in] q Second operand
 **/

void ed448Add(Ed448State *state, Ed448Point *r, const Ed448Point *p,
   const Ed448Point *q)
{
   //Compute A = X1 * X2
   curve448Mul(state->a, p->x, q->x);
   //Compute B = Y1 * Y2
   curve448Mul(state->b, p->y, q->y);
   //Compute C = Z1 * Z2
   curve448Mul(state->c, p->z, q->z);
   //Compute D = C^2
   curve448Sqr(state->d, state->c);
   //Compute E = d * A * B
   curve448Mul(state->e, state->a, state->b);
   curve448Mul(state->e, state->e, ED448_D);
   //Compute F = D + E
   curve448Add(state->f, state->d, state->e);
   //Compute G = D - E
   curve448Sub(state->g, state->d, state->e);
   //Compute D = (X1 + Y1) * (X2 + Y2)
   curve448Add(state->d, p->x, p->y);
   curve448Add(state->e, q->x, q->y);
   curve448Mul(state->d, state->d, state->e);
   //Compute X3 = C * G * (D - A - B)
   curve448Sub(state->d, state->d, state->a);
   curve448Sub(state->d, state->d, state->b);
   curve448Mul(state->d, state->d, state->c);
   curve448Mul(r->x, state->d, state->g);
   //Compute Y3 = C * F * (B - A)
   curve448Sub(state->b, state->b, state->a);
   curve448Mul(state->b, state->b, state->c);
   curve448Mul(r->y, state->b, state->f);
   //Compute Z3 = F * G
   curve448Mul(r->z, state->f, state->g);
}


/**
 * @brief Point doubling
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = 2 * P
 * @param[in] p Input point P
 **/

void ed448Double(Ed448State *state, Ed448Point *r, const Ed448Point *p)
{
   //Compute A = X1 * X2
   curve448Mul(state->a, p->x, p->x);
   //Compute B = Y1 * Y2
   curve448Mul(state->b, p->y, p->y);
   //Compute C = Z1 * Z2
   curve448Mul(state->c, p->z, p->z);
   //Compute F = A + B
   curve448Add(state->f, state->a, state->b);
   //Compute G = F - 2 * C
   curve448Add(state->c, state->c, state->c);
   curve448Sub(state->g, state->f, state->c);
   //Compute D = (X1 + Y1)^2
   curve448Add(state->d, p->x, p->y);
   curve448Sqr(state->d, state->d);
   //Compute X3 = G * (D - F)
   curve448Sub(state->d, state->d, state->f);
   curve448Mul(r->x, state->d, state->g);
   //Compute Y3 = F * (A - B)
   curve448Sub(state->a, state->a, state->b);
   curve448Mul(r->y, state->a, state->f);
   //Compute Z3 = F * G
   curve448Mul(r->z, state->f, state->g);
}


/**
 * @brief Point encoding
 * @param[in] p Point representation
 * @param[out] data Octet string resulting from the conversion
 **/

void ed448Encode(Ed448Point *p, uint8_t *data)
{
   //Retrieve affine representation
   curve448Inv(p->z, p->z);
   curve448Mul(p->x, p->x, p->z);
   curve448Mul(p->y, p->y, p->z);
   curve448SetInt(p->z, 1);

   //Encode the y-coordinate as a little-endian string of 57 octets. The final
   //octet is always zero
   curve448Export(p->y, data);
   data[56] = 0;

   //Copy the least significant bit of the x-coordinate to the most significant
   //bit of the final octet
   data[56] |= (p->x[0] & 1) << 7;
}


/**
 * @brief Point decoding
 * @param[in] p Point representation
 * @param[out] data Octet string to be converted
 **/

uint32_t ed448Decode(Ed448Point *p, const uint8_t *data)
{
   uint_t i;
   uint8_t x0;
   uint32_t ret;
   uint64_t temp;
   uint32_t u[14];
   uint32_t v[14];

   //First, interpret the string as an integer in little-endian representation.
   //Bit 455 of this number is the least significant bit of the x-coordinate
   //and denote this value x_0
   x0 = data[56] >> 7;

   //The y-coordinate is recovered simply by clearing this bit
   curve448Import(p->y, data);

   //Compute u = y + 2^224 + 1
   for(temp = 1, i = 0; i < 7; i++)
   {
      temp += p->y[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   for(temp += 1, i = 7; i < 14; i++)
   {
      temp += p->y[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   temp += data[56] & 0x7F;
   ret = temp & 0xFFFFFFFF;

   //If the y-coordinate is >= p, decoding fails
   ret = (ret | (~ret + 1)) >> 31;

   //The curve equation implies x^2 = (y^2 - 1) / (d * y^2 - 1) mod p
   //Let u = y^2 - 1 and v = d * y^2 - 1
   curve448Sqr(v, p->y);
   curve448SubInt(u, v, 1);
   curve448Mul(v, v, ED448_D);
   curve448SubInt(v, v, 1);

   //Compute u = sqrt(u / v)
   ret |= curve448Sqrt(u, u, v);

   //If x = 0, and x_0 = 1, decoding fails
   ret |= (curve448Comp(u, ED448_ZERO) ^ 1) & x0;

   //Compute v = p - u
   curve448Sub(v, ED448_ZERO, u);

   //Finally, use the x_0 bit to select the right square root
   curve448Select(p->x, u, v, (x0 ^ u[0]) & 1);

   //Initialize z-coordinate (projective representation)
   curve448SetInt(p->z, 1);

   //Return 0 if the point has been successfully decoded, else 1
   return ret;
}


/**
 * @brief Reduce an integer modulo L
 *
 * This function implements Barrett reduction with b = 2^24 and k = 19. The
 * algorithm requires the precomputation of the quantity mu = b^(2 * k) / L
 *
 * @param[out] r Resulting integer R = A mod L
 * @param[in] a An integer such as 0 <= A < b^(2 * k)
 **/

void ed448RedInt(uint8_t *r, const uint8_t *a)
{
   uint8_t c;
   uint8_t u[60];
   uint8_t v[60];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ed448MulInt(NULL, u, a + 54, ED448_MU, 60);
   //Compute v = u * L mod b^(k + 1)
   ed448MulInt(v, NULL, u, ED448_L, 60);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ed448SubInt(u, a, v, 60);

   //This estimation implies that at most two subtractions of L are required to
   //obtain the correct remainder r
   c = ed448SubInt(v, u, ED448_L, 60);
   ed448SelectInt(u, v, u, c, 60);
   c = ed448SubInt(v, u, ED448_L, 60);
   ed448SelectInt(u, v, u, c, 60);

   //Copy the resulting remainder
   ed448CopyInt(r, u, 57);
}


/**
 * @brief Addition of two integers
 * @param[out] r Resulting integer R = A + B
 * @param[in] a An integer such as 0 <= A < (2^8)^n
 * @param[in] b An integer such as 0 <= B < (2^8)^n
 * @param[in] n Size of the operands, in bytes
 **/

void ed448AddInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n)
{
   uint_t i;
   uint16_t temp;

   //Compute R = A + B
   for(temp = 0, i = 0; i < n; i++)
   {
      temp += a[i];
      temp += b[i];
      r[i] = temp & 0xFF;
      temp >>= 8;
   }
}


/**
 * @brief Subtraction of two integers
 * @param[out] r Resulting integer R = A - B
 * @param[in] a An integer such as 0 <= A < (2^8)^n
 * @param[in] b An integer such as 0 <= B < (2^8)^n
 * @param[in] n Size of the operands, in bytes
 * @return 1 if the result is negative, else 0
 **/

uint8_t ed448SubInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n)
{
   uint_t i;
   int16_t temp;

   //Compute R = A - B
   for(temp = 0, i = 0; i < n; i++)
   {
      temp += a[i];
      temp -= b[i];
      r[i] = temp & 0xFF;
      temp >>= 8;
   }

   //Return 1 if the result of the subtraction is negative
   return temp & 1;
}


/**
 * @brief Multiplication of two integers
 * @param[out] rl Low part of the result R = (A + B) mod (2^8)^n
 * @param[out] rh High part of the result R = (A + B) / (2^8)^n
 * @param[in] a An integer such as 0 <= A < (2^8)^n
 * @param[in] b An integer such as 0 <= B < (2^8)^n
 * @param[in] n Size of the operands, in bytes
 **/

void ed448MulInt(uint8_t *rl, uint8_t *rh, const uint8_t *a,
   const uint8_t *b, uint_t n)
{
   uint_t i;
   uint_t j;
   uint32_t c;
   uint32_t d;
   uint64_t temp;

   //Perform multiplication in base b = 2^24
   n /= 3;

   //Compute the low part of the multiplication
   for(temp = 0, i = 0; i < n; i++)
   {
      //The Comba's algorithm computes the products, column by column
      for(j = 0; j <= i; j++)
      {
         c = LOAD24LE(a + 3 * j);
         d = LOAD24LE(b + 3 * (i - j));
         temp += (uint64_t) c * d;
      }

      //At the bottom of each column, the final result is written to memory
      if(rl != NULL)
      {
         STORE24LE(temp & 0xFFFFFF, rl + 3 * i);
      }

      //Propagate the carry upwards
      temp >>= 24;
   }

   //Check whether the high part of the multiplication should be calculated
   if(rh != NULL)
   {
      //Compute the high part of the multiplication
      for(i = n; i < (2 * n); i++)
      {
         //The Comba's algorithm computes the products, column by column
         for(j = i + 1 - n; j < n; j++)
         {
            c = LOAD24LE(a + 3 * j);
            d = LOAD24LE(b + 3 * (i - j));
            temp += (uint64_t) c * d;
         }

         //At the bottom of each column, the final result is written to memory
         STORE24LE(temp & 0xFFFFFF, rh + 3 * (i - n));

         //Propagate the carry upwards
         temp >>= 24;
      }
   }
}


/**
 * @brief Copy an integer
 * @param[out] a Pointer to the destination integer
 * @param[in] b Pointer to the source integer
 * @param[in] n Size of the integers, in bytes
 **/

void ed448CopyInt(uint8_t *a, const uint8_t *b, uint_t n)
{
   uint_t i;

   //Copy the value of the integer
   for(i = 0; i < n; i++)
   {
      a[i] = b[i];
   }
}


/**
 * @brief Select an integer
 * @param[out] r Pointer to the destination integer
 * @param[in] a Pointer to the first source integer
 * @param[in] b Pointer to the second source integer
 * @param[in] c Condition variable
 * @param[in] n Size of the integers, in bytes
 **/

void ed448SelectInt(uint8_t *r, const uint8_t *a, const uint8_t *b,
   uint8_t c, uint_t n)
{
   uint_t i;
   uint8_t mask;

   //The mask is the all-1 or all-0 word
   mask = c - 1;

   //Select between A and B
   for(i = 0; i < n; i++)
   {
      //Constant time implementation
      r[i] = (a[i] & mask) | (b[i] & ~mask);
   }
}


/**
 * @brief Compare integers
 * @param[in] a Pointer to the first integer
 * @param[in] b Pointer to the second integer
 * @param[in] n Size of the integers, in bytes
 * @return The function returns 0 if the A = B, else 1
 **/

uint8_t ed448CompInt(const uint8_t *a, const uint8_t *b, uint_t n)
{
   uint_t i;
   uint8_t mask;

   //Initialize mask
   mask = 0;

   //Compare A and B
   for(i = 0; i < n; i++)
   {
      //Constant time implementation
      mask |= a[i] ^ b[i];
   }

   //Return 0 if A = B, else 1
   return ((uint8_t) (mask | (~mask + 1))) >> 7;
}

#endif
