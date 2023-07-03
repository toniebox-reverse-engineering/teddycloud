/**
 * @file ed25519.c
 * @brief Ed25519 elliptic curve (constant-time implementation)
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
#include "ecc/curve25519.h"
#include "ecc/ed25519.h"
#include "debug.h"

//Check crypto library configuration
#if (ED25519_SUPPORT == ENABLED)

//Base point B
static const Ed25519Point ED25519_B =
{
   {
      0x8F25D51A, 0xC9562D60, 0x9525A7B2, 0x692CC760,
      0xFDD6DC5C, 0xC0A4E231, 0xCD6E53FE, 0x216936D3
   },
   {
      0x66666658, 0x66666666, 0x66666666, 0x66666666,
      0x66666666, 0x66666666, 0x66666666, 0x66666666
   },
   {
      0x00000001, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000
   },
   {
      0xA5B7DDA3, 0x6DDE8AB3, 0x775152F5, 0x20F09F80,
      0x64ABE37D, 0x66EA4E8E, 0xD78B7665, 0x67875F0F
   }
};

//Zero (constant)
static const uint32_t ED25519_ZERO[8] =
{
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x00000000
};

//Curve parameter d
static const uint32_t ED25519_D[8] =
{
   0x135978A3, 0x75EB4DCA, 0x4141D8AB, 0x00700A4D,
   0x7779E898, 0x8CC74079, 0x2B6FFE73, 0x52036CEE
};

//Pre-computed value of 2 * d
static const uint32_t ED25519_2D[8] =
{
   0x26B2F159, 0xEBD69B94, 0x8283B156, 0x00E0149A,
   0xEEF3D130, 0x198E80F2, 0x56DFFCE7, 0x2406D9DC
};

//Order of the base point L
static const uint8_t ED25519_L[33] =
{
   0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
   0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
   0x00,
};

//Pre-computed value of mu = b^(2 * k) / L with b = 2^8 and k = 32
static const uint8_t ED25519_MU[33] =
{
   0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED,
   0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21,
   0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0x0F
};


/**
 * @brief EdDSA key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[out] privateKey EdDSA private key (32 bytes)
 * @param[out] publicKey EdDSA public key (32 bytes)
 * @return Error code
 **/

error_t ed25519GenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey, uint8_t *publicKey)
{
   error_t error;

   //Generate a private key
   error = ed25519GeneratePrivateKey(prngAlgo, prngContext, privateKey);

   //Check status code
   if(!error)
   {
      //Derive the public key from the private key
      error = ed25519GeneratePublicKey(privateKey, publicKey);
   }

   //Return status code
   return error;
}


/**
 * @brief EdDSA private key generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[out] privateKey EdDSA private key (32 bytes)
 * @return Error code
 **/

error_t ed25519GeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey)
{
   error_t error;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL || privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //The private key is 32 octets of cryptographically secure random data
   error = prngAlgo->read(prngContext, privateKey, ED25519_PRIVATE_KEY_LEN);

   //Return status code
   return error;
}


/**
 * @brief Derive the public key from an EdDSA private key
 * @param[in] privateKey EdDSA private key (32 bytes)
 * @param[out] publicKey EdDSA public key (32 bytes)
 * @return Error code
 **/

error_t ed25519GeneratePublicKey(const uint8_t *privateKey, uint8_t *publicKey)
{
   uint8_t *s;
   Ed25519State *state;

   //Check parameters
   if(privateKey == NULL || publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Allocate working state
   state = cryptoAllocMem(sizeof(Ed25519State));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Hash the 32-byte private key using SHA-512
   sha512Init(&state->sha512Context);
   sha512Update(&state->sha512Context, privateKey, ED25519_PRIVATE_KEY_LEN);
   sha512Final(&state->sha512Context, NULL);

   //Only the lower 32 bytes are used for generating the public key. Interpret
   //the buffer as the little-endian integer, forming a secret scalar s
   s = state->sha512Context.digest;

   //The lowest three bits of the first octet are cleared, the highest bit
   //of the last octet is cleared, and the second highest bit of the last
   //octet is set
   s[0] &= 0xF8;
   s[31] &= 0x7F;
   s[31] |= 0x40;

   //Perform a fixed-base scalar multiplication s * B
   ed25519Mul(state, &state->sb, s, &ED25519_B);
   //The public key A is the encoding of the point s * B
   ed25519Encode(&state->sb, publicKey);

   //Erase working state
   osMemset(state, 0, sizeof(Ed25519State));
   //Release working state
   cryptoFreeMem(state);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief EdDSA signature generation
 * @param[in] privateKey Signer's EdDSA private key (32 bytes)
 * @param[in] publicKey Signer's EdDSA public key (32 bytes)
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed25519ph scheme
 * @param[out] signature EdDSA signature (64 bytes)
 * @return Error code
 **/

error_t ed25519GenerateSignature(const uint8_t *privateKey,
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

   //Ed25519 signature generation
   error = ed25519GenerateSignatureEx(privateKey, publicKey, messageChunks,
      context, contextLen, flag, signature);

   //Return status code
   return error;
}


/**
 * @brief EdDSA signature generation
 * @param[in] privateKey Signer's EdDSA private key (32 bytes)
 * @param[in] publicKey Signer's EdDSA public key (32 bytes)
 * @param[in] messageChunks Collection of chunks representing the message to
 *   be signed
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed25519ph scheme
 * @param[out] signature EdDSA signature (64 bytes)
 * @return Error code
 **/

error_t ed25519GenerateSignatureEx(const uint8_t *privateKey,
   const uint8_t *publicKey, const EddsaMessageChunk *messageChunks,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature)
{
   uint_t i;
   uint8_t c;
   Ed25519State *state;

   //Check parameters
   if(privateKey == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;
   if(messageChunks == NULL)
      return ERROR_INVALID_PARAMETER;
   if(context == NULL && contextLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Allocate working state
   state = cryptoAllocMem(sizeof(Ed25519State));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Hash the private key, 32 octets, using SHA-512. Let h denote the
   //resulting digest
   sha512Init(&state->sha512Context);
   sha512Update(&state->sha512Context, privateKey, ED25519_PRIVATE_KEY_LEN);
   sha512Final(&state->sha512Context, NULL);

   //Construct the secret scalar s from the first half of the digest
   osMemcpy(state->s, state->sha512Context.digest, 32);

   //The lowest three bits of the first octet are cleared, the highest bit
   //of the last octet is cleared, and the second highest bit of the last
   //octet is set
   state->s[0] &= 0xF8;
   state->s[31] &= 0x7F;
   state->s[31] |= 0x40;

   //The public key is optional
   if(publicKey == NULL)
   {
      //Perform a fixed-base scalar multiplication s * B
      ed25519Mul(state, &state->sb, state->s, &ED25519_B);
      //The public key A is the encoding of the point s * B
      ed25519Encode(&state->sb, state->k);
      //Point to the resulting public key
      publicKey = state->k;
   }

   //Let prefix denote the second half of the hash digest
   osMemcpy(state->p, state->sha512Context.digest + 32, 32);

   //Initialize SHA-512 context
   sha512Init(&state->sha512Context);

   //For Ed25519ctx and Ed25519ph schemes, dom2(x, y) is the octet string
   //"SigEd25519 no Ed25519 collisions" || octet(x) || octet(OLEN(y)) || y,
   //where x is in range 0-255 and y is an octet string of at most 255 octets
   if(context != NULL || flag != 0)
   {
      sha512Update(&state->sha512Context, "SigEd25519 no Ed25519 collisions", 32);
      sha512Update(&state->sha512Context, &flag, sizeof(uint8_t));
      sha512Update(&state->sha512Context, &contextLen, sizeof(uint8_t));
      sha512Update(&state->sha512Context, context, contextLen);
   }

   //Digest prefix
   sha512Update(&state->sha512Context, state->p, 32);

   //The message is split over multiple chunks
   for(i = 0; messageChunks[i].buffer != NULL; i++)
   {
      //Digest current chunk
      sha512Update(&state->sha512Context, messageChunks[i].buffer,
         messageChunks[i].length);
   }

   //Compute SHA-512(dom2(F, C) || prefix || PH(M))
   sha512Final(&state->sha512Context, NULL);

   //Reduce the 64-octet digest as a little-endian integer r
   ed25519RedInt(state->r, state->sha512Context.digest);
   //Compute the point r * B
   ed25519Mul(state, &state->rb, state->r, &ED25519_B);
   //Let the string R be the encoding of this point
   ed25519Encode(&state->rb, signature);

   //Initialize SHA-512 context
   sha512Init(&state->sha512Context);

   //For Ed25519ctx and Ed25519ph schemes, dom2(x, y) is the octet string
   //"SigEd25519 no Ed25519 collisions" || octet(x) || octet(OLEN(y)) || y,
   //where x is in range 0-255 and y is an octet string of at most 255 octets
   if(context != NULL || flag != 0)
   {
      sha512Update(&state->sha512Context, "SigEd25519 no Ed25519 collisions", 32);
      sha512Update(&state->sha512Context, &flag, sizeof(uint8_t));
      sha512Update(&state->sha512Context, &contextLen, sizeof(uint8_t));
      sha512Update(&state->sha512Context, context, contextLen);
   }

   //Digest R || A
   sha512Update(&state->sha512Context, signature, ED25519_SIGNATURE_LEN / 2);
   sha512Update(&state->sha512Context, publicKey, ED25519_PUBLIC_KEY_LEN);

   //The message is split over multiple chunks
   for(i = 0; messageChunks[i].buffer != NULL; i++)
   {
      //Digest current chunk
      sha512Update(&state->sha512Context, messageChunks[i].buffer,
         messageChunks[i].length);
   }

   //Compute SHA512(dom2(F, C) || R || A || PH(M)) and interpret the 64-octet
   //digest as a little-endian integer k
   sha512Final(&state->sha512Context, state->k);

   //Compute S = (r + k * s) mod L. For efficiency, reduce k modulo L first
   ed25519RedInt(state->p, state->k);
   ed25519MulInt(state->k, state->k + 32, state->p, state->s, 32);
   ed25519RedInt(state->p, state->k);
   ed25519AddInt(state->s, state->p, state->r, 32);

   //Perform modular reduction
   c = ed25519SubInt(state->p, state->s, ED25519_L, 32);
   ed25519SelectInt(signature + 32, state->p, state->s, c, 32);

   //Erase working state
   osMemset(state, 0, sizeof(Ed25519State));
   //Release working state
   cryptoFreeMem(state);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief EdDSA signature verification
 * @param[in] publicKey Signer's EdDSA public key (32 bytes)
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed25519ph scheme
 * @param[in] signature EdDSA signature (64 bytes)
 * @return Error code
 **/

error_t ed25519VerifySignature(const uint8_t *publicKey, const void *message,
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

   //Ed25519 signature verification
   error = ed25519VerifySignatureEx(publicKey, messageChunks, context,
      contextLen, flag, signature);

   //Return status code
   return error;
}


/**
 * @brief EdDSA signature verification
 * @param[in] publicKey Signer's EdDSA public key (32 bytes)
 * @param[in] messageChunks Collection of chunks representing the message
 *   whose signature is to be verified
 * @param[in] context Constant string specified by the protocol using it
 * @param[in] contextLen Length of the context, in bytes
 * @param[in] flag Prehash flag for Ed25519ph scheme
 * @param[in] signature EdDSA signature (64 bytes)
 * @return Error code
 **/

error_t ed25519VerifySignatureEx(const uint8_t *publicKey,
   const EddsaMessageChunk *messageChunks, const void *context,
   uint8_t contextLen, uint8_t flag, const uint8_t *signature)
{
   uint_t i;
   uint32_t ret;
   Ed25519State *state;

   //Check parameters
   if(publicKey == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;
   if(messageChunks == NULL)
      return ERROR_INVALID_PARAMETER;
   if(context == NULL && contextLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Allocate working state
   state = cryptoAllocMem(sizeof(Ed25519State));
   //Failed to allocate memory?
   if(state == NULL)
      return ERROR_OUT_OF_MEMORY;

   //First split the signature into two 32-octet halves. Decode the first
   //half as a point R
   osMemcpy(state->r, signature, ED25519_SIGNATURE_LEN / 2);

   //Decode the second half as an integer S, in the range 0 <= s < L
   osMemcpy(state->s, signature + ED25519_SIGNATURE_LEN / 2,
      ED25519_SIGNATURE_LEN / 2);

   //Ed25519 signatures are not malleable due to the verification check that
   //decoded S is smaller than L (refer to RFC 8032, section 8.4)
   ret = 1 ^ ed25519SubInt(state->p, state->s, ED25519_L,
      ED25519_SIGNATURE_LEN / 2);

   //Decode the public key A as point A'
   ret |= ed25519Decode(&state->ka, publicKey);

   //Initialize SHA-512 context
   sha512Init(&state->sha512Context);

   //For Ed25519ctx and Ed25519ph schemes, dom2(x, y) is the octet string
   //"SigEd25519 no Ed25519 collisions" || octet(x) || octet(OLEN(y)) || y,
   //where x is in range 0-255 and y is an octet string of at most 255 octets
   if(context != NULL || flag != 0)
   {
      sha512Update(&state->sha512Context, "SigEd25519 no Ed25519 collisions", 32);
      sha512Update(&state->sha512Context, &flag, sizeof(uint8_t));
      sha512Update(&state->sha512Context, &contextLen, sizeof(uint8_t));
      sha512Update(&state->sha512Context, context, contextLen);
   }

   //Digest R || A
   sha512Update(&state->sha512Context, state->r, ED25519_SIGNATURE_LEN / 2);
   sha512Update(&state->sha512Context, publicKey, ED25519_PUBLIC_KEY_LEN);

   //The message is split over multiple chunks
   for(i = 0; messageChunks[i].buffer != NULL; i++)
   {
      //Digest current chunk
      sha512Update(&state->sha512Context, messageChunks[i].buffer,
         messageChunks[i].length);
   }

   //Compute SHA512(dom2(F, C) || R || A || PH(M)) and interpret the 64-octet
   //digest as a little-endian integer k
   sha512Final(&state->sha512Context, state->k);

   //For efficiency, reduce k modulo L first
   ed25519RedInt(state->k, state->k);

   //Compute the point P = s * B - k * A'
   curve25519Sub(state->ka.x, ED25519_ZERO, state->ka.x);
   curve25519Sub(state->ka.t, ED25519_ZERO, state->ka.t);
   ed25519Mul(state, &state->sb, state->s, &ED25519_B);
   ed25519Mul(state, &state->ka, state->k, &state->ka);
   ed25519Add(state, &state->ka, &state->sb, &state->ka);

   //Encode of the resulting point P
   ed25519Encode(&state->ka, state->p);

   //If P = R, then the signature is verified. If P does not equal R,
   //then the message or the signature may have been modified
   ret |= ed25519CompInt(state->p, signature, ED25519_SIGNATURE_LEN / 2);

   //Erase working state
   osMemset(state, 0, sizeof(Ed25519State));
   //Release working state
   cryptoFreeMem(state);

   //Return status code
   return (ret == 0) ? NO_ERROR : ERROR_INVALID_SIGNATURE;
}


/**
 * @brief Scalar multiplication on Ed25519 curve
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = d * S
 * @param[in] k Input scalar
 * @param[in] p Input point
 **/

void ed25519Mul(Ed25519State *state, Ed25519Point *r, const uint8_t *k,
   const Ed25519Point *p)
{
   int_t i;
   uint8_t b;

   //The neutral element is represented by (0, 1, 1, 0)
   curve25519SetInt(state->u.x, 0);
   curve25519SetInt(state->u.y, 1);
   curve25519SetInt(state->u.z, 1);
   curve25519SetInt(state->u.t, 0);

   //Perform scalar multiplication
   for(i = CURVE25519_BIT_LEN - 1; i >= 0; i--)
   {
      //The scalar is processed in a left-to-right fashion
      b = (k[i / 8] >> (i % 8)) & 1;

      //Compute U = 2 * U
      ed25519Double(state, &state->u, &state->u);
      //Compute V = U + P
      ed25519Add(state, &state->v, &state->u, p);

      //If b is set, then U = V
      curve25519Select(state->u.x, state->u.x, state->v.x, b);
      curve25519Select(state->u.y, state->u.y, state->v.y, b);
      curve25519Select(state->u.z, state->u.z, state->v.z, b);
      curve25519Select(state->u.t, state->u.t, state->v.t, b);
   }

   //Copy result
   curve25519Copy(r->x, state->u.x);
   curve25519Copy(r->y, state->u.y);
   curve25519Copy(r->z, state->u.z);
   curve25519Copy(r->t, state->u.t);
}


/**
 * @brief Point addition
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = P + Q
 * @param[in] p First operand
 * @param[in] q Second operand
 **/

void ed25519Add(Ed25519State *state, Ed25519Point *r, const Ed25519Point *p,
   const Ed25519Point *q)
{
   //Compute A = (Y1 + X1) * (Y2 + X2)
   curve25519Add(state->c, p->y, p->x);
   curve25519Add(state->d, q->y, q->x);
   curve25519Mul(state->a, state->c, state->d);
   //Compute B = (Y1 - X1) * (Y2 - X2)
   curve25519Sub(state->c, p->y, p->x);
   curve25519Sub(state->d, q->y, q->x);
   curve25519Mul(state->b, state->c, state->d);
   //Compute C = 2 * Z1 * Z2
   curve25519Mul(state->c, p->z, q->z);
   curve25519Add(state->c, state->c, state->c);
   //Compute D = (2 * d) * T1 * T2
   curve25519Mul(state->d, p->t, q->t);
   curve25519Mul(state->d, state->d, ED25519_2D);
   //Compute E = A + B
   curve25519Add(state->e, state->a, state->b);
   //Compute F = A - B
   curve25519Sub(state->f, state->a, state->b);
   //Compute G = C + D
   curve25519Add(state->g, state->c, state->d);
   //Compute H = C - D
   curve25519Sub(state->h, state->c, state->d);
   //Compute X3 = F * H
   curve25519Mul(r->x, state->f, state->h);
   //Compute Y3 = E * G
   curve25519Mul(r->y, state->e, state->g);
   //Compute Z3 = G * H
   curve25519Mul(r->z, state->g, state->h);
   //Compute T3 = E * F
   curve25519Mul(r->t, state->e, state->f);
}


/**
 * @brief Point doubling
 * @param[in] state Pointer to the working state
 * @param[out] r Resulting point R = 2 * P
 * @param[in] p Input point P
 **/

void ed25519Double(Ed25519State *state, Ed25519Point *r, const Ed25519Point *p)
{
   //Compute A = X1^2
   curve25519Sqr(state->a, p->x);
   //Compute B = Y1^2
   curve25519Sqr(state->b, p->y);
   //Compute C = 2 * Z1^2
   curve25519Sqr(state->c, p->z);
   curve25519Add(state->c, state->c, state->c);
   //Compute E = A + B
   curve25519Add(state->e, state->a, state->b);
   //Compute F = E - (X1 + Y1)^2
   curve25519Add(state->f, p->x, p->y);
   curve25519Sqr(state->f, state->f);
   curve25519Sub(state->f, state->e, state->f);
   //Compute G = A - B
   curve25519Sub(state->g, state->a, state->b);
   //Compute H = C + G
   curve25519Add(state->h, state->c, state->g);
   //Compute X3 = F * H
   curve25519Mul(r->x, state->f, state->h);
   //Compute Y3 = E * G
   curve25519Mul(r->y, state->e, state->g);
   //Compute Z3 = G * H
   curve25519Mul(r->z, state->g, state->h);
   //Compute T3 = E * F
   curve25519Mul(r->t, state->e, state->f);
}


/**
 * @brief Point encoding
 * @param[in] p Point representation
 * @param[out] data Octet string resulting from the conversion
 **/

void ed25519Encode(Ed25519Point *p, uint8_t *data)
{
   //Retrieve affine representation
   curve25519Inv(p->z, p->z);
   curve25519Mul(p->x, p->x, p->z);
   curve25519Mul(p->y, p->y, p->z);
   curve25519SetInt(p->z, 1);
   curve25519Mul(p->t, p->x, p->y);

   //Encode the y-coordinate as a little-endian string of 32 octets. The most
   //significant bit of the final octet is always zero
   curve25519Export(p->y, data);

   //Copy the least significant bit of the x-coordinate to the most significant
   //bit of the final octet
   data[31] |= (p->x[0] & 1) << 7;
}


/**
 * @brief Point decoding
 * @param[in] p Point representation
 * @param[out] data Octet string to be converted
 **/

uint32_t ed25519Decode(Ed25519Point *p, const uint8_t *data)
{
   uint_t i;
   uint8_t x0;
   uint32_t ret;
   uint64_t temp;
   uint32_t u[8];
   uint32_t v[8];

   //First, interpret the string as an integer in little-endian representation.
   //Bit 255 of this number is the least significant bit of the x-coordinate
   //and denote this value x_0
   x0 = data[31] >> 7;

   //The y-coordinate is recovered simply by clearing this bit
   curve25519Import(p->y, data);
   p->y[7] &= 0x7FFFFFFF;

   //Compute u = y + 19
   for(temp = 19, i = 0; i < 8; i++)
   {
      temp += p->y[i];
      u[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   //If the y-coordinate is >= p, decoding fails
   ret = (u[7] >> 31) & 1;

   //The curve equation implies x^2 = (y^2 - 1) / (d * y^2 + 1) mod p
   //Let u = y^2 - 1 and v = d * y^2 + 1
   curve25519Sqr(v, p->y);
   curve25519SubInt(u, v, 1);
   curve25519Mul(v, v, ED25519_D);
   curve25519AddInt(v, v, 1);

   //Compute u = sqrt(u / v)
   ret |= curve25519Sqrt(u, u, v);

   //If x = 0, and x_0 = 1, decoding fails
   ret |= (curve25519Comp(u, ED25519_ZERO) ^ 1) & x0;

   //Compute v = p - u
   curve25519Sub(v, ED25519_ZERO, u);

   //Finally, use the x_0 bit to select the right square root
   curve25519Select(p->x, u, v, (x0 ^ u[0]) & 1);

   //Calculate extended point representation
   curve25519SetInt(p->z, 1);
   curve25519Mul(p->t, p->x, p->y);

   //Return 0 if the point has been successfully decoded, else 1
   return ret;
}


/**
 * @brief Reduce an integer modulo L
 *
 * This function implements Barrett reduction with b = 2^8 and k = 32. The
 * algorithm requires the precomputation of the quantity mu = b^(2 * k) / L
 *
 * @param[out] r Resulting integer R = A mod L
 * @param[in] a An integer such as 0 <= A < b^(2 * k)
 **/

void ed25519RedInt(uint8_t *r, const uint8_t *a)
{
   uint8_t c;
   uint8_t u[33];
   uint8_t v[33];

   //Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ed25519MulInt(NULL, u, a + 31, ED25519_MU, 33);
   //Compute v = u * L mod b^(k + 1)
   ed25519MulInt(v, NULL, u, ED25519_L, 33);

   //Compute the estimate of the remainder u = a mod b^(k + 1) - v
   //If u < 0, then u = u + b^(k + 1)
   ed25519SubInt(u, a, v, 33);

   //This estimation implies that at most two subtractions of L are required to
   //obtain the correct remainder r
   c = ed25519SubInt(v, u, ED25519_L, 33);
   ed25519SelectInt(u, v, u, c, 33);
   c = ed25519SubInt(v, u, ED25519_L, 33);
   ed25519SelectInt(u, v, u, c, 33);

   //Copy the resulting remainder
   ed25519CopyInt(r, u, 32);
}


/**
 * @brief Addition of two integers
 * @param[out] r Resulting integer R = A + B
 * @param[in] a An integer such as 0 <= A < (2^8)^n
 * @param[in] b An integer such as 0 <= B < (2^8)^n
 * @param[in] n Size of the operands, in bytes
 **/

void ed25519AddInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n)
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

uint8_t ed25519SubInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n)
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

void ed25519MulInt(uint8_t *rl, uint8_t *rh, const uint8_t *a,
   const uint8_t *b, uint_t n)
{
   uint_t i;
   uint_t j;
   uint32_t temp;

   //Compute the low part of the multiplication
   for(temp = 0, i = 0; i < n; i++)
   {
      //The Comba's algorithm computes the products, column by column
      for(j = 0; j <= i; j++)
      {
         temp += (uint16_t) a[j] * b[i - j];
      }

      //At the bottom of each column, the final result is written to memory
      if(rl != NULL)
      {
         rl[i] = temp & 0xFF;
      }

      //Propagate the carry upwards
      temp >>= 8;
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
            temp += (uint16_t) a[j] * b[i - j];
         }

         //At the bottom of each column, the final result is written to memory
         rh[i - n] = temp & 0xFF;

         //Propagate the carry upwards
         temp >>= 8;
      }
   }
}


/**
 * @brief Copy an integer
 * @param[out] a Pointer to the destination integer
 * @param[in] b Pointer to the source integer
 * @param[in] n Size of the integers, in bytes
 **/

void ed25519CopyInt(uint8_t *a, const uint8_t *b, uint_t n)
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

void ed25519SelectInt(uint8_t *r, const uint8_t *a, const uint8_t *b,
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

uint8_t ed25519CompInt(const uint8_t *a, const uint8_t *b, uint_t n)
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
