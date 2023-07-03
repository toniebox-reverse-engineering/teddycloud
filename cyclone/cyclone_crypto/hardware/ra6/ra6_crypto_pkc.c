/**
 * @file ra6_crypto_pkc.c
 * @brief RA6 public-key hardware accelerator
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
#include "hw_sce_private.h"
#include "hw_sce_rsa_private.h"
#include "hw_sce_ecc_private.h"
#include "core/crypto.h"
#include "hardware/ra6/ra6_crypto.h"
#include "hardware/ra6/ra6_crypto_pkc.h"
#include "pkc/rsa.h"
#include "ecc/ec.h"
#include "ecc/ecdsa.h"
#include "debug.h"

//SCE9 specific dependencies
#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   #include "hw_sce_ra_private.h"
#endif

//Check crypto library configuration
#if (RA6_CRYPTO_PKC_SUPPORT == ENABLED)

//Global variables
static Ra6RsaArgs rsaArgs;
static Ra6EcArgs ecArgs;


#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
#else

/**
 * @brief RSA private key generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] k Required bit length of the modulus n (must be 2048)
 * @param[in] e Public exponent (must be 65537)
 * @param[out] privateKey RSA private key
 * @return Error code
 **/

error_t rsaGeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   size_t k, uint_t e, RsaPrivateKey *privateKey)
{
   error_t error;
   fsp_err_t status;

   //Check parameters
   if(e != 65537 || privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra6CryptoMutex);

   //Check the length of the modulus
   if(k == 2048)
   {
      //Generate a 2048-bit RSA private key
      status = HW_SCE_RSA_2048KeyGenerate(UINT32_MAX, rsaArgs.d, rsaArgs.n,
         rsaArgs.key);
   }
   else
   {
      //Report an error
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //The value of the public exponent is fixed to 65537
      error = mpiSetValue(&privateKey->e, e);

      //Check status code
      if(!error)
      {
         //Copy the private exponent
         error = mpiReadRaw(&privateKey->d, (uint8_t *) rsaArgs.d, 256);
      }

      //Check status code
      if(!error)
      {
         //Copy the modulus
         error = mpiReadRaw(&privateKey->n, (uint8_t *) rsaArgs.n, 256);
      }

      //Check status code
      if(!error)
      {
         //Copy the first factor
         error = mpiReadRaw(&privateKey->p, (uint8_t *) rsaArgs.key + 384,
            128);
      }

      //Check status code
      if(!error)
      {
         //Copy the second factor
         error = mpiReadRaw(&privateKey->q, (uint8_t *) rsaArgs.key + 128,
            128);
      }

      //Check status code
      if(!error)
      {
         //Copy the first factor's CRT exponent
         error = mpiReadRaw(&privateKey->dp, (uint8_t *) rsaArgs.key + 256,
            128);
      }

      //Check status code
      if(!error)
      {
         //Copy the second factor's CRT exponent
         error = mpiReadRaw(&privateKey->dq, (uint8_t *) rsaArgs.key, 128);
      }

      //Check status code
      if(!error)
      {
         //Copy the CRT coefficient
         error = mpiReadRaw(&privateKey->qinv, (uint8_t *) rsaArgs.key + 512,
            128);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra6CryptoMutex);

   //Return status code
   return error;
}

#endif


/**
 * @brief RSA encryption primitive
 *
 * The RSA encryption primitive produces a ciphertext representative from
 * a message representative under the control of a public key
 *
 * @param[in] key RSA public key
 * @param[in] m Message representative
 * @param[out] c Ciphertext representative
 * @return Error code
 **/

error_t rsaep(const RsaPublicKey *key, const Mpi *m, Mpi *c)
{
   error_t error;
   fsp_err_t status;
   size_t nLen;
   size_t eLen;

   //Retrieve the length of the public key
   nLen = mpiGetByteLength(&key->n);
   eLen = mpiGetByteLength(&key->e);

   //Sanity check
   if(nLen == 0 || eLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The message representative m shall be between 0 and n - 1
   if(mpiCompInt(m, 0) < 0 || mpiComp(m, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   //Check the length of the public key
   if(nLen <= 512 && eLen <= 4)
   {
      size_t n;
      sce_oem_cmd_t command;

      //Select appropriate scalar length
      if(nLen <= 256)
      {
         command = SCE_OEM_CMD_RSA2048_PUBLIC;
         n = 256;
      }
      else if(nLen <= 384)
      {
         command = SCE_OEM_CMD_RSA3072_PUBLIC;
         n = 384;
      }
      else
      {
         command = SCE_OEM_CMD_RSA4096_PUBLIC;
         n = 512;
      }

      //Acquire exclusive access to the SCE module
      osAcquireMutex(&ra6CryptoMutex);

      //Format message representative
      mpiWriteRaw(m, (uint8_t *) rsaArgs.m, n);

      //Format public key
      mpiWriteRaw(&key->n, (uint8_t *) rsaArgs.key, n);
      mpiWriteRaw(&key->e, (uint8_t *) rsaArgs.key + n, 4);

      //Install the plaintext public key and get the wrapped key
      status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
         command, NULL, NULL, (uint8_t *) rsaArgs.key, rsaArgs.wrappedKey);

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Perform RSA encryption
         if(n == 256)
         {
            status = HW_SCE_Rsa2048ModularExponentEncryptSub(rsaArgs.wrappedKey,
               rsaArgs.m, rsaArgs.c);
         }
         else if(n == 384)
         {
            status = HW_SCE_Rsa3072ModularExponentEncryptSub(rsaArgs.wrappedKey,
               rsaArgs.m, rsaArgs.c);
         }
         else if(n == 512)
         {
            status = HW_SCE_Rsa4096ModularExponentEncryptSub(rsaArgs.wrappedKey,
               rsaArgs.m, rsaArgs.c);
         }
         else
         {
            status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
         }
      }

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Copy the ciphertext representative
         error = mpiReadRaw(c, (uint8_t *) rsaArgs.c, n);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the SCE module
      osReleaseMutex(&ra6CryptoMutex);
   }
   else
   {
      //Perform modular exponentiation (c = m ^ e mod n)
      error = mpiExpMod(c, m, &key->e, &key->n);
   }
#else
   //Check the length of the public key
   if(nLen <= 256 && eLen <= 4)
   {
      //Acquire exclusive access to the SCE module
      osAcquireMutex(&ra6CryptoMutex);

      //Format message representative
      mpiWriteRaw(m, (uint8_t *) rsaArgs.m, 256);

      //Format public key
      mpiWriteRaw(&key->n, (uint8_t *) rsaArgs.n, 256);
      mpiWriteRaw(&key->e, (uint8_t *) rsaArgs.e, 4);

      //Perform RSA encryption
      status = HW_SCE_RSA_2048PublicKeyEncrypt(rsaArgs.m, rsaArgs.e,
         rsaArgs.n, rsaArgs.c);

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Copy the ciphertext representative
         error = mpiReadRaw(c, (uint8_t *) rsaArgs.c, 256);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the SCE module
      osReleaseMutex(&ra6CryptoMutex);
   }
   else
   {
      //Perform modular exponentiation (c = m ^ e mod n)
      error = mpiExpMod(c, m, &key->e, &key->n);
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief RSA decryption primitive
 *
 * The RSA decryption primitive recovers the message representative from
 * the ciphertext representative under the control of a private key
 *
 * @param[in] key RSA private key
 * @param[in] c Ciphertext representative
 * @param[out] m Message representative
 * @return Error code
 **/

error_t rsadp(const RsaPrivateKey *key, const Mpi *c, Mpi *m)
{
   error_t error;
   size_t nLen;
   size_t dLen;
   size_t pLen;
   size_t qLen;
   size_t dpLen;
   size_t dqLen;
   size_t qinvLen;

   //Retrieve the length of the private key
   nLen = mpiGetByteLength(&key->n);
   dLen = mpiGetByteLength(&key->d);
   pLen = mpiGetByteLength(&key->p);
   qLen = mpiGetByteLength(&key->q);
   dpLen = mpiGetByteLength(&key->dp);
   dqLen = mpiGetByteLength(&key->dq);
   qinvLen = mpiGetByteLength(&key->qinv);

   //Sanity check
   if(nLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The ciphertext representative c shall be between 0 and n - 1
   if(mpiCompInt(c, 0) < 0 || mpiComp(c, &key->n) >= 0)
      return ERROR_OUT_OF_RANGE;

   //Check the length of the public key
   if(nLen <= 256 && dLen <= 256)
   {
      fsp_err_t status;

      //Acquire exclusive access to the SCE module
      osAcquireMutex(&ra6CryptoMutex);

      //Format ciphertext representative
      mpiWriteRaw(c, (uint8_t *) rsaArgs.c, 256);

      //Format private key
      mpiWriteRaw(&key->n, (uint8_t *) rsaArgs.key, 256);
      mpiWriteRaw(&key->d, (uint8_t *) rsaArgs.key + 256, 256);

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
      //Install the plaintext private key and get the wrapped key
      status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
         SCE_OEM_CMD_RSA2048_PRIVATE, NULL, NULL, (uint8_t *) rsaArgs.key,
         rsaArgs.wrappedKey);

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Perform RSA decryption
         status = HW_SCE_Rsa2048ModularExponentDecryptSub(rsaArgs.wrappedKey,
            rsaArgs.c, rsaArgs.m);
      }
#else
      //Perform RSA decryption
      status = HW_SCE_RSA_2048PrivateKeyDecrypt(rsaArgs.c, rsaArgs.key + 64,
         rsaArgs.key, rsaArgs.m);
#endif

      //Check status code
      if(status == FSP_SUCCESS)
      {
         //Copy the message representative
         error = mpiReadRaw(m, (uint8_t *) rsaArgs.m, 256);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }

      //Release exclusive access to the SCE module
      osReleaseMutex(&ra6CryptoMutex);
   }
   else if(nLen > 0 && pLen > 0 && qLen > 0 && dpLen > 0 && dqLen > 0 &&
      qinvLen > 0)
   {
      Mpi m1;
      Mpi m2;
      Mpi h;

      //Initialize multiple-precision integers
      mpiInit(&m1);
      mpiInit(&m2);
      mpiInit(&h);

      //Check the length of p, q, dp and dq
      if(pLen <= 256 && qLen <= 256 && dpLen <= 256 && dqLen <= 256)
      {
         fsp_err_t status;

         //Reduce c first
         error = mpiMod(&h, c, &key->p);

         //Check status code
         if(!error)
         {
            //Acquire exclusive access to the SCE module
            osAcquireMutex(&ra6CryptoMutex);

            //Format ciphertext representative
            mpiWriteRaw(&h, (uint8_t *) rsaArgs.c, 256);

            //Format private key
            mpiWriteRaw(&key->p, (uint8_t *) rsaArgs.key, 256);
            mpiWriteRaw(&key->dp, (uint8_t *) rsaArgs.key + 256, 256);

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
            //Install the plaintext private key and get the wrapped key
            status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
               SCE_OEM_CMD_RSA2048_PRIVATE, NULL, NULL, (uint8_t *) rsaArgs.key,
               rsaArgs.wrappedKey);

            //Check status code
            if(status == FSP_SUCCESS)
            {
               //Compute m1 = c ^ dP mod p
               status = HW_SCE_Rsa2048ModularExponentDecryptSub(rsaArgs.wrappedKey,
                  rsaArgs.c, rsaArgs.m);
            }
#else
            //Compute m1 = c ^ dP mod p
            status = HW_SCE_RSA_2048PrivateKeyDecrypt(rsaArgs.c, rsaArgs.key + 64,
               rsaArgs.key, rsaArgs.m);
#endif

            //Check status code
            if(status == FSP_SUCCESS)
            {
               error = mpiReadRaw(&m1, (uint8_t *) rsaArgs.m, 256);
            }
            else
            {
               error = ERROR_FAILURE;
            }

            //Release exclusive access to the SCE module
            osReleaseMutex(&ra6CryptoMutex);
         }

         //Check status code
         if(!error)
         {
            //Reduce c
            error = mpiMod(&h, c, &key->q);
         }

         //Check status code
         if(!error)
         {
            //Acquire exclusive access to the SCE module
            osAcquireMutex(&ra6CryptoMutex);

            //Format ciphertext representative
            mpiWriteRaw(&h, (uint8_t *) rsaArgs.c, 256);

            //Format private key
            mpiWriteRaw(&key->q, (uint8_t *) rsaArgs.key, 256);
            mpiWriteRaw(&key->dq, (uint8_t *) rsaArgs.key + 256, 256);

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
            //Install the plaintext private key and get the wrapped key
            status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
               SCE_OEM_CMD_RSA2048_PRIVATE, NULL, NULL, (uint8_t *) rsaArgs.key,
               rsaArgs.wrappedKey);

            //Check status code
            if(status == FSP_SUCCESS)
            {
               //Compute m2 = c ^ dQ mod q
               status = HW_SCE_Rsa2048ModularExponentDecryptSub(rsaArgs.wrappedKey,
                  rsaArgs.c, rsaArgs.m);
            }
#else
            //Compute m2 = c ^ dQ mod q
            status = HW_SCE_RSA_2048PrivateKeyDecrypt(rsaArgs.c, rsaArgs.key + 64,
               rsaArgs.key, rsaArgs.m);
#endif

            //Check status code
            if(status == FSP_SUCCESS)
            {
               error = mpiReadRaw(&m2, (uint8_t *) rsaArgs.m, 256);
            }
            else
            {
               error = ERROR_FAILURE;
            }

            //Release exclusive access to the SCE module
            osReleaseMutex(&ra6CryptoMutex);
         }
      }
      else
      {
         //Compute m1 = c ^ dP mod p
         error = mpiExpMod(&m1, c, &key->dp, &key->p);

         //Compute m2 = c ^ dQ mod q
         if(!error)
         {
            error = mpiExpMod(&m2, c, &key->dq, &key->q);
         }
      }

      //Let h = (m1 - m2) * qInv mod p
      if(!error)
      {
         error = mpiSub(&h, &m1, &m2);
      }

      if(!error)
      {
         error = mpiMulMod(&h, &h, &key->qinv, &key->p);
      }

      //Let m = m2 + q * h
      if(!error)
      {
         error = mpiMul(m, &key->q, &h);
      }

      if(!error)
      {
         error = mpiAdd(m, m, &m2);
      }

      //Free previously allocated memory
      mpiFree(&m1);
      mpiFree(&m2);
      mpiFree(&h);
   }
   else if(nLen > 0 && dLen > 0)
   {
      //Let m = c ^ d mod n
      error = mpiExpMod(m, c, &key->d, &key->n);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Scalar multiplication
 * @param[in] params EC domain parameters
 * @param[out] r Resulting point R = d.S
 * @param[in] d An integer d such as 0 <= d < p
 * @param[in] s EC point
 * @return Error code
 **/

error_t ecMult(const EcDomainParameters *params, EcPoint *r, const Mpi *d,
   const EcPoint *s)
{
   error_t error;
   fsp_err_t status;
   size_t n;
#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   uint32_t curveType;
   uint32_t command;
   sce_oem_cmd_t oemCommand;
#else
   size_t modLen;
#endif

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   //Check elliptic curve parameters
   if(!osStrcmp(params->name, "secp256k1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_KOBLITZ;
      oemCommand = SCE_OEM_CMD_ECC_SECP256K1_PRIVATE;
      command = 0;
      n = 32;
   }
   else if(!osStrcmp(params->name, "secp256r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P256_PRIVATE;
      command = 0;
      n = 32;
   }
   else if(!osStrcmp(params->name, "secp384r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P384_PRIVATE;
      command = 0;
      n = 48;
   }
   else if(!osStrcmp(params->name, "brainpoolP256r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P256R1_PRIVATE;
      command = 0;
      n = 32;
   }
   else if(!osStrcmp(params->name, "brainpoolP384r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P384R1_PRIVATE;
      command = 0;
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }
#else
   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);

   //Compute the length of the scalar
   if(modLen <= 32)
   {
      n = 32;
   }
   else if(modLen <= 48)
   {
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }
#endif

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra6CryptoMutex);

   //Set scalar value
   mpiWriteRaw(d, (uint8_t *) ecArgs.d, n);

   //Set input point
   mpiWriteRaw(&s->x, (uint8_t *) ecArgs.g, n);
   mpiWriteRaw(&s->y, (uint8_t *) ecArgs.g + n, n);

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   //Install the plaintext private key and get the wrapped key
   status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
      oemCommand, NULL, NULL, (uint8_t *) ecArgs.d, ecArgs.wrappedKey);

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Perform scalar multiplication
      if(n == 32)
      {
         status = HW_SCE_ECC_256WrappedScalarMultiplication(&curveType,
            &command, ecArgs.wrappedKey, ecArgs.g, ecArgs.q);
      }
      else if(n == 48)
      {
         status = HW_SCE_ECC_384WrappedScalarMultiplication(&curveType,
            &command, ecArgs.wrappedKey, ecArgs.g, ecArgs.q);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }
#else
   //Set domain parameters
   mpiWriteRaw(&params->a, (uint8_t *) ecArgs.params, n);
   mpiWriteRaw(&params->b, (uint8_t *) ecArgs.params + n, n);
   mpiWriteRaw(&params->p, (uint8_t *) ecArgs.params + n * 2, n);
   mpiWriteRaw(&params->q, (uint8_t *) ecArgs.params + n * 3, n);

   //Perform scalar multiplication
   if(n == 32)
   {
      status = HW_SCE_ECC_256ScalarMultiplication(ecArgs.params, ecArgs.d,
         ecArgs.g, ecArgs.q);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384ScalarMultiplication(ecArgs.params, ecArgs.d,
         ecArgs.g, ecArgs.q);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }
#endif

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the x-coordinate of the result
      error = mpiReadRaw(&r->x, (uint8_t *) ecArgs.q, n);

      //Check status code
      if(!error)
      {
         //Copy the y-coordinate of the result
         error = mpiReadRaw(&r->y, (uint8_t *) ecArgs.q + n, n);
      }

      //Check status code
      if(!error)
      {
         //Set the z-coordinate of the result
         error = mpiSetValue(&r->z, 1);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra6CryptoMutex);

   //Return status code
   return error;
}


#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
#else

/**
 * @brief EC key pair generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] params EC domain parameters
 * @param[out] privateKey EC private key
 * @param[out] publicKey EC public key
 * @return Error code
 **/

error_t ecGenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, EcPrivateKey *privateKey,
   EcPublicKey *publicKey)
{
   error_t error;
   fsp_err_t status;
   size_t n;
   size_t modLen;

   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);

   //Compute the length of the scalar
   if(modLen <= 32)
   {
      n = 32;
   }
   else if(modLen <= 48)
   {
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra6CryptoMutex);

   //Set domain parameters
   mpiWriteRaw(&params->a, (uint8_t *) ecArgs.params, n);
   mpiWriteRaw(&params->b, (uint8_t *) ecArgs.params + n, n);
   mpiWriteRaw(&params->p, (uint8_t *) ecArgs.params + n * 2, n);
   mpiWriteRaw(&params->q, (uint8_t *) ecArgs.params + n * 3, n);

   //Set base point
   mpiWriteRaw(&params->g.x, (uint8_t *) ecArgs.g, n);
   mpiWriteRaw(&params->g.y, (uint8_t *) ecArgs.g + n, n);

   //Generate an EC key pair
   if(n == 32)
   {
      status = HW_SCE_ECC_256GenerateKey(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.q);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384GenerateKey(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.q);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy the private key
      error = mpiReadRaw(&privateKey->d, (uint8_t *) ecArgs.d, n);

      //Check status code
      if(!error)
      {
         //Copy the x-coordinate of the public key
         error = mpiReadRaw(&publicKey->q.x, (uint8_t *) ecArgs.q, n);
      }

      //Check status code
      if(!error)
      {
         //Copy the y-coordinate of the public key
         error = mpiReadRaw(&publicKey->q.y, (uint8_t *) ecArgs.q + n, n);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra6CryptoMutex);

   //Return status code
   return error;
}

#endif


/**
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] params EC domain parameters
 * @param[in] privateKey Signer's EC private key
 * @param[in] digest Digest of the message to be signed
 * @param[in] digestLen Length in octets of the digest
 * @param[out] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const EcDomainParameters *params, const EcPrivateKey *privateKey,
   const uint8_t *digest, size_t digestLen, EcdsaSignature *signature)
{
   error_t error;
   fsp_err_t status;
   size_t n;
   size_t orderLen;
#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   uint32_t curveType;
   uint32_t command;
   sce_oem_cmd_t oemCommand;
#else
   size_t modLen;
#endif

   //Check parameters
   if(params == NULL || privateKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the base point order, in bytes
   orderLen = mpiGetByteLength(&params->q);

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   //Check elliptic curve parameters
   if(!osStrcmp(params->name, "secp256k1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_KOBLITZ;
      oemCommand = SCE_OEM_CMD_ECC_SECP256K1_PRIVATE;
      command = 0;
      n = 32;
   }
   else if(!osStrcmp(params->name, "secp256r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P256_PRIVATE;
      command = 0;
      n = 32;
   }
   else if(!osStrcmp(params->name, "secp384r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P384_PRIVATE;
      command = 0;
      n = 48;
   }
   else if(!osStrcmp(params->name, "brainpoolP256r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P256R1_PRIVATE;
      command = 0;
      n = 32;
   }
   else if(!osStrcmp(params->name, "brainpoolP384r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P384R1_PRIVATE;
      command = 0;
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }
#else
   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);

   //Check elliptic curve parameters
   if(modLen <= 32 && orderLen <= 32)
   {
      n = 32;
   }
   else if(modLen <= 48 && orderLen <= 48)
   {
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }
#endif

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, orderLen);

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra6CryptoMutex);

   //Pad the digest with leading zeroes if necessary
   osMemset(ecArgs.digest, 0, n);
   osMemcpy((uint8_t *) ecArgs.digest + n - digestLen, digest, digestLen);

   //Set private key
   mpiWriteRaw(&privateKey->d, (uint8_t *) ecArgs.d, n);

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   //Install the plaintext private key and get the wrapped key
   status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
      oemCommand, NULL, NULL, (uint8_t *) ecArgs.d, ecArgs.wrappedKey);

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Verify ECDSA signature
      if(n == 32)
      {
         status = HW_SCE_EcdsaSignatureGenerateSub(&curveType, &command,
            ecArgs.wrappedKey, ecArgs.digest, ecArgs.signature);
      }
      else if(n == 48)
      {
         status = HW_SCE_EcdsaP384SignatureGenerateSub(&curveType,
            ecArgs.wrappedKey, ecArgs.digest, ecArgs.signature);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }
#else
   //Set domain parameters
   mpiWriteRaw(&params->a, (uint8_t *) ecArgs.params, n);
   mpiWriteRaw(&params->b, (uint8_t *) ecArgs.params + n, n);
   mpiWriteRaw(&params->p, (uint8_t *) ecArgs.params + n * 2, n);
   mpiWriteRaw(&params->q, (uint8_t *) ecArgs.params + n * 3, n);

   //Set base point
   mpiWriteRaw(&params->g.x, (uint8_t *) ecArgs.g, n);
   mpiWriteRaw(&params->g.y, (uint8_t *) ecArgs.g + n, n);

   //Generate ECDSA signature
   if(n == 32)
   {
      status = HW_SCE_ECC_256GenerateSign(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.digest, ecArgs.signature, ecArgs.signature + 8);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384GenerateSign(ecArgs.params, ecArgs.g, ecArgs.d,
         ecArgs.digest, ecArgs.signature, ecArgs.signature + 12);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }
#endif

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Copy integer R
      error = mpiReadRaw(&signature->r, (uint8_t *) ecArgs.signature, n);

      //Check status code
      if(!error)
      {
         //Copy integer S
         error = mpiReadRaw(&signature->s, (uint8_t *) ecArgs.signature + n, n);
      }
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra6CryptoMutex);

   //Return status code
   return error;
}


/**
 * @brief ECDSA signature verification
 * @param[in] params EC domain parameters
 * @param[in] publicKey Signer's EC public key
 * @param[in] digest Digest of the message whose signature is to be verified
 * @param[in] digestLen Length in octets of the digest
 * @param[in] signature (R, S) integer pair
 * @return Error code
 **/

error_t ecdsaVerifySignature(const EcDomainParameters *params,
   const EcPublicKey *publicKey, const uint8_t *digest, size_t digestLen,
   const EcdsaSignature *signature)
{
   fsp_err_t status;
   size_t n;
   size_t orderLen;
#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   uint32_t curveType;
   uint32_t command;
   sce_oem_cmd_t oemCommand;
#else
   size_t modLen;
#endif

   //Check parameters
   if(params == NULL || publicKey == NULL || digest == NULL || signature == NULL)
      return ERROR_INVALID_PARAMETER;

   //The verifier shall check that 0 < r < q
   if(mpiCompInt(&signature->r, 0) <= 0 ||
      mpiComp(&signature->r, &params->q) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //The verifier shall check that 0 < s < q
   if(mpiCompInt(&signature->s, 0) <= 0 ||
      mpiComp(&signature->s, &params->q) >= 0)
   {
      //If the condition is violated, the signature shall be rejected as invalid
      return ERROR_INVALID_SIGNATURE;
   }

   //Retrieve the length of the base point order, in bytes
   orderLen = mpiGetByteLength(&params->q);

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   //Check elliptic curve parameters
   if(!osStrcmp(params->name, "secp256k1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_KOBLITZ;
      oemCommand = SCE_OEM_CMD_ECC_SECP256K1_PUBLIC;
      command = 0;
      n = 32;
   }
   else if(!osStrcmp(params->name, "secp256r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P256_PUBLIC;
      command = 0;
      n = 32;
   }
   else if(!osStrcmp(params->name, "secp384r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_NIST;
      oemCommand = SCE_OEM_CMD_ECC_P384_PUBLIC;
      command = 0;
      n = 48;
   }
   else if(!osStrcmp(params->name, "brainpoolP256r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P256R1_PUBLIC;
      command = 0;
      n = 32;
   }
   else if(!osStrcmp(params->name, "brainpoolP384r1"))
   {
      curveType = SCE_ECC_CURVE_TYPE_BRAINPOOL;
      oemCommand = SCE_OEM_CMD_ECC_P384R1_PUBLIC;
      command = 0;
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }
#else
   //Retrieve the length of the modulus, in bytes
   modLen = mpiGetByteLength(&params->p);

   //Check elliptic curve parameters
   if(modLen <= 32 && orderLen <= 32)
   {
      n = 32;
   }
   else if(modLen <= 48 && orderLen <= 48)
   {
      n = 48;
   }
   else
   {
      return ERROR_FAILURE;
   }
#endif

   //Keep the leftmost bits of the hash value
   digestLen = MIN(digestLen, orderLen);

   //Acquire exclusive access to the SCE module
   osAcquireMutex(&ra6CryptoMutex);

   //Pad the digest with leading zeroes if necessary
   osMemset(ecArgs.digest, 0, n);
   osMemcpy((uint8_t *) ecArgs.digest + n - digestLen, digest, digestLen);

   //Set public key
   mpiWriteRaw(&publicKey->q.x, (uint8_t *) ecArgs.q, n);
   mpiWriteRaw(&publicKey->q.y, (uint8_t *) ecArgs.q + n, n);

   //Set signature
   mpiWriteRaw(&signature->r, (uint8_t *) ecArgs.signature, n);
   mpiWriteRaw(&signature->s, (uint8_t *) ecArgs.signature + n, n);

#if (BSP_FEATURE_CRYPTO_HAS_SCE9 != 0)
   //Install the plaintext public key and get the wrapped key
   status = HW_SCE_GenerateOemKeyIndexPrivate(SCE_OEM_KEY_TYPE_PLAIN,
      oemCommand, NULL, NULL, (uint8_t *) ecArgs.q, ecArgs.wrappedKey);

   //Check status code
   if(status == FSP_SUCCESS)
   {
      //Verify ECDSA signature
      if(n == 32)
      {
         status = HW_SCE_EcdsaSignatureVerificationSub(&curveType, &command,
            ecArgs.wrappedKey, ecArgs.digest, ecArgs.signature);
      }
      else if(n == 48)
      {
         status = HW_SCE_EcdsaP384SignatureVerificationSub(&curveType,
            ecArgs.wrappedKey, ecArgs.digest, ecArgs.signature);
      }
      else
      {
         status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
      }
   }
#else
   //Set domain parameters
   mpiWriteRaw(&params->a, (uint8_t *) ecArgs.params, n);
   mpiWriteRaw(&params->b, (uint8_t *) ecArgs.params + n, n);
   mpiWriteRaw(&params->p, (uint8_t *) ecArgs.params + n * 2, n);
   mpiWriteRaw(&params->q, (uint8_t *) ecArgs.params + n * 3, n);

   //Set base point
   mpiWriteRaw(&params->g.x, (uint8_t *) ecArgs.g, n);
   mpiWriteRaw(&params->g.y, (uint8_t *) ecArgs.g + n, n);

   //Verify ECDSA signature
   if(n == 32)
   {
      status = HW_SCE_ECC_256VerifySign(ecArgs.params, ecArgs.g, ecArgs.q,
         ecArgs.digest, ecArgs.signature, ecArgs.signature + 8);
   }
   else if(n == 48)
   {
      status = HW_SCE_ECC_384VerifySign(ecArgs.params, ecArgs.g, ecArgs.q,
         ecArgs.digest, ecArgs.signature, ecArgs.signature + 12);
   }
   else
   {
      status = FSP_ERR_CRYPTO_NOT_IMPLEMENTED;
   }
#endif

   //Release exclusive access to the SCE module
   osReleaseMutex(&ra6CryptoMutex);

   //Return status code
   return (status == FSP_SUCCESS) ? NO_ERROR : ERROR_INVALID_SIGNATURE;
}

#endif
