/**
 * @file bcrypt.c
 * @brief bcrypt password hashing function
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
#include "kdf/bcrypt.h"
#include "cipher_modes/ecb.h"
#include "encoding/radix64.h"

//Check crypto library configuration
#if (BCRYPT_SUPPORT == ENABLED)


/**
 * @brief Password hashing function
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] cost Key expansion iteration count as a power of two
 * @param[in] password NULL-terminated password to be encoded
 * @param[out] hash NULL-terminated hash string
 * @param[out] hashLen Length of the hash string (optional parameter)
 * @return Error code
 **/

error_t bcryptHashPassword(const PrngAlgo *prngAlgo, void *prngContext,
   uint_t cost, const char_t *password, char_t *hash, size_t *hashLen)
{
   error_t error;
   uint8_t salt[16];

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL || password == NULL ||
      hash == NULL)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Generate a 16-byte random salt
   error = prngAlgo->read(prngContext, salt, sizeof(salt));

   //Check status code
   if(!error)
   {
      //Hash the password using bcrypt algorithm
      error = bcrypt(cost, salt, password, hash, hashLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Password verification function
 * @param[in] password NULL-terminated password to be checked
 * @param[in] hash NULL-terminated hash string
 * @return Error code
 **/

error_t bcryptVerifyPassword(const char_t *password, const char_t *hash)
{
   error_t error;
   size_t i;
   size_t n;
   uint_t cost;
   uint8_t mask;
   char_t *p;
   uint8_t salt[16];
   char_t temp[BCRYPT_HASH_STRING_LEN + 1];

   //Check parameters
   if(password == NULL || hash == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the hash string
   if(osStrlen(hash) != BCRYPT_HASH_STRING_LEN)
      return ERROR_INVALID_PASSWORD;

   //bcrypt uses the $2a$ prefix in the hash string
   if(osMemcmp(hash, "$2a$", 4))
      return ERROR_INVALID_PASSWORD;

   //Parse cost parameter
   cost = osStrtoul(hash + 4, &p, 10);

   //Malformed hash string?
   if(p != (hash + 6) || *p != '$')
      return ERROR_INVALID_PASSWORD;

   //Check the value of the cost parameter
   if(cost < BCRYPT_MIN_COST || cost > BCRYPT_MAX_COST)
      return ERROR_INVALID_PASSWORD;

   //Parse salt parameter
   error = radix64Decode(hash + 7, 22, salt, &n);
   //Any error to report?
   if(error)
      return error;

   //Hash the password using bcrypt algorithm
   error = bcrypt(cost, salt, password, temp, &n);
   //Any error to report?
   if(error)
      return error;

   //The calculated string is bitwise compared to the hash string. The
   //password is correct if and only if the strings match
   for(mask = 0, i = 0; i < BCRYPT_HASH_STRING_LEN; i++)
   {
      mask |= temp[i] ^ hash[i];
   }

   //Return status code
   return (mask == 0) ? NO_ERROR : ERROR_INVALID_PASSWORD;
}


/**
 * @brief bcrypt algorithm
 * @param[in] cost Key expansion iteration count as a power of two
 * @param[in] salt Random salt (16 bytes)
 * @param[in] password NULL-terminated password to be encoded
 * @param[out] hash NULL-terminated hash string
 * @param[out] hashLen Length of the hash string (optional parameter)
 * @return Error code
 **/

error_t bcrypt(uint_t cost, const uint8_t *salt, const char_t *password,
   char_t *hash, size_t *hashLen)
{
   error_t error;
   uint_t i;
   size_t n;
   size_t length;
   BlowfishContext *context;
   uint8_t buffer[24];

   //Check parameters
   if(salt == NULL || password == NULL || hash == NULL)
      return ERROR_INVALID_PARAMETER;

   //Allocate a memory buffer to hold the Blowfish context
   context = cryptoAllocMem(sizeof(BlowfishContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Calculate the length of the password (including the NULL-terminator byte)
      length = osStrlen(password) + 1;

      //The key setup begins with a modified form of the standard Blowfish key
      //setup, in which both the salt and password are used to set all subkeys
      error = eksBlowfishSetup(context, cost, salt, 16, password, length);

      //Check status code
      if(!error)
      {
         //Initialize plaintext
         osMemcpy(buffer, "OrpheanBeholderScryDoubt", 24);

         //Repeatedly encrypt the text "OrpheanBeholderScryDoubt" 64 times
         for(i = 0; i < 64 && !error; i++)
         {
            //Perform encryption using Blowfish in ECB mode
            error = ecbEncrypt(BLOWFISH_CIPHER_ALGO, context, buffer, buffer, 24);
         }
      }

      //Release Blowfish context
      cryptoFreeMem(context);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Check status code
   if(!error)
   {
      //bcrypt uses the $2a$ prefix in the hash string
      length = osSprintf(hash, "$2a$%02u$", cost);

      //Concatenate the salt and the ciphertext
      radix64Encode(salt, 16, hash + length, &n);
      length += n;
      radix64Encode(buffer, 23, hash + length, &n);
      length += n;

      //Return the length of the resulting hash string
      if(hashLen != NULL)
      {
         *hashLen = length;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Expensive key setup
 * @param[in] context Pointer to the Blowfish context
 * @param[in] cost Key expansion iteration count as a power of 2
 * @param[in] salt Random salt
 * @param[in] saltLen Length of the random salt, in bytes
 * @param[in] password NULL-terminated password to be encoded
 * @param[in] passwordLen Length of the password, in bytes
 * @return Error code
 **/

error_t eksBlowfishSetup(BlowfishContext *context, uint_t cost,
   const uint8_t *salt, size_t saltLen, const char_t *password,
   size_t passwordLen)
{
   error_t error;
   uint32_t i;
   uint32_t n;

   //Check the value of the cost parameter
   if(cost < BCRYPT_MIN_COST || cost > BCRYPT_MAX_COST)
      return ERROR_INVALID_PARAMETER;

   //The cost parameter specifies a key expansion iteration count as a power
   //of two
   n = 1U << cost;

   //Initialize Blowfish state
   error = blowfishInitState(context);

   //Check status code
   if(!error)
   {
      //Perform the first key expansion
      error = blowfishExpandKey(context, salt, saltLen, (uint8_t *) password,
         passwordLen);
   }

   //Check status code
   if(!error)
   {
      //Iterate as many times as desired
      for(i = 0; i < n; i++)
      {
         //Perform key expansion with password
         error = blowfishExpandKey(context, NULL, 0, (uint8_t *) password,
            passwordLen);
         //Any error to report?
         if(error)
            break;

         //Perform key expansion with salt
         error = blowfishExpandKey(context, NULL, 0, salt, saltLen);
         //Any error to report?
         if(error)
            break;
      }
   }

   //Return status code
   return error;
}

#endif
