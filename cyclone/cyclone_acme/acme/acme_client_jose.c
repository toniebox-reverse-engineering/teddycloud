/**
 * @file acme_client_jose.c
 * @brief JOSE (JSON Object Signing and Encryption)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneACME Open.
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
#define TRACE_LEVEL ACME_TRACE_LEVEL

//Dependencies
#include "acme/acme_client.h"
#include "acme/acme_client_jose.h"
#include "encoding/base64url.h"
#include "jansson.h"
#include "jansson_private.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Export an RSA public key to JWK format
 * @param[in] publicKey RSA public key
 * @param[out] buffer Output buffer where to store the JSON representation
 * @param[out] written Length of the resulting JSON representation
 * @param[in] sort Sort members of the JWK representation in lexicographic order
 * @return Error code
 **/

error_t jwkExportRsaPublicKey(const RsaPublicKey *publicKey, char_t *buffer,
   size_t *written, bool_t sort)
{
   error_t error;
   int_t ret;
   size_t n;
   uint_t flags;
   char_t *s;
   json_t *rootObj;

   //Initialize status code
   error = NO_ERROR;

   //Initialize variables
   ret = 0;
   s = NULL;

   //Initialize JSON object
   rootObj = json_object();

   //Start of exception handling block
   do
   {
      //The "kty" (key type) parameter identifies the cryptographic algorithm
      //family used with the key (refer to RFC 7517, section 4.1)
      ret = json_object_set_new(rootObj, "kty", json_string("RSA"));
      //Any error to report?
      if(ret != 0)
         break;

      //The octet sequence must utilize the minimum number of octets to
      //represent the RSA modulus (refer to RFC 7518, section 6.3.1.1)
      n = mpiGetByteLength(&publicKey->n);

      //Convert the RSA modulus to an octet string
      error = mpiExport(&publicKey->n, (uint8_t *) buffer, n,
         MPI_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         break;

      //Integers are represented using the base64url encoding of their
      //big-endian representations
      base64urlEncode(buffer, n, buffer, &n);

      //Format "n" parameter
      ret = json_object_set_new(rootObj, "n", json_string(buffer));
      //Any error to report?
      if(ret != 0)
         break;

      //Retrieve the length of the RSA public exponent
      n = mpiGetByteLength(&publicKey->e);

      //Convert the RSA public exponent to an octet string
      error = mpiExport(&publicKey->e, (uint8_t *) buffer, n,
         MPI_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         break;

      //Integers are represented using the base64url encoding of their
      //big-endian representations
      base64urlEncode(buffer, n, buffer, &n);

      //Format "e" parameter
      ret = json_object_set_new(rootObj, "e", json_string(buffer));
      //Any error to report?
      if(ret != 0)
         break;

      //If this sort parameter is set, all the keys of the JWK representation
      //are sorted in lexicographic order
      flags = sort ? (JSON_COMPACT | JSON_SORT_KEYS) : JSON_COMPACT;

      //Generate the JSON representation of the JWK object
      s = json_dumps(rootObj, flags);

      //End of exception handling block
   } while(0);

   //Valid JSON representation?
   if(s != NULL)
   {
      //Copy JSON string
      osStrcpy(buffer, s);
      //Total number of bytes that have been written
      *written = osStrlen(s);

      //Release JSON string
      jsonp_free(s);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release JSON object
   json_decref(rootObj);

   //Return status code
   return error;
}


/**
 * @brief Export an EC public key to JWK format
 * @param[in] params EC domain parameters
 * @param[in] publicKey EC public key
 * @param[out] buffer Output buffer where to store the JSON representation
 * @param[out] written Length of the resulting JSON representation
 * @param[in] sort Sort members of the JWK representation in lexicographic order
 * @return Error code
 **/

error_t jwkExportEcPublicKey(const EcDomainParameters *params,
   const EcPublicKey *publicKey, char_t *buffer, size_t *written, bool_t sort)
{
   error_t error;
   int_t ret;
   size_t n;
   uint_t flags;
   char_t *s;
   const char_t *crv;
   json_t *rootObj;

   //Initialize status code
   error = NO_ERROR;

   //Initialize variables
   ret = 0;
   s = NULL;

   //Initialize JSON object
   rootObj = json_object();

   //Start of exception handling block
   do
   {
      //The "kty" (key type) parameter identifies the cryptographic algorithm
      //family used with the key (refer to RFC 7517, section 4.1)
      ret = json_object_set_new(rootObj, "kty", json_string("EC"));
      //Any error to report?
      if(ret != 0)
         break;

      //The "crv" (curve) parameter identifies the cryptographic curve used
      //with the key (refer to RFC 7518, section 6.2.1.1)
      if(!osStrcmp(params->name, "secp256r1"))
      {
         //Select NIST P-256 elliptic curve
         crv = "P-256";
      }
      else if(!osStrcmp(params->name, "secp384r1"))
      {
         //Select NIST P-384 elliptic curve
         crv = "P-384";
      }
      else if(!osStrcmp(params->name, "secp521r1"))
      {
         //Select NIST P-521 elliptic curve
         crv = "P-521";
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_IDENTIFIER;
         break;
      }

      //Format "crv" parameter
      ret |= json_object_set_new(rootObj, "crv", json_string(crv));
      //Any error to report?
      if(ret != 0)
         break;

      //The length of the "x" octet string must be the full size of the
      //x-coordinate for the curve specified in the "crv" parameter (refer
      //to RFC 7518, section 6.2.1.2)
      n = mpiGetByteLength(&params->p);

      //Convert the x-coordinate to an octet string
      error = mpiExport(&publicKey->q.x, (uint8_t *) buffer, n,
         MPI_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         break;

      //Integers are represented using the base64url encoding of their
      //big-endian representations
      base64urlEncode(buffer, n, buffer, &n);

      //Format "x" parameter
      ret = json_object_set_new(rootObj, "x", json_string(buffer));
      //Any error to report?
      if(ret != 0)
         break;

      //The length of the "y" octet string must be the full size of the
      //y-coordinate for the curve specified in the "crv" parameter (refer
      //to RFC 7518, section 6.2.1.3)
      n = mpiGetByteLength(&params->p);

      //Convert the y-coordinate to an octet string
      error = mpiExport(&publicKey->q.y, (uint8_t *) buffer, n,
         MPI_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         break;

      //Integers are represented using the base64url encoding of their
      //big-endian representations
      base64urlEncode(buffer, n, buffer, &n);

      //Format "y" parameter
      ret = json_object_set_new(rootObj, "y", json_string(buffer));
      //Any error to report?
      if(ret != 0)
         break;

      //If this sort parameter is set, all the keys of the JWK representation
      //are sorted in lexicographic order
      flags = sort ? (JSON_COMPACT | JSON_SORT_KEYS) : JSON_COMPACT;

      //Generate the JSON representation of the JWK object
      s = json_dumps(rootObj, flags);

      //End of exception handling block
   } while(0);

   //Valid JSON representation?
   if(s != NULL)
   {
      //Copy JSON string
      osStrcpy(buffer, s);
      //Total number of bytes that have been written
      *written = osStrlen(s);

      //Release JSON string
      jsonp_free(s);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release JSON object
   json_decref(rootObj);

   //Return status code
   return error;
}


/**
 * @brief Export an EdDSA public key to JWK format
 * @param[in] crv Subtype of the key
 * @param[in] publicKey EdDSA public key
 * @param[out] buffer Output buffer where to store the JSON representation
 * @param[out] written Length of the resulting JSON representation
 * @param[in] sort Sort members of the JWK representation in lexicographic order
 * @return Error code
 **/

error_t jwkExportEddsaPublicKey(const char_t *crv,
   const EddsaPublicKey *publicKey, char_t *buffer, size_t *written,
   bool_t sort)
{
   error_t error;
   int_t ret;
   size_t n;
   uint_t flags;
   char_t *s;
   json_t *rootObj;

   //Initialize status code
   error = NO_ERROR;

   //Initialize variables
   ret = 0;
   s = NULL;

   //Initialize JSON object
   rootObj = json_object();

   //Start of exception handling block
   do
   {
      //The parameter "kty" must be "OKP" (refer to RFC 8037, section 2)
      ret = json_object_set_new(rootObj, "kty", json_string("OKP"));
      //Any error to report?
      if(ret != 0)
         break;

      //The parameter "crv" must be present and contain the subtype of the key
      ret |= json_object_set_new(rootObj, "crv", json_string(crv));
      //Any error to report?
      if(ret != 0)
         break;

      //Retrieve the length of the public key
      if(!osStrcmp(crv, "Ed25519"))
      {
         //The public key consists of 32 octets
         n = 32;
      }
      else if(!osStrcmp(crv, "Ed448"))
      {
         //The public key consists of 57 octets
         n = 57;
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_IDENTIFIER;
         break;
      }

      //Convert the public key to an octet string
      error = mpiExport(&publicKey->q, (uint8_t *) buffer, n,
         MPI_FORMAT_BIG_ENDIAN);
      //Any error to report?
      if(error)
         break;

      //Integers are represented using the base64url encoding of their
      //big-endian representations
      base64urlEncode(buffer, n, buffer, &n);

      //Format "x" parameter
      ret = json_object_set_new(rootObj, "x", json_string(buffer));
      //Any error to report?
      if(ret != 0)
         break;

      //If this sort parameter is set, all the keys of the JWK representation
      //are sorted in lexicographic order
      flags = sort ? (JSON_COMPACT | JSON_SORT_KEYS) : JSON_COMPACT;

      //Generate the JSON representation of the JWK object
      s = json_dumps(rootObj, flags);

      //End of exception handling block
   } while(0);

   //Valid JSON representation?
   if(s != NULL)
   {
      //Copy JSON string
      osStrcpy(buffer, s);
      //Total number of bytes that have been written
      *written = osStrlen(s);

      //Release JSON string
      jsonp_free(s);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release JSON object
   json_decref(rootObj);

   //Return status code
   return error;
}


/**
 * @brief Create a JSON Web Signature
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] protected Pointer to the JWS protected header
 * @param[in] payload Pointer to the JWS payload
 * @param[in] alg Cryptographic algorithm used to secure the JWS
 * @param[in] crv Subtype of the key
 * @param[in] privateKey Pointer to the signer's private key
 * @param[out] buffer JSON structure representing the digitally signed
 *   or MACed message
 * @param[out] written Length of the resulting JSON structure
 * @return Error code
 **/

error_t jwsCreate(const PrngAlgo *prngAlgo, void *prngContext,
   const char_t *protected, const char_t *payload, const char_t *alg,
   const char_t *crv, const void *privateKey, char_t *buffer, size_t *written)
{
   error_t error;
   int_t ret;
   size_t n;
   char_t *p;
   char_t *s;
   json_t *rootObj;

   //Debug message
   TRACE_DEBUG("JWS protected header (%" PRIuSIZE " bytes):\r\n", osStrlen(protected));
   TRACE_DEBUG("%s\r\n\r\n", protected);
   TRACE_DEBUG("JWS payload (%" PRIuSIZE " bytes):\r\n", osStrlen(payload));
   TRACE_DEBUG("%s\r\n\r\n", payload);

   //Initialize status code
   error = NO_ERROR;

   //Initialize variables
   ret = 0;
   s = NULL;

   //Initialize JSON object
   rootObj = json_object();

   //Start of exception handling block
   do
   {
      //Point to the beginning of the buffer
      p = buffer;

      //Encode the JWS protected header using Base64url
      base64urlEncode(protected, osStrlen(protected), p, &n);

      //The "protected" member must be present and contain the value of the
      //Base64url-encoded JWS protected header (refer to RFC 7515, section 7.2.1)
      ret = json_object_set_new(rootObj, "protected", json_string(p));
      //Any error to report?
      if(ret != 0)
         break;

      //Advance write pointer
      p += n;

      //Insert a '.' character between the Base64url-encoded JWS protected
      //header and JWS payload
      *(p++) = '.';

      //Encode the JWS payload value using Base64url
      base64urlEncode(payload, osStrlen(payload), p, &n);

      //The "payload" member must be present and contain the value of the
      //Base64url-encoded JWS payload (refer to RFC 7515, section 7.2.1)
      ret = json_object_set_new(rootObj, "payload", json_string(p));
      //Any error to report?
      if(ret != 0)
         break;

      //Advance write pointer
      p += n;
      //Compute the length of the JWS signing input
      n = p - buffer;

      //Compute the JWS Signature in the manner defined for the particular
      //algorithm being used over the JWS signing input (refer to RFC 7515,
      //section 5.1)
      error = jwsGenerateSignature(prngAlgo, prngContext, alg, crv,
         privateKey, buffer, n, (uint8_t *) buffer, &n);
      //Any error to report?
      if(error)
         break;

      //Encode the JWS signature using Base64url
      base64urlEncode(buffer, n, buffer, &n);

      //The "signature" member must be present and contain the value of the
      //Base64url-encoded JWS Signature (refer to RFC 7515, section 7.2.1)
      ret = json_object_set_new(rootObj, "signature", json_string(buffer));
      //Any error to report?
      if(ret != 0)
         break;

      //Generate the JSON representation of the JWS object
      s = json_dumps(rootObj, JSON_COMPACT);

      //End of exception handling block
   } while(0);

   //Valid JSON representation?
   if(s != NULL)
   {
      //Debug message
      TRACE_DEBUG("JWS (%" PRIuSIZE " bytes):\r\n", osStrlen(s));
      TRACE_DEBUG("%s\r\n\r\n", s);

      //Copy JSON string
      osStrcpy(buffer, s);
      //Total number of bytes that have been written
      *written = osStrlen(s);

      //Release JSON string
      jsonp_free(s);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release JSON object
   json_decref(rootObj);

   //Return status code
   return error;
}


/**
 * @brief Compute JWS signature using the specified algorithm
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] alg Cryptographic algorithm used to secure the JWS
 * @param[in] crv Subtype of the key
 * @param[in] privateKey Pointer to the signer's private key
 * @param[in] input Pointer to the JWS signing input
 * @param[in] inputLen Length of the JWS signing input
 * @param[out] output Buffer where to store the JWS signature
 * @param[out] outputLen Length of the JWS signature
 * @return Error code
 **/

error_t jwsGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const char_t *alg, const char_t *crv, const void *privateKey,
   const char_t *input, size_t inputLen, uint8_t *output, size_t *outputLen)
{
   error_t error;

#if (ACME_CLIENT_RSA_SUPPORT == ENABLED)
   //RSASSA-PKCS1-v1_5 algorithm?
   if(!osStrcmp(alg, "RS256") || !osStrcmp(alg, "RS384") || !osStrcmp(alg, "RS512"))
   {
      const HashAlgo *hashAlgo;
      uint8_t digest[SHA512_DIGEST_SIZE];

      //Select the relevant signature algorithm
      if(!osStrcmp(alg, "RS256"))
      {
         //RSASSA-PKCS1-v1_5 algorithm with SHA-256
         hashAlgo = SHA256_HASH_ALGO;
      }
      else if(!osStrcmp(alg, "RS384"))
      {
         //RSASSA-PKCS1-v1_5 algorithm with SHA-384
         hashAlgo = SHA384_HASH_ALGO;
      }
      else if(!osStrcmp(alg, "RS512"))
      {
         //RSASSA-PKCS1-v1_5 algorithm with SHA-512
         hashAlgo = SHA512_HASH_ALGO;
      }
      else
      {
         //Just for sanity
         hashAlgo = NULL;
      }

      //Valid hash algorithm?
      if(hashAlgo != NULL)
      {
         //Digest the JWS signing input
         error = hashAlgo->compute(input, inputLen, digest);
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_SIGNATURE_ALGO;
      }

      //Check status code
      if(!error)
      {
         //Generate RSA signature
         error = rsassaPkcs1v15Sign(privateKey, hashAlgo, digest, output,
            outputLen);
      }
   }
   else
#endif
#if (ACME_CLIENT_ECDSA_SUPPORT == ENABLED)
   //ECDSA algorithm?
   if(!osStrcmp(alg, "ES256") || !osStrcmp(alg, "ES384") || !osStrcmp(alg, "ES512"))
   {
      size_t n;
      const HashAlgo *hashAlgo;
      const EcCurveInfo *curveInfo;
      EcDomainParameters params;
      EcdsaSignature signature;
      uint8_t digest[SHA512_DIGEST_SIZE];

      //Initialize EC domain parameters
      ecInitDomainParameters(&params);
      //Initialize ECDSA signature
      ecdsaInitSignature(&signature);

      //Select the relevant signature algorithm
      if(!osStrcmp(alg, "ES256"))
      {
         //ECDSA algorithm using P-256 and SHA-256
         curveInfo = SECP256R1_CURVE;
         hashAlgo = SHA256_HASH_ALGO;
      }
      else if(!osStrcmp(alg, "ES384"))
      {
         //ECDSA algorithm using P-384 and SHA-384
         curveInfo = SECP384R1_CURVE;
         hashAlgo = SHA384_HASH_ALGO;
      }
      else if(!osStrcmp(alg, "ES512"))
      {
         //ECDSA algorithm using P-521 and SHA-512
         curveInfo = SECP521R1_CURVE;
         hashAlgo = SHA512_HASH_ALGO;
      }
      else
      {
         //Just for sanity
         curveInfo = NULL;
         hashAlgo = NULL;
      }

      //Valid signature algorithm?
      if(curveInfo != NULL && hashAlgo != NULL)
      {
         //Load EC domain parameters
         error = ecLoadDomainParameters(&params, curveInfo);
      }
      else
      {
         //Report an error
         error = ERROR_INVALID_SIGNATURE_ALGO;
      }

      //Check status code
      if(!error)
      {
         //Digest the JWS signing input
         error = hashAlgo->compute(input, inputLen, digest);
      }

      //Check status code
      if(!error)
      {
         //Generate ECDSA signature (R, S)
         error = ecdsaGenerateSignature(prngAlgo, prngContext, &params,
            privateKey, digest, hashAlgo->digestSize, &signature);
      }

      //Check status code
      if(!error)
      {
         //Turn R and S into octet sequences in big-endian order, with each
         //array being be 32 octets long. The octet sequence representations
         //must not be shortened to omit any leading zero octets contained in
         //the values (refer to RFC 7518, section 3.4)
         n = mpiGetByteLength(&params.q);

         //Convert R to an octet string
         error = mpiExport(&signature.r, (uint8_t *) output, n,
            MPI_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Convert S to an octet string
         error = mpiExport(&signature.s, (uint8_t *) output + n, n,
            MPI_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Concatenate the two octet sequences in the order R and then S.
         //The resulting 64-octet sequence is the JWS signature value
         *outputLen = 2 * n;
      }

      //Release previously allocated resources
      ecFreeDomainParameters(&params);
      ecdsaFreeSignature(&signature);
   }
   else
#endif
#if (ACME_CLIENT_ED25519_SUPPORT == ENABLED)
   //Ed25519 algorithm?
   if(!osStrcmp(alg, "EdDSA") && !osStrcmp(crv, "Ed25519"))
   {
      const EddsaPrivateKey *eddsaPrivateKey;
      uint8_t d[ED25519_PRIVATE_KEY_LEN];

      //Point to the EdDSA private key
      eddsaPrivateKey = (const EddsaPrivateKey *) privateKey;

      //Retrieve private key
      error = mpiExport(&eddsaPrivateKey->d, d, ED25519_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);

      //Check status code
      if(!error)
      {
         //Generate Ed25519 signature (PureEdDSA mode)
         error = ed25519GenerateSignature(d, NULL, input, inputLen,
            NULL, 0, 0, output);
      }

      //Length of the resulting EdDSA signature
      *outputLen = ED25519_SIGNATURE_LEN;
   }
   else
#endif
#if (ACME_CLIENT_ED448_SUPPORT == ENABLED)
   //Ed448 algorithm?
   if(!osStrcmp(alg, "EdDSA") && !osStrcmp(crv, "Ed448"))
   {
      const EddsaPrivateKey *eddsaPrivateKey;
      uint8_t d[ED448_PRIVATE_KEY_LEN];

      //Point to the EdDSA private key
      eddsaPrivateKey = (const EddsaPrivateKey *) privateKey;

      //Retrieve private key
      error = mpiExport(&eddsaPrivateKey->d, d, ED448_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);

      //Check status code
      if(!error)
      {
         //Generate Ed448 signature (PureEdDSA mode)
         error = ed448GenerateSignature(d, NULL, input, inputLen,
            NULL, 0, 0, output);
      }

      //Length of the resulting EdDSA signature
      *outputLen = ED448_SIGNATURE_LEN;
   }
   else
#endif
   //Unknown algorithm?
   {
      //Report an error
      error = ERROR_INVALID_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}

#endif
