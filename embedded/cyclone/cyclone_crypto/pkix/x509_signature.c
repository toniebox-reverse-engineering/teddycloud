/**
 * @file x509_signature.c
 * @brief RSA/DSA/ECDSA/EdDSA signature generation and verification
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
#include "pkix/x509_key_parse.h"
#include "pkix/x509_signature.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ecdsa.h"
#include "ecc/eddsa.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)

//Signature generation/verification callback functions
#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   static X509SignGenCallback x509SignGenCallback = NULL;
   static X509SignVerifyCallback x509SignVerifyCallback = NULL;
#endif


/**
 * @brief Register signature generation callback function
 * @param[in] callback Signature generation callback function
 * @return Error code
 **/

error_t x509RegisterSignGenCallback(X509SignGenCallback callback)
{
#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Save callback function
   x509SignGenCallback = callback;
   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register signature verification callback function
 * @param[in] callback Signature verification callback function
 * @return Error code
 **/

error_t x509RegisterSignVerifyCallback(X509SignVerifyCallback callback)
{
#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Save callback function
   x509SignVerifyCallback = callback;
   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Certificate signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsCert Pointer to the TBSCertificate to be signed
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] signatureAlgoId Signature algorithm identifier
 * @param[in] publicKeyInfo Signer's public key information
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *tbsCert, size_t tbsCertLen, const X509SignatureAlgoId *signatureAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo, const void *privateKey,
   uint8_t *output, size_t *written)
{
   error_t error;
   X509SignatureAlgo signAlgo;
   const HashAlgo *hashAlgo;

#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Valid signature generation callback function?
   if(x509SignGenCallback != NULL)
   {
      //Invoke user-defined callback
      error = x509SignGenCallback(prngAlgo, prngContext, tbsCert, tbsCertLen,
         signatureAlgoId, publicKeyInfo, privateKey, output, written);
   }
   else
#endif
   {
      //No callback function registered
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(error == ERROR_UNSUPPORTED_SIGNATURE_ALGO ||
      error == ERROR_UNKOWN_KEY)
   {
      //Retrieve the signature algorithm that will be used to sign the
      //certificate
      error = x509GetSignHashAlgo(signatureAlgoId, &signAlgo, &hashAlgo);

      //Check status code
      if(!error)
      {
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
         //RSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_RSA)
         {
            //Generate RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
            error = x509GenerateRsaSignature(tbsCert, tbsCertLen, hashAlgo,
               privateKey, output, written);
         }
         else
#endif
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
         //RSA-PSS signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_RSA_PSS)
         {
            //Generate RSA signature (RSASSA-PSS signature scheme)
            error = x509GenerateRsaPssSignature(prngAlgo, prngContext, tbsCert,
               tbsCertLen, hashAlgo, signatureAlgoId->rsaPssParams.saltLen,
               privateKey, output, written);
         }
         else
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
         //DSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_DSA)
         {
            //Generate DSA signature
            error = x509GenerateDsaSignature(prngAlgo, prngContext, tbsCert,
               tbsCertLen, hashAlgo, privateKey, output, written);
         }
         else
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
         //ECDSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ECDSA)
         {
            //Generate ECDSA signature
            error = x509GenerateEcdsaSignature(prngAlgo, prngContext, tbsCert,
               tbsCertLen, hashAlgo, publicKeyInfo, privateKey, output,
               written);
         }
         else
#endif
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
         //Ed25519 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ED25519)
         {
            //Generate Ed25519 signature (PureEdDSA mode)
            error = x509GenerateEd25519Signature(tbsCert, tbsCertLen,
               privateKey, output, written);
         }
         else
#endif
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
         //Ed448 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ED448)
         {
            //Generate Ed448 signature (PureEdDSA mode)
            error = x509GenerateEd448Signature(tbsCert, tbsCertLen, privateKey,
               output, written);
         }
         else
#endif
         //Invalid signature algorithm?
         {
            //Report an error
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature generation
 * @param[in] tbsCert Pointer to the TBSCertificate to be signed
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] hashAlgo Underlying hash function
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateRsaSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, const RsaPrivateKey *privateKey, uint8_t *output,
   size_t *written)
{
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   uint8_t digest[X509_MAX_HASH_DIGEST_SIZE];

   //Digest the TBSCertificate structure using the specified hash algorithm
   error = hashAlgo->compute(tbsCert, tbsCertLen, digest);

   //Check status code
   if(!error)
   {
      //Generate RSA signature
      error = rsassaPkcs1v15Sign(privateKey, hashAlgo, digest, output,
         written);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief RSA-PSS signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsCert Pointer to the TBSCertificate to be signed
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] hashAlgo Underlying hash function
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateRsaPssSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *tbsCert, size_t tbsCertLen, const HashAlgo *hashAlgo,
   size_t saltLen, const RsaPrivateKey *privateKey, uint8_t *output,
   size_t *written)
{
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   uint8_t digest[X509_MAX_HASH_DIGEST_SIZE];

   //Digest the TBSCertificate structure using the specified hash algorithm
   error = hashAlgo->compute(tbsCert, tbsCertLen, digest);

   //Check status code
   if(!error)
   {
      //Generate RSA-PSS signature
      error = rsassaPssSign(prngAlgo, prngContext, privateKey, hashAlgo,
         saltLen, digest, output, written);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsCert Pointer to the TBSCertificate to be signed
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] hashAlgo Underlying hash function
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateDsaSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *tbsCert, size_t tbsCertLen, const HashAlgo *hashAlgo,
   const DsaPrivateKey *privateKey, uint8_t *output, size_t *written)
{
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   error_t error;
   DsaSignature signature;
   uint8_t digest[X509_MAX_HASH_DIGEST_SIZE];

   //Initialize DSA signature
   dsaInitSignature(&signature);

   //Digest the TBSCertificate structure using the specified hash algorithm
   error = hashAlgo->compute(tbsCert, tbsCertLen, digest);

   //Check status code
   if(!error)
   {
      //Generate DSA signature
      error = dsaGenerateSignature(prngAlgo, prngContext, privateKey, digest,
         hashAlgo->digestSize, &signature);
   }

   //Check status code
   if(!error)
   {
      //Encode DSA signature using ASN.1
      error = dsaWriteSignature(&signature, output, written);
   }

   //Release previously allocated resources
   dsaFreeSignature(&signature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature generation
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @param[in] tbsCert Pointer to the TBSCertificate to be signed
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] hashAlgo Underlying hash function
 * @param[in] publicKeyInfo Signer's public key information
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateEcdsaSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const uint8_t *tbsCert, size_t tbsCertLen, const HashAlgo *hashAlgo,
   const X509SubjectPublicKeyInfo *publicKeyInfo, const EcPrivateKey *privateKey,
   uint8_t *output, size_t *written)
{
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   error_t error;
   const EcCurveInfo *curveInfo;
   EcDomainParameters params;
   EcdsaSignature signature;
   uint8_t digest[X509_MAX_HASH_DIGEST_SIZE];

   //Initialize EC domain parameters
   ecInitDomainParameters(&params);
   //Initialize ECDSA signature
   ecdsaInitSignature(&signature);

   //Retrieve EC domain parameters
   curveInfo = x509GetCurveInfo(publicKeyInfo->ecParams.namedCurve,
      publicKeyInfo->ecParams.namedCurveLen);

   //Make sure the specified elliptic curve is supported
   if(curveInfo != NULL)
   {
      //Load EC domain parameters
      error = ecLoadDomainParameters(&params, curveInfo);
   }
   else
   {
      //Invalid EC domain parameters
      error = ERROR_BAD_CERTIFICATE;
   }

   //Check status code
   if(!error)
   {
      //Digest the TBSCertificate structure using the specified hash algorithm
      error = hashAlgo->compute(tbsCert, tbsCertLen, digest);
   }

   //Check status code
   if(!error)
   {
      //Generate ECDSA signature
      error = ecdsaGenerateSignature(prngAlgo, prngContext, &params, privateKey,
         digest, hashAlgo->digestSize, &signature);
   }

   //Check status code
   if(!error)
   {
      //Encode ECDSA signature using ASN.1
      error = ecdsaWriteSignature(&signature, output, written);
   }

   //Release previously allocated resources
   ecFreeDomainParameters(&params);
   ecdsaFreeSignature(&signature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature generation
 * @param[in] tbsCert Pointer to the TBSCertificate to be signed
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateEd25519Signature(const uint8_t *tbsCert, size_t tbsCertLen,
   const EddsaPrivateKey *privateKey, uint8_t *output, size_t *written)
{
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
   error_t error;

   //Check the length of the EdDSA private key
   if(mpiGetByteLength(&privateKey->d) == ED25519_PRIVATE_KEY_LEN)
   {
      uint8_t d[ED25519_PRIVATE_KEY_LEN];

      //Retrieve private key
      error = mpiExport(&privateKey->d, d, ED25519_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);

      //Check status code
      if(!error)
      {
         //Generate Ed25519 signature (PureEdDSA mode)
         error = ed25519GenerateSignature(d, NULL, tbsCert, tbsCertLen,
            NULL, 0, 0, output);
      }

      //Length of the resulting EdDSA signature
      *written = ED25519_SIGNATURE_LEN;
   }
   else
   {
      //The length of the EdDSA private key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature generation
 * @param[in] tbsCert Pointer to the TBSCertificate to be signed
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] privateKey Signer's private key
 * @param[out] output Resulting signature
 * @param[out] written Length of the resulting signature
 * @return Error code
 **/

error_t x509GenerateEd448Signature(const uint8_t *tbsCert, size_t tbsCertLen,
   const EddsaPrivateKey *privateKey, uint8_t *output, size_t *written)
{
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
   error_t error;

   //Check the length of the EdDSA private key
   if(mpiGetByteLength(&privateKey->d) == ED448_PRIVATE_KEY_LEN)
   {
      uint8_t d[ED448_PRIVATE_KEY_LEN];

      //Retrieve private key
      error = mpiExport(&privateKey->d, d, ED448_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);

      //Check status code
      if(!error)
      {
         //Generate Ed448 signature (PureEdDSA mode)
         error = ed448GenerateSignature(d, NULL, tbsCert, tbsCertLen,
            NULL, 0, 0, output);
      }

      //Length of the resulting EdDSA signature
      *written = ED448_SIGNATURE_LEN;
   }
   else
   {
      //The length of the EdDSA private key is not valid
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Certificate signature verification
 * @param[in] tbsCert TBSCertificate whose signature is to be verified
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] signatureAlgoId Signature algorithm identifier
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signatureValue Signature to be verified
 * @return Error code
 **/

error_t x509VerifySignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const X509SignatureAlgoId *signatureAlgoId,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue)
{
   error_t error;
   X509SignatureAlgo signAlgo;
   const HashAlgo *hashAlgo;

#if (X509_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Valid signature verification callback function?
   if(x509SignVerifyCallback != NULL)
   {
      //Invoke user-defined callback
      error = x509SignVerifyCallback(tbsCert, tbsCertLen, signatureAlgoId,
         publicKeyInfo, signatureValue);
   }
   else
#endif
   {
      //No callback function registered
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(error == ERROR_UNSUPPORTED_SIGNATURE_ALGO)
   {
      //Retrieve the signature algorithm that was used to sign the certificate
      error = x509GetSignHashAlgo(signatureAlgoId, &signAlgo, &hashAlgo);

      //Check status code
      if(!error)
      {
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
         //RSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_RSA)
         {
            //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
            error = x509VerifyRsaSignature(tbsCert, tbsCertLen, hashAlgo,
               publicKeyInfo, signatureValue);
         }
         else
#endif
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
         //RSA-PSS signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_RSA_PSS)
         {
            //Verify RSA signature (RSASSA-PSS signature scheme)
            error = x509VerifyRsaPssSignature(tbsCert, tbsCertLen, hashAlgo,
               signatureAlgoId->rsaPssParams.saltLen, publicKeyInfo,
               signatureValue);
         }
         else
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
         //DSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_DSA)
         {
            //Verify DSA signature
            error = x509VerifyDsaSignature(tbsCert, tbsCertLen, hashAlgo,
               publicKeyInfo, signatureValue);
         }
         else
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
         //ECDSA signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ECDSA)
         {
            //Verify ECDSA signature
            error = x509VerifyEcdsaSignature(tbsCert, tbsCertLen, hashAlgo,
               publicKeyInfo, signatureValue);
         }
         else
#endif
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
         //Ed25519 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ED25519)
         {
            //Verify Ed25519 signature (PureEdDSA mode)
            error = x509VerifyEd25519Signature(tbsCert, tbsCertLen,
               publicKeyInfo, signatureValue);
         }
         else
#endif
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
         //Ed448 signature algorithm?
         if(signAlgo == X509_SIGN_ALGO_ED448)
         {
            //Verify Ed448 signature (PureEdDSA mode)
            error = x509VerifyEd448Signature(tbsCert, tbsCertLen, publicKeyInfo,
               signatureValue);
         }
         else
#endif
         //Invalid signature algorithm?
         {
            //Report an error
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature verification
 * @param[in] tbsCert TBSCertificate whose signature is to be verified
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] hashAlgo Underlying hash function
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signatureValue Signature to be verified
 * @return Error code
 **/

error_t x509VerifyRsaSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue)
{
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   RsaPublicKey publicKey;
   uint8_t digest[X509_MAX_HASH_DIGEST_SIZE];

   //Initialize RSA public key
   rsaInitPublicKey(&publicKey);

   //Digest the TBSCertificate structure using the specified hash algorithm
   error = hashAlgo->compute(tbsCert, tbsCertLen, digest);

   //Check status code
   if(!error)
   {
      //Import the RSA public key
      error = x509ImportRsaPublicKey(publicKeyInfo, &publicKey);
   }

   //Check status code
   if(!error)
   {
      //Get the length of the modulus, in bits
      k = mpiGetBitLength(&publicKey.n);

      //Make sure the modulus is acceptable
      if(k < X509_MIN_RSA_MODULUS_SIZE || k > X509_MAX_RSA_MODULUS_SIZE)
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }

   //Check status code
   if(!error)
   {
      //Verify RSA signature (RSASSA-PKCS1-v1_5 signature scheme)
      error = rsassaPkcs1v15Verify(&publicKey, hashAlgo, digest,
         signatureValue->data, signatureValue->length);
   }

   //Release previously allocated resources
   rsaFreePublicKey(&publicKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief RSA-PSS signature verification
 * @param[in] tbsCert TBSCertificate whose signature is to be verified
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] hashAlgo Underlying hash function
 * @param[in] saltLen Length of the salt, in bytes
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signatureValue Signature to be verified
 * @return Error code
 **/

error_t x509VerifyRsaPssSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, size_t saltLen,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue)
{
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   RsaPublicKey publicKey;
   uint8_t digest[X509_MAX_HASH_DIGEST_SIZE];

   //Initialize RSA public key
   rsaInitPublicKey(&publicKey);

   //Digest the TBSCertificate structure using the specified hash algorithm
   error = hashAlgo->compute(tbsCert, tbsCertLen, digest);

   //Check status code
   if(!error)
   {
      //Import the RSA public key
      error = x509ImportRsaPublicKey(publicKeyInfo, &publicKey);
   }

   //Check status code
   if(!error)
   {
      //Get the length of the modulus, in bits
      k = mpiGetBitLength(&publicKey.n);

      //Make sure the modulus is acceptable
      if(k < X509_MIN_RSA_MODULUS_SIZE || k > X509_MAX_RSA_MODULUS_SIZE)
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }

   //Check status code
   if(!error)
   {
      //Verify RSA signature (RSASSA-PSS signature scheme)
      error = rsassaPssVerify(&publicKey, hashAlgo, saltLen, digest,
         signatureValue->data, signatureValue->length);
   }

   //Release previously allocated resources
   rsaFreePublicKey(&publicKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature verification
 * @param[in] tbsCert TBSCertificate whose signature is to be verified
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] hashAlgo Underlying hash function
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signatureValue Signature to be verified
 * @return Error code
 **/

error_t x509VerifyDsaSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue)
{
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   DsaPublicKey publicKey;
   DsaSignature signature;
   uint8_t digest[X509_MAX_HASH_DIGEST_SIZE];

   //Initialize DSA public key
   dsaInitPublicKey(&publicKey);
   //Initialize DSA signature
   dsaInitSignature(&signature);

   //Digest the TBSCertificate structure using the specified hash algorithm
   error = hashAlgo->compute(tbsCert, tbsCertLen, digest);

   //Check status code
   if(!error)
   {
      //Import the DSA public key
      error = x509ImportDsaPublicKey(publicKeyInfo, &publicKey);
   }

   //Check status code
   if(!error)
   {
      //Get the length of the prime modulus, in bits
      k = mpiGetBitLength(&publicKey.params.p);

      //Make sure the prime modulus is acceptable
      if(k < X509_MIN_DSA_MODULUS_SIZE || k > X509_MAX_DSA_MODULUS_SIZE)
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }

   //Check status code
   if(!error)
   {
      //Read the ASN.1 encoded signature
      error = dsaReadSignature(signatureValue->data, signatureValue->length,
         &signature);
   }

   //Check status code
   if(!error)
   {
      //Verify DSA signature
      error = dsaVerifySignature(&publicKey, digest, hashAlgo->digestSize,
         &signature);
   }

   //Release previously allocated resources
   dsaFreePublicKey(&publicKey);
   dsaFreeSignature(&signature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature verification
 * @param[in] tbsCert TBSCertificate whose signature is to be verified
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] hashAlgo Underlying hash function
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signatureValue Signature to be verified
 * @return Error code
 **/

error_t x509VerifyEcdsaSignature(const uint8_t *tbsCert, size_t tbsCertLen,
   const HashAlgo *hashAlgo, const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue)
{
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   error_t error;
   const EcCurveInfo *curveInfo;
   EcDomainParameters params;
   EcPublicKey publicKey;
   EcdsaSignature signature;
   uint8_t digest[X509_MAX_HASH_DIGEST_SIZE];

   //Initialize EC domain parameters
   ecInitDomainParameters(&params);
   //Initialize EC public key
   ecInitPublicKey(&publicKey);
   //Initialize ECDSA signature
   ecdsaInitSignature(&signature);

   //Retrieve EC domain parameters
   curveInfo = x509GetCurveInfo(publicKeyInfo->ecParams.namedCurve,
      publicKeyInfo->ecParams.namedCurveLen);

   //Make sure the specified elliptic curve is supported
   if(curveInfo != NULL)
   {
      //Load EC domain parameters
      error = ecLoadDomainParameters(&params, curveInfo);
   }
   else
   {
      //Invalid EC domain parameters
      error = ERROR_BAD_CERTIFICATE;
   }

   //Check status code
   if(!error)
   {
      //Digest the TBSCertificate structure using the specified hash algorithm
      error = hashAlgo->compute(tbsCert, tbsCertLen, digest);
   }

   //Check status code
   if(!error)
   {
      //Retrieve the EC public key
      error = ecImport(&params, &publicKey.q, publicKeyInfo->ecPublicKey.q,
         publicKeyInfo->ecPublicKey.qLen);
   }

   //Check status code
   if(!error)
   {
      //Read the ASN.1 encoded signature
      error = ecdsaReadSignature(signatureValue->data,
         signatureValue->length, &signature);
   }

   //Check status code
   if(!error)
   {
      //Verify ECDSA signature
      error = ecdsaVerifySignature(&params, &publicKey, digest,
         hashAlgo->digestSize, &signature);
   }

   //Release previously allocated resources
   ecFreeDomainParameters(&params);
   ecFreePublicKey(&publicKey);
   ecdsaFreeSignature(&signature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature verification
 * @param[in] tbsCert TBSCertificate whose signature is to be verified
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signatureValue Signature to be verified
 * @return Error code
 **/

error_t x509VerifyEd25519Signature(const uint8_t *tbsCert, size_t tbsCertLen,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue)
{
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
   error_t error;

   //Check the length of the public key
   if(publicKeyInfo->ecPublicKey.qLen == ED25519_PUBLIC_KEY_LEN)
   {
      //Check the length of the EdDSA signature
      if(signatureValue->length == ED25519_SIGNATURE_LEN)
      {
         //Verify signature (PureEdDSA mode)
         error = ed25519VerifySignature(publicKeyInfo->ecPublicKey.q,
            tbsCert, tbsCertLen, NULL, 0, 0, signatureValue->data);
      }
      else
      {
         //The length of the EdDSA signature is not valid
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
   {
      //The length of the Ed25519 public key is not valid
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature verification
 * @param[in] tbsCert TBSCertificate whose signature is to be verified
 * @param[in] tbsCertLen Length of the TBSCertificate, in bytes
 * @param[in] publicKeyInfo Issuer's public key
 * @param[in] signatureValue Signature to be verified
 * @return Error code
 **/

error_t x509VerifyEd448Signature(const uint8_t *tbsCert, size_t tbsCertLen,
   const X509SubjectPublicKeyInfo *publicKeyInfo,
   const X509SignatureValue *signatureValue)
{
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
   error_t error;

   //Check the length of the public key
   if(publicKeyInfo->ecPublicKey.qLen == ED448_PUBLIC_KEY_LEN)
   {
      //Check the length of the EdDSA signature
      if(signatureValue->length == ED448_SIGNATURE_LEN)
      {
         //Verify signature (PureEdDSA mode)
         error = ed448VerifySignature(publicKeyInfo->ecPublicKey.q,
            tbsCert, tbsCertLen, NULL, 0, 0, signatureValue->data);
      }
      else
      {
         //The length of the EdDSA signature is not valid
         error = ERROR_INVALID_SIGNATURE;
      }
   }
   else
   {
      //The length of the Ed448 public key is not valid
      error = ERROR_ILLEGAL_PARAMETER;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
