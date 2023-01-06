/**
 * @file x509_common.c
 * @brief X.509 common definitions
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
#include "pkix/x509_common.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "hash/hash_algorithms.h"
#include "debug.h"

//Check crypto library configuration
#if (X509_SUPPORT == ENABLED)

//Common Name OID (2.5.4.3)
const uint8_t X509_COMMON_NAME_OID[3] = {0x55, 0x04, 0x03};
//Surname OID (2.5.4.4)
const uint8_t X509_SURNAME_OID[3] = {0x55, 0x04, 0x04};
//Serial Number OID (2.5.4.5)
const uint8_t X509_SERIAL_NUMBER_OID[3] = {0x55, 0x04, 0x05};
//Country Name OID (2.5.4.6)
const uint8_t X509_COUNTRY_NAME_OID[3] = {0x55, 0x04, 0x06};
//Locality Name OID (2.5.4.7)
const uint8_t X509_LOCALITY_NAME_OID[3] = {0x55, 0x04, 0x07};
//State Or Province Name OID (2.5.4.8)
const uint8_t X509_STATE_OR_PROVINCE_NAME_OID[] = {0x55, 0x04, 0x08};
//Organization Name OID (2.5.4.10)
const uint8_t X509_ORGANIZATION_NAME_OID[3] = {0x55, 0x04, 0x0A};
//Organizational Unit Name OID (2.5.4.11)
const uint8_t X509_ORGANIZATIONAL_UNIT_NAME_OID[3] = {0x55, 0x04, 0x0B};
//Title OID (2.5.4.12)
const uint8_t X509_TITLE_OID[3] = {0x55, 0x04, 0x0C};
//Name OID (2.5.4.41)
const uint8_t X509_NAME_OID[3] = {0x55, 0x04, 0x29};
//Given Name OID (2.5.4.42)
const uint8_t X509_GIVEN_NAME_OID[3] = {0x55, 0x04, 0x2A};
//Initials OID (2.5.4.43)
const uint8_t X509_INITIALS_OID[3] = {0x55, 0x04, 0x2B};
//Generation Qualifier OID (2.5.4.44)
const uint8_t X509_GENERATION_QUALIFIER_OID[3] = {0x55, 0x04, 0x2C};
//DN Qualifier OID (2.5.4.46)
const uint8_t X509_DN_QUALIFIER_OID[3] = {0x55, 0x04, 0x2E};
//Pseudonym OID (2.5.4.65)
const uint8_t X509_PSEUDONYM_OID[3] = {0x55, 0x04, 0x41};

//Subject Directory Attributes OID (2.5.29.9)
const uint8_t X509_SUBJECT_DIRECTORY_ATTR_OID[3] = {0x55, 0x1D, 0x09};
//Subject Key Identifier OID (2.5.29.14)
const uint8_t X509_SUBJECT_KEY_ID_OID[3] = {0x55, 0x1D, 0x0E};
//Key Usage OID (2.5.29.15)
const uint8_t X509_KEY_USAGE_OID[3] = {0x55, 0x1D, 0x0F};
//Subject Alternative Name OID (2.5.29.17)
const uint8_t X509_SUBJECT_ALT_NAME_OID[3] = {0x55, 0x1D, 0x11};
//Issuer Alternative Name OID (2.5.29.18)
const uint8_t X509_ISSUER_ALT_NAME_OID[3] = {0x55, 0x1D, 0x12};
//Basic Constraints OID (2.5.29.19)
const uint8_t X509_BASIC_CONSTRAINTS_OID[3] = {0x55, 0x1D, 0x13};
//CRL Number OID (2.5.29.20)
const uint8_t X509_CRL_NUMBER_OID[3] = {0x55, 0x1D, 0x14};
//Reason Code OID (2.5.29.21)
const uint8_t X509_REASON_CODE_OID[3] = {0x55, 0x1D, 0x15};
//Invalidity Date OID (2.5.29.24)
const uint8_t X509_INVALIDITY_DATE_OID[3] = {0x55, 0x1D, 0x18};
//Delta CRL Indicator OID (2.5.29.27)
const uint8_t X509_DELTA_CRL_INDICATOR_OID[3] = {0x55, 0x1D, 0x1B};
//Issuing Distribution Point OID (2.5.29.28)
const uint8_t X509_ISSUING_DISTR_POINT_OID[3] = {0x55, 0x1D, 0x1C};
//Certificate Issuer OID (2.5.29.29)
const uint8_t X509_CERTIFICATE_ISSUER_OID[3] = {0x55, 0x1D, 0x1D};
//Name Constraints OID (2.5.29.30)
const uint8_t X509_NAME_CONSTRAINTS_OID[3] = {0x55, 0x1D, 0x1E};
//CRL Distribution Points OID (2.5.29.31)
const uint8_t X509_CRL_DISTR_POINTS_OID[3] = {0x55, 0x1D, 0x1F};
//Certificate Policies OID (2.5.29.32)
const uint8_t X509_CERTIFICATE_POLICIES_OID[3] = {0x55, 0x1D, 0x20};
//Policy Mappings OID (2.5.29.33)
const uint8_t X509_POLICY_MAPPINGS_OID[3] = {0x55, 0x1D, 0x21};
//Authority Key Identifier OID (2.5.29.35)
const uint8_t X509_AUTHORITY_KEY_ID_OID[3] = {0x55, 0x1D, 0x23};
//Policy Constraints OID (2.5.29.36)
const uint8_t X509_POLICY_CONSTRAINTS_OID[3] = {0x55, 0x1D, 0x24};
//Extended Key Usage OID (2.5.29.37)
const uint8_t X509_EXTENDED_KEY_USAGE_OID[3] = {0x55, 0x1D, 0x25};
//Freshest CRL OID (2.5.29.46)
const uint8_t X509_FRESHEST_CRL_OID[3] = {0x55, 0x1D, 0x2E};
//Inhibit Any-Policy OID (2.5.29.54)
const uint8_t X509_INHIBIT_ANY_POLICY_OID[3] = {0x55, 0x1D, 0x36};

//Netscape Certificate Type OID (2.16.840.1.113730.1.1)
const uint8_t X509_NS_CERT_TYPE_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x01};

//Any Extended Key Usage OID (2.5.29.37.0)
const uint8_t X509_ANY_EXT_KEY_USAGE_OID[4] = {0x55, 0x1D, 0x25, 0x00};
//Key Purpose Server Auth OID (1.3.6.1.5.5.7.3.1)
const uint8_t X509_KP_SERVER_AUTH_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
//Key Purpose Client Auth OID (1.3.6.1.5.5.7.3.2)
const uint8_t X509_KP_CLIENT_AUTH_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02};
//Key Purpose Code Signing OID (1.3.6.1.5.5.7.3.3)
const uint8_t X509_KP_CODE_SIGNING_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03};
//Key Purpose Email Protection OID (1.3.6.1.5.5.7.3.4)
const uint8_t X509_KP_EMAIL_PROTECTION_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04};
//Key Purpose Time Stamping OID (1.3.6.1.5.5.7.3.8)
const uint8_t X509_KP_TIME_STAMPING_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08};
//Key Purpose OCSP Signing OID (1.3.6.1.5.5.7.3.9)
const uint8_t X509_KP_OCSP_SIGNING_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09};
//Key Purpose Secure Shell Client (1.3.6.1.5.5.7.3.21)
const uint8_t X509_KP_SSH_CLIENT_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x15};
//Key Purpose Secure Shell Client (1.3.6.1.5.5.7.3.22)
const uint8_t X509_KP_SSH_SERVER_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x16};

//PKCS#9 Challenge Password OID (1.2.840.113549.1.9.7)
const uint8_t X509_CHALLENGE_PASSWORD_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07};
//PKCS#9 Extension Request OID (1.2.840.113549.1.9.14)
const uint8_t X509_EXTENSION_REQUEST_OID[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E};


/**
 * @brief Check whether a given signature algorithm is supported
 * @param[in] signAlgo signature algorithm
 * @return TRUE is the signature algorithm is supported, else FALSE
 **/

bool_t x509IsSignAlgoSupported(X509SignatureAlgo signAlgo)
{
   bool_t acceptable;

   //Invalid signature algorithm?
   if(signAlgo == X509_SIGN_ALGO_NONE)
   {
      acceptable = FALSE;
   }
#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA signature algorithm?
   else if(signAlgo == X509_SIGN_ALGO_RSA)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA-PSS signature algorithm?
   else if(signAlgo == X509_SIGN_ALGO_RSA_PSS)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
   //DSA signature algorithm?
   else if(signAlgo == X509_SIGN_ALGO_DSA)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   //ECDSA signature algorithm?
   else if(signAlgo == X509_SIGN_ALGO_ECDSA)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
   //Ed25519 signature algorithm?
   else if(signAlgo == X509_SIGN_ALGO_ED25519)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
   //Ed448 signature algorithm?
   else if(signAlgo == X509_SIGN_ALGO_ED448)
   {
      acceptable = TRUE;
   }
#endif
   //Invalid signature algorithm?
   else
   {
      acceptable = FALSE;
   }

   //Return TRUE is the signature algorithm is supported
   return acceptable;
}


/**
 * @brief Check whether a given hash algorithm is supported
 * @param[in] hashAlgo signature hash
 * @return TRUE is the signature hash is supported, else FALSE
 **/

bool_t x509IsHashAlgoSupported(X509HashAlgo hashAlgo)
{
   bool_t acceptable;

   //Invalid hash algorithm?
   if(hashAlgo == X509_HASH_ALGO_NONE)
   {
      acceptable = FALSE;
   }
#if (X509_MD5_SUPPORT == ENABLED && MD5_SUPPORT == ENABLED)
   //MD5 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_MD5)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //SHA-1 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_SHA1)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_SHA224_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   //SHA-224 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_SHA224)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   //SHA-256 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_SHA256)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   //SHA-384 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_SHA384)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   //SHA-512 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_SHA512)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_SHA3_224_SUPPORT == ENABLED && SHA3_224_SUPPORT == ENABLED)
   //SHA3-224 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_SHA3_224)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_SHA3_256_SUPPORT == ENABLED && SHA3_256_SUPPORT == ENABLED)
   //SHA3-256 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_SHA3_256)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_SHA3_384_SUPPORT == ENABLED && SHA3_384_SUPPORT == ENABLED)
   //SHA3-384 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_SHA3_384)
   {
      acceptable = TRUE;
   }
#endif
#if (X509_SHA3_512_SUPPORT == ENABLED && SHA3_512_SUPPORT == ENABLED)
   //SHA3-512 hash algorithm?
   else if(hashAlgo == X509_HASH_ALGO_SHA3_512)
   {
      acceptable = TRUE;
   }
#endif
   //Invalid hash algorithm?
   else
   {
      acceptable = FALSE;
   }

   //Return TRUE is the hash algorithm is supported
   return acceptable;
}


/**
 * @brief Get the signature and hash algorithms that match the specified
 *   identifier
 * @param[in] signAlgoId Signature algorithm identifier
 * @param[out] signAlgo Signature algorithm
 * @param[out] hashAlgo Hash algorithm
 * @return Error code
 **/

error_t x509GetSignHashAlgo(const X509SignatureAlgoId *signAlgoId,
   X509SignatureAlgo *signAlgo, const HashAlgo **hashAlgo)
{
   error_t error;
   size_t oidLen;
   const uint8_t *oid;

   //Initialize status code
   error = NO_ERROR;

   //Point to the object identifier
   oid = signAlgoId->oid;
   oidLen = signAlgoId->oidLen;

#if (X509_RSA_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
#if (X509_MD5_SUPPORT == ENABLED && MD5_SUPPORT == ENABLED)
   //RSA with MD5 signature algorithm?
   if(!oidComp(oid, oidLen, MD5_WITH_RSA_ENCRYPTION_OID,
      sizeof(MD5_WITH_RSA_ENCRYPTION_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = MD5_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //RSA with SHA-1 signature algorithm?
   if(!oidComp(oid, oidLen, SHA1_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA1_WITH_RSA_ENCRYPTION_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA224_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   //RSA with SHA-224 signature algorithm?
   if(!oidComp(oid, oidLen, SHA224_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA224_WITH_RSA_ENCRYPTION_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = SHA224_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   //RSA with SHA-256 signature algorithm?
   if(!oidComp(oid, oidLen, SHA256_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA256_WITH_RSA_ENCRYPTION_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   //RSA with SHA-384 signature algorithm?
   if(!oidComp(oid, oidLen, SHA384_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA384_WITH_RSA_ENCRYPTION_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   //RSA with SHA-512 signature algorithm?
   if(!oidComp(oid, oidLen, SHA512_WITH_RSA_ENCRYPTION_OID,
      sizeof(SHA512_WITH_RSA_ENCRYPTION_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_224_SUPPORT == ENABLED && SHA3_224_SUPPORT == ENABLED)
   //RSA with SHA3-224 signature algorithm?
   if(!oidComp(oid, oidLen, RSASSA_PKCS1_V1_5_WITH_SHA3_224_OID,
      sizeof(RSASSA_PKCS1_V1_5_WITH_SHA3_224_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = SHA3_224_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_256_SUPPORT == ENABLED && SHA3_256_SUPPORT == ENABLED)
   //RSA with SHA3-256 signature algorithm?
   if(!oidComp(oid, oidLen, RSASSA_PKCS1_V1_5_WITH_SHA3_256_OID,
      sizeof(RSASSA_PKCS1_V1_5_WITH_SHA3_256_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = SHA3_256_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_384_SUPPORT == ENABLED && SHA3_384_SUPPORT == ENABLED)
   //RSA with SHA3-384 signature algorithm?
   if(!oidComp(oid, oidLen, RSASSA_PKCS1_V1_5_WITH_SHA3_384_OID,
      sizeof(RSASSA_PKCS1_V1_5_WITH_SHA3_384_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = SHA3_384_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_512_SUPPORT == ENABLED && SHA3_512_SUPPORT == ENABLED)
   //RSA with SHA3-512 signature algorithm?
   if(!oidComp(oid, oidLen, RSASSA_PKCS1_V1_5_WITH_SHA3_512_OID,
      sizeof(RSASSA_PKCS1_V1_5_WITH_SHA3_512_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_RSA;
      *hashAlgo = SHA3_512_HASH_ALGO;
   }
   else
#endif
#endif
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   //RSA-PSS signature algorithm
   if(!oidComp(oid, oidLen, RSASSA_PSS_OID,
      sizeof(RSASSA_PSS_OID)))
   {
      //Get the OID of the hash algorithm
      oid = signAlgoId->rsaPssParams.hashAlgo;
      oidLen = signAlgoId->rsaPssParams.hashAlgoLen;

#if (X509_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
      //SHA-1 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA1_OID, sizeof(SHA1_OID)))
      {
         //RSA-PSS with SHA-1 signature algorithm
         *signAlgo = X509_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA1_HASH_ALGO;
      }
      else
#endif
#if (X509_SHA224_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
      //SHA-224 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA224_OID, sizeof(SHA224_OID)))
      {
         //RSA-PSS with SHA-224 signature algorithm
         *signAlgo = X509_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA224_HASH_ALGO;
      }
      else
#endif
#if (X509_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
      //SHA-256 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA256_OID, sizeof(SHA256_OID)))
      {
         //RSA-PSS with SHA-256 signature algorithm
         *signAlgo = X509_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA256_HASH_ALGO;
      }
      else
#endif
#if (X509_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
      //SHA-384 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA384_OID, sizeof(SHA384_OID)))
      {
         //RSA-PSS with SHA-384 signature algorithm
         *signAlgo = X509_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA384_HASH_ALGO;
      }
      else
#endif
#if (X509_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
      //SHA-512 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA512_OID, sizeof(SHA512_OID)))
      {
         //RSA-PSS with SHA-512 signature algorithm
         *signAlgo = X509_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA512_HASH_ALGO;
      }
      else
#endif
#if (X509_SHA3_224_SUPPORT == ENABLED && SHA3_224_SUPPORT == ENABLED)
      //SHA3-224 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA3_224_OID, sizeof(SHA3_224_OID)))
      {
         //RSA-PSS with SHA3-224 signature algorithm
         *signAlgo = X509_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA3_224_HASH_ALGO;
      }
      else
#endif
#if (X509_SHA3_256_SUPPORT == ENABLED && SHA3_256_SUPPORT == ENABLED)
      //SHA3-256 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA3_256_OID, sizeof(SHA3_256_OID)))
      {
         //RSA-PSS with SHA3-256 signature algorithm
         *signAlgo = X509_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA3_256_HASH_ALGO;
      }
      else
#endif
#if (X509_SHA3_384_SUPPORT == ENABLED && SHA3_384_SUPPORT == ENABLED)
      //SHA3-384 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA3_384_OID, sizeof(SHA3_384_OID)))
      {
         //RSA-PSS with SHA3-384 signature algorithm
         *signAlgo = X509_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA3_384_HASH_ALGO;
      }
      else
#endif
#if (X509_SHA3_512_SUPPORT == ENABLED && SHA3_512_SUPPORT == ENABLED)
      //SHA3-512 hash algorithm identifier?
      if(!oidComp(oid, oidLen, SHA3_512_OID, sizeof(SHA3_512_OID)))
      {
         //RSA-PSS with SHA3-512 signature algorithm
         *signAlgo = X509_SIGN_ALGO_RSA_PSS;
         *hashAlgo = SHA3_512_HASH_ALGO;
      }
      else
#endif
      //Unknown hash algorithm identifier?
      {
         //The specified signature algorithm is not supported
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }
   else
#endif
#if (X509_DSA_SUPPORT == ENABLED && DSA_SUPPORT == ENABLED)
#if (X509_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //DSA with SHA-1 signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA1_OID,
      sizeof(DSA_WITH_SHA1_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_DSA;
      *hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA224_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   //DSA with SHA-224 signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA224_OID,
      sizeof(DSA_WITH_SHA224_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_DSA;
      *hashAlgo = SHA224_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   //DSA with SHA-256 signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA256_OID,
      sizeof(DSA_WITH_SHA256_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_DSA;
      *hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   //DSA with SHA-384 signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA384_OID,
      sizeof(DSA_WITH_SHA384_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_DSA;
      *hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   //DSA with SHA-512 signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA512_OID,
      sizeof(DSA_WITH_SHA512_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_DSA;
      *hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_224_SUPPORT == ENABLED && SHA3_224_SUPPORT == ENABLED)
   //DSA with SHA3-224 signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA3_224_OID,
      sizeof(DSA_WITH_SHA3_224_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_DSA;
      *hashAlgo = SHA3_224_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_256_SUPPORT == ENABLED && SHA3_256_SUPPORT == ENABLED)
   //DSA with SHA3-256 signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA3_256_OID,
      sizeof(DSA_WITH_SHA3_256_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_DSA;
      *hashAlgo = SHA3_256_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_384_SUPPORT == ENABLED && SHA3_384_SUPPORT == ENABLED)
   //DSA with SHA3-384 signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA3_384_OID,
      sizeof(DSA_WITH_SHA3_384_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_DSA;
      *hashAlgo = SHA3_384_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_512_SUPPORT == ENABLED && SHA3_512_SUPPORT == ENABLED)
   //DSA with SHA3-512 signature algorithm?
   if(!oidComp(oid, oidLen, DSA_WITH_SHA3_512_OID,
      sizeof(DSA_WITH_SHA3_512_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_DSA;
      *hashAlgo = SHA3_512_HASH_ALGO;
   }
   else
#endif
#endif
#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
#if (X509_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   //ECDSA with SHA-1 signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA1_OID,
      sizeof(ECDSA_WITH_SHA1_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA224_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   //ECDSA with SHA-224 signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA224_OID,
      sizeof(ECDSA_WITH_SHA224_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA224_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   //ECDSA with SHA-256 signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA256_OID,
      sizeof(ECDSA_WITH_SHA256_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   //ECDSA with SHA-384 signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA384_OID,
      sizeof(ECDSA_WITH_SHA384_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   //ECDSA with SHA-512 signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA512_OID,
      sizeof(ECDSA_WITH_SHA512_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_224_SUPPORT == ENABLED && SHA3_224_SUPPORT == ENABLED)
   //ECDSA with SHA3-224 signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA3_224_OID,
      sizeof(ECDSA_WITH_SHA3_224_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA3_224_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_256_SUPPORT == ENABLED && SHA3_256_SUPPORT == ENABLED)
   //ECDSA with SHA3-256 signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA3_256_OID,
      sizeof(ECDSA_WITH_SHA3_256_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA3_256_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_384_SUPPORT == ENABLED && SHA3_384_SUPPORT == ENABLED)
   //ECDSA with SHA3-384 signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA3_384_OID,
      sizeof(ECDSA_WITH_SHA3_384_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA3_384_HASH_ALGO;
   }
   else
#endif
#if (X509_SHA3_512_SUPPORT == ENABLED && SHA3_512_SUPPORT == ENABLED)
   //ECDSA with SHA3-512 signature algorithm?
   if(!oidComp(oid, oidLen, ECDSA_WITH_SHA3_512_OID,
      sizeof(ECDSA_WITH_SHA3_512_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ECDSA;
      *hashAlgo = SHA3_512_HASH_ALGO;
   }
   else
#endif
#endif
#if (X509_ED25519_SUPPORT == ENABLED && ED25519_SUPPORT == ENABLED)
   //Ed25519 signature algorithm?
   if(!oidComp(oid, oidLen, ED25519_OID, sizeof(ED25519_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ED25519;
      *hashAlgo = NULL;
   }
   else
#endif
#if (X509_ED448_SUPPORT == ENABLED && ED448_SUPPORT == ENABLED)
   //Ed448 signature algorithm?
   if(!oidComp(oid, oidLen, ED448_OID, sizeof(ED448_OID)))
   {
      *signAlgo = X509_SIGN_ALGO_ED448;
      *hashAlgo = NULL;
   }
   else
#endif
   //Unknown signature algorithm?
   {
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the public key type that matches the specified OID
 * @param[in] oid Object identifier
 * @param[in] length OID length
 * @return Public key type
 **/

X509KeyType x509GetPublicKeyType(const uint8_t *oid, size_t length)
{
   X509KeyType keyType;

   //Invalid parameters?
   if(oid == NULL || length == 0)
   {
      keyType = X509_KEY_TYPE_UNKNOWN;
   }
#if (RSA_SUPPORT == ENABLED)
   //RSA algorithm identifier?
   else if(!oidComp(oid, length, RSA_ENCRYPTION_OID, sizeof(RSA_ENCRYPTION_OID)))
   {
      keyType = X509_KEY_TYPE_RSA;
   }
   //RSA-PSS algorithm identifier?
   else if(!oidComp(oid, length, RSASSA_PSS_OID, sizeof(RSASSA_PSS_OID)))
   {
      keyType = X509_KEY_TYPE_RSA_PSS;
   }
#endif
#if (DSA_SUPPORT == ENABLED)
   //DSA algorithm identifier?
   else if(!oidComp(oid, length, DSA_OID, sizeof(DSA_OID)))
   {
      keyType = X509_KEY_TYPE_DSA;
   }
#endif
#if (EC_SUPPORT == ENABLED)
   //EC public key identifier?
   else if(!oidComp(oid, length, EC_PUBLIC_KEY_OID, sizeof(EC_PUBLIC_KEY_OID)))
   {
      keyType = X509_KEY_TYPE_EC;
   }
#endif
#if (X25519_SUPPORT == ENABLED)
   //X25519 algorithm identifier?
   else if(!oidComp(oid, length, X25519_OID, sizeof(X25519_OID)))
   {
      keyType = X509_KEY_TYPE_X25519;
   }
#endif
#if (ED25519_SUPPORT == ENABLED)
   //Ed25519 algorithm identifier?
   else if(!oidComp(oid, length, ED25519_OID, sizeof(ED25519_OID)))
   {
      keyType = X509_KEY_TYPE_ED25519;
   }
#endif
#if (X448_SUPPORT == ENABLED)
   //X448 algorithm identifier?
   else if(!oidComp(oid, length, X448_OID, sizeof(X448_OID)))
   {
      keyType = X509_KEY_TYPE_X448;
   }
#endif
#if (ED448_SUPPORT == ENABLED)
   //Ed448 algorithm identifier?
   else if(!oidComp(oid, length, ED448_OID, sizeof(ED448_OID)))
   {
      keyType = X509_KEY_TYPE_ED448;
   }
#endif
   //Unknown algorithm identifier?
   else
   {
      keyType = X509_KEY_TYPE_UNKNOWN;
   }

   //Return public key type
   return keyType;
}


/**
 * @brief Get the elliptic curve that matches the specified OID
 * @param[in] oid Object identifier
 * @param[in] length OID length
 * @return Elliptic curve domain parameters
 **/

const EcCurveInfo *x509GetCurveInfo(const uint8_t *oid, size_t length)
{
   const EcCurveInfo *curveInfo;

   //Default elliptic curve domain parameters
   curveInfo = NULL;

#if (X509_ECDSA_SUPPORT == ENABLED && ECDSA_SUPPORT == ENABLED)
   //Invalid parameters?
   if(oid == NULL || length == 0)
   {
      curveInfo = NULL;
   }
#if (X509_SECP112R1_SUPPORT == ENABLED)
   //secp112r1 elliptic curve?
   else if(!oidComp(oid, length, SECP112R1_OID, sizeof(SECP112R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP112R2_SUPPORT == ENABLED)
   //secp112r2 elliptic curve?
   else if(!oidComp(oid, length, SECP112R2_OID, sizeof(SECP112R2_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP128R1_SUPPORT == ENABLED)
   //secp128r1 elliptic curve?
   else if(!oidComp(oid, length, SECP128R1_OID, sizeof(SECP128R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP128R2_SUPPORT == ENABLED)
   //secp128r2 elliptic curve?
   else if(!oidComp(oid, length, SECP128R2_OID, sizeof(SECP128R2_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP160K1_SUPPORT == ENABLED)
   //secp160k1 elliptic curve?
   else if(!oidComp(oid, length, SECP160K1_OID, sizeof(SECP160K1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP160R1_SUPPORT == ENABLED)
   //secp160r1 elliptic curve?
   else if(!oidComp(oid, length, SECP160R1_OID, sizeof(SECP160R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP160R2_SUPPORT == ENABLED)
   //secp160r2 elliptic curve?
   else if(!oidComp(oid, length, SECP160R2_OID, sizeof(SECP160R2_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP192K1_SUPPORT == ENABLED)
   //secp192k1 elliptic curve?
   else if(!oidComp(oid, length, SECP192K1_OID, sizeof(SECP192K1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP192R1_SUPPORT == ENABLED)
   //secp192r1 elliptic curve?
   else if(!oidComp(oid, length, SECP192R1_OID, sizeof(SECP192R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP224K1_SUPPORT == ENABLED)
   //secp224k1 elliptic curve?
   else if(!oidComp(oid, length, SECP224K1_OID, sizeof(SECP224K1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP224R1_SUPPORT == ENABLED)
   //secp224r1 elliptic curve?
   else if(!oidComp(oid, length, SECP224R1_OID, sizeof(SECP224R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP256K1_SUPPORT == ENABLED)
   //secp256k1 elliptic curve?
   else if(!oidComp(oid, length, SECP256K1_OID, sizeof(SECP256K1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP256R1_SUPPORT == ENABLED)
   //secp256r1 elliptic curve?
   else if(!oidComp(oid, length, SECP256R1_OID, sizeof(SECP256R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP384R1_SUPPORT == ENABLED)
   //secp384r1 elliptic curve?
   else if(!oidComp(oid, length, SECP384R1_OID, sizeof(SECP384R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_SECP521R1_SUPPORT == ENABLED)
   //secp521r1 elliptic curve?
   else if(!oidComp(oid, length, SECP521R1_OID, sizeof(SECP521R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP160R1_SUPPORT == ENABLED)
   //brainpoolP160r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP160R1_OID, sizeof(BRAINPOOLP160R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP192R1_SUPPORT == ENABLED)
   //brainpoolP192r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP192R1_OID, sizeof(BRAINPOOLP192R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP224R1_SUPPORT == ENABLED)
   //brainpoolP224r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP224R1_OID, sizeof(BRAINPOOLP224R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP256R1_SUPPORT == ENABLED)
   //brainpoolP256r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP256R1_OID, sizeof(BRAINPOOLP256R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP320R1_SUPPORT == ENABLED)
   //brainpoolP320r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP320R1_OID, sizeof(BRAINPOOLP320R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP384R1_SUPPORT == ENABLED)
   //brainpoolP384r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP384R1_OID, sizeof(BRAINPOOLP384R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_BRAINPOOLP512R1_SUPPORT == ENABLED)
   //brainpoolP512r1 elliptic curve?
   else if(!oidComp(oid, length, BRAINPOOLP512R1_OID, sizeof(BRAINPOOLP512R1_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_ED25519_SUPPORT == ENABLED)
   //Ed25519 elliptic curve?
   else if(!oidComp(oid, length, ED25519_OID, sizeof(ED25519_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
#if (X509_ED448_SUPPORT == ENABLED)
   //Ed448 elliptic curve?
   else if(!oidComp(oid, length, ED448_OID, sizeof(ED448_OID)))
   {
      curveInfo = ecGetCurveInfo(oid, length);
   }
#endif
   //Unknown elliptic curve?
   else
   {
      curveInfo = NULL;
   }
#endif

   //Return the elliptic curve domain parameters, if any
   return curveInfo;
}

#endif
