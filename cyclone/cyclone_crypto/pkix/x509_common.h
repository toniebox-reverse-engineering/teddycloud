/**
 * @file x509_common.h
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

#ifndef _X509_COMMON_H
#define _X509_COMMON_H

//Dependencies
#include "core/crypto.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ecdsa.h"
#include "ecc/eddsa.h"
#include "date_time.h"

//RSA certificate support
#ifndef X509_RSA_SUPPORT
   #define X509_RSA_SUPPORT ENABLED
#elif (X509_RSA_SUPPORT != ENABLED && X509_RSA_SUPPORT != DISABLED)
   #error X509_RSA_SUPPORT
#endif

//RSA-PSS certificate support
#ifndef X509_RSA_PSS_SUPPORT
   #define X509_RSA_PSS_SUPPORT DISABLED
#elif (X509_RSA_PSS_SUPPORT != ENABLED && X509_RSA_PSS_SUPPORT != DISABLED)
   #error X509_RSA_PSS_SUPPORT
#endif

//DSA certificate support
#ifndef X509_DSA_SUPPORT
   #define X509_DSA_SUPPORT DISABLED
#elif (X509_DSA_SUPPORT != ENABLED && X509_DSA_SUPPORT != DISABLED)
   #error X509_DSA_SUPPORT parameter is not valid
#endif

//ECDSA certificate support
#ifndef X509_ECDSA_SUPPORT
   #define X509_ECDSA_SUPPORT ENABLED
#elif (X509_ECDSA_SUPPORT != ENABLED && X509_ECDSA_SUPPORT != DISABLED)
   #error X509_ECDSA_SUPPORT parameter is not valid
#endif

//MD5 hash support (insecure)
#ifndef X509_MD5_SUPPORT
   #define X509_MD5_SUPPORT DISABLED
#elif (X509_MD5_SUPPORT != ENABLED && X509_MD5_SUPPORT != DISABLED)
   #error X509_MD5_SUPPORT parameter is not valid
#endif

//SHA-1 hash support (weak)
#ifndef X509_SHA1_SUPPORT
   #define X509_SHA1_SUPPORT DISABLED
#elif (X509_SHA1_SUPPORT != ENABLED && X509_SHA1_SUPPORT != DISABLED)
   #error X509_SHA1_SUPPORT parameter is not valid
#endif

//SHA-224 hash support (weak)
#ifndef X509_SHA224_SUPPORT
   #define X509_SHA224_SUPPORT DISABLED
#elif (X509_SHA224_SUPPORT != ENABLED && X509_SHA224_SUPPORT != DISABLED)
   #error X509_SHA224_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef X509_SHA256_SUPPORT
   #define X509_SHA256_SUPPORT ENABLED
#elif (X509_SHA256_SUPPORT != ENABLED && X509_SHA256_SUPPORT != DISABLED)
   #error X509_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef X509_SHA384_SUPPORT
   #define X509_SHA384_SUPPORT ENABLED
#elif (X509_SHA384_SUPPORT != ENABLED && X509_SHA384_SUPPORT != DISABLED)
   #error X509_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef X509_SHA512_SUPPORT
   #define X509_SHA512_SUPPORT ENABLED
#elif (X509_SHA512_SUPPORT != ENABLED && X509_SHA512_SUPPORT != DISABLED)
   #error X509_SHA512_SUPPORT parameter is not valid
#endif

//SHA3-224 hash support
#ifndef X509_SHA3_224_SUPPORT
   #define X509_SHA3_224_SUPPORT DISABLED
#elif (X509_SHA3_224_SUPPORT != ENABLED && X509_SHA3_224_SUPPORT != DISABLED)
   #error X509_SHA3_224_SUPPORT parameter is not valid
#endif

//SHA3-256 hash support
#ifndef X509_SHA3_256_SUPPORT
   #define X509_SHA3_256_SUPPORT DISABLED
#elif (X509_SHA3_256_SUPPORT != ENABLED && X509_SHA3_256_SUPPORT != DISABLED)
   #error X509_SHA3_256_SUPPORT parameter is not valid
#endif

//SHA3-384 hash support
#ifndef X509_SHA3_384_SUPPORT
   #define X509_SHA3_384_SUPPORT DISABLED
#elif (X509_SHA3_384_SUPPORT != ENABLED && X509_SHA3_384_SUPPORT != DISABLED)
   #error X509_SHA3_384_SUPPORT parameter is not valid
#endif

//SHA3-512 hash support
#ifndef X509_SHA3_512_SUPPORT
   #define X509_SHA3_512_SUPPORT DISABLED
#elif (X509_SHA3_512_SUPPORT != ENABLED && X509_SHA3_512_SUPPORT != DISABLED)
   #error X509_SHA3_512_SUPPORT parameter is not valid
#endif

//secp112r1 elliptic curve support (weak)
#ifndef X509_SECP112R1_SUPPORT
   #define X509_SECP112R1_SUPPORT DISABLED
#elif (X509_SECP112R1_SUPPORT != ENABLED && X509_SECP112R1_SUPPORT != DISABLED)
   #error X509_SECP112R1_SUPPORT parameter is not valid
#endif

//secp112r2 elliptic curve support (weak)
#ifndef X509_SECP112R2_SUPPORT
   #define X509_SECP112R2_SUPPORT DISABLED
#elif (X509_SECP112R2_SUPPORT != ENABLED && X509_SECP112R2_SUPPORT != DISABLED)
   #error X509_SECP112R2_SUPPORT parameter is not valid
#endif

//secp128r1 elliptic curve support (weak)
#ifndef X509_SECP128R1_SUPPORT
   #define X509_SECP128R1_SUPPORT DISABLED
#elif (X509_SECP128R1_SUPPORT != ENABLED && X509_SECP128R1_SUPPORT != DISABLED)
   #error X509_SECP128R1_SUPPORT parameter is not valid
#endif

//secp128r2 elliptic curve support (weak)
#ifndef X509_SECP128R2_SUPPORT
   #define X509_SECP128R2_SUPPORT DISABLED
#elif (X509_SECP128R2_SUPPORT != ENABLED && X509_SECP128R2_SUPPORT != DISABLED)
   #error X509_SECP128R2_SUPPORT parameter is not valid
#endif

//secp160k1 elliptic curve support (weak)
#ifndef X509_SECP160K1_SUPPORT
   #define X509_SECP160K1_SUPPORT DISABLED
#elif (X509_SECP160K1_SUPPORT != ENABLED && X509_SECP160K1_SUPPORT != DISABLED)
   #error X509_SECP160K1_SUPPORT parameter is not valid
#endif

//secp160r1 elliptic curve support (weak)
#ifndef X509_SECP160R1_SUPPORT
   #define X509_SECP160R1_SUPPORT DISABLED
#elif (X509_SECP160R1_SUPPORT != ENABLED && X509_SECP160R1_SUPPORT != DISABLED)
   #error X509_SECP160R1_SUPPORT parameter is not valid
#endif

//secp160r2 elliptic curve support (weak)
#ifndef X509_SECP160R2_SUPPORT
   #define X509_SECP160R2_SUPPORT DISABLED
#elif (X509_SECP160R2_SUPPORT != ENABLED && X509_SECP160R2_SUPPORT != DISABLED)
   #error X509_SECP160R2_SUPPORT parameter is not valid
#endif

//secp192k1 elliptic curve support
#ifndef X509_SECP192K1_SUPPORT
   #define X509_SECP192K1_SUPPORT DISABLED
#elif (X509_SECP192K1_SUPPORT != ENABLED && X509_SECP192K1_SUPPORT != DISABLED)
   #error X509_SECP192K1_SUPPORT parameter is not valid
#endif

//secp192r1 elliptic curve support (NIST P-192)
#ifndef X509_SECP192R1_SUPPORT
   #define X509_SECP192R1_SUPPORT DISABLED
#elif (X509_SECP192R1_SUPPORT != ENABLED && X509_SECP192R1_SUPPORT != DISABLED)
   #error X509_SECP192R1_SUPPORT parameter is not valid
#endif

//secp224k1 elliptic curve support
#ifndef X509_SECP224K1_SUPPORT
   #define X509_SECP224K1_SUPPORT DISABLED
#elif (X509_SECP224K1_SUPPORT != ENABLED && X509_SECP224K1_SUPPORT != DISABLED)
   #error X509_SECP224K1_SUPPORT parameter is not valid
#endif

//secp224r1 elliptic curve support (NIST P-224)
#ifndef X509_SECP224R1_SUPPORT
   #define X509_SECP224R1_SUPPORT DISABLED
#elif (X509_SECP224R1_SUPPORT != ENABLED && X509_SECP224R1_SUPPORT != DISABLED)
   #error X509_SECP224R1_SUPPORT parameter is not valid
#endif

//secp256k1 elliptic curve support
#ifndef X509_SECP256K1_SUPPORT
   #define X509_SECP256K1_SUPPORT DISABLED
#elif (X509_SECP256K1_SUPPORT != ENABLED && X509_SECP256K1_SUPPORT != DISABLED)
   #error X509_SECP256K1_SUPPORT parameter is not valid
#endif

//secp256r1 elliptic curve support (NIST P-256)
#ifndef X509_SECP256R1_SUPPORT
   #define X509_SECP256R1_SUPPORT ENABLED
#elif (X509_SECP256R1_SUPPORT != ENABLED && X509_SECP256R1_SUPPORT != DISABLED)
   #error X509_SECP256R1_SUPPORT parameter is not valid
#endif

//secp384r1 elliptic curve support (NIST P-384)
#ifndef X509_SECP384R1_SUPPORT
   #define X509_SECP384R1_SUPPORT ENABLED
#elif (X509_SECP384R1_SUPPORT != ENABLED && X509_SECP384R1_SUPPORT != DISABLED)
   #error X509_SECP384R1_SUPPORT parameter is not valid
#endif

//secp521r1 elliptic curve support (NIST P-521)
#ifndef X509_SECP521R1_SUPPORT
   #define X509_SECP521R1_SUPPORT ENABLED
#elif (X509_SECP521R1_SUPPORT != ENABLED && X509_SECP521R1_SUPPORT != DISABLED)
   #error X509_SECP521R1_SUPPORT parameter is not valid
#endif

//brainpoolP160r1 elliptic curve support
#ifndef X509_BRAINPOOLP160R1_SUPPORT
   #define X509_BRAINPOOLP160R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP160R1_SUPPORT != ENABLED && X509_BRAINPOOLP160R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP160R1_SUPPORT parameter is not valid
#endif

//brainpoolP192r1 elliptic curve support
#ifndef X509_BRAINPOOLP192R1_SUPPORT
   #define X509_BRAINPOOLP192R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP192R1_SUPPORT != ENABLED && X509_BRAINPOOLP192R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP192R1_SUPPORT parameter is not valid
#endif

//brainpoolP224r1 elliptic curve support
#ifndef X509_BRAINPOOLP224R1_SUPPORT
   #define X509_BRAINPOOLP224R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP224R1_SUPPORT != ENABLED && X509_BRAINPOOLP224R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP224R1_SUPPORT parameter is not valid
#endif

//brainpoolP256r1 elliptic curve support
#ifndef X509_BRAINPOOLP256R1_SUPPORT
   #define X509_BRAINPOOLP256R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP256R1_SUPPORT != ENABLED && X509_BRAINPOOLP256R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP256R1_SUPPORT parameter is not valid
#endif

//brainpoolP320r1 elliptic curve support
#ifndef X509_BRAINPOOLP320R1_SUPPORT
   #define X509_BRAINPOOLP320R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP320R1_SUPPORT != ENABLED && X509_BRAINPOOLP320R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP320R1_SUPPORT parameter is not valid
#endif

//brainpoolP384r1 elliptic curve support
#ifndef X509_BRAINPOOLP384R1_SUPPORT
   #define X509_BRAINPOOLP384R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP384R1_SUPPORT != ENABLED && X509_BRAINPOOLP384R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP384R1_SUPPORT parameter is not valid
#endif

//brainpoolP512r1 elliptic curve support
#ifndef X509_BRAINPOOLP512R1_SUPPORT
   #define X509_BRAINPOOLP512R1_SUPPORT DISABLED
#elif (X509_BRAINPOOLP512R1_SUPPORT != ENABLED && X509_BRAINPOOLP512R1_SUPPORT != DISABLED)
   #error X509_BRAINPOOLP512R1_SUPPORT parameter is not valid
#endif

//Ed25519 elliptic curve support
#ifndef X509_ED25519_SUPPORT
   #define X509_ED25519_SUPPORT DISABLED
#elif (X509_ED25519_SUPPORT != ENABLED && X509_ED25519_SUPPORT != DISABLED)
   #error X509_ED25519_SUPPORT parameter is not valid
#endif

//Ed448 elliptic curve support
#ifndef X509_ED448_SUPPORT
   #define X509_ED448_SUPPORT DISABLED
#elif (X509_ED448_SUPPORT != ENABLED && X509_ED448_SUPPORT != DISABLED)
   #error X509_ED448_SUPPORT parameter is not valid
#endif

//Minimum acceptable size for RSA modulus
#ifndef X509_MIN_RSA_MODULUS_SIZE
   #define X509_MIN_RSA_MODULUS_SIZE 1024
#elif (X509_MIN_RSA_MODULUS_SIZE < 512)
   #error X509_MIN_RSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for RSA modulus
#ifndef X509_MAX_RSA_MODULUS_SIZE
   #define X509_MAX_RSA_MODULUS_SIZE 4096
#elif (X509_MAX_RSA_MODULUS_SIZE < X509_MIN_RSA_MODULUS_SIZE)
   #error X509_MAX_RSA_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for DSA prime modulus
#ifndef X509_MIN_DSA_MODULUS_SIZE
   #define X509_MIN_DSA_MODULUS_SIZE 1024
#elif (X509_MIN_DSA_MODULUS_SIZE < 512)
   #error X509_MIN_DSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for DSA prime modulus
#ifndef X509_MAX_DSA_MODULUS_SIZE
   #define X509_MAX_DSA_MODULUS_SIZE 4096
#elif (X509_MAX_DSA_MODULUS_SIZE < X509_MIN_DSA_MODULUS_SIZE)
   #error X509_MAX_DSA_MODULUS_SIZE parameter is not valid
#endif

//Default size of serial numbers
#ifndef X509_SERIAL_NUMBER_SIZE
   #define X509_SERIAL_NUMBER_SIZE 20
#elif (X509_SERIAL_NUMBER_SIZE < 1)
   #error X509_SERIAL_NUMBER_SIZE parameter is not valid
#endif

//Maximum number of subject alternative names
#ifndef X509_MAX_SUBJECT_ALT_NAMES
   #define X509_MAX_SUBJECT_ALT_NAMES 4
#elif (X509_MAX_SUBJECT_ALT_NAMES < 1)
   #error X509_MAX_SUBJECT_ALT_NAMES parameter is not valid
#endif

//Maximum number of certificate issuer names
#ifndef X509_MAX_CERT_ISSUER_NAMES
   #define X509_MAX_CERT_ISSUER_NAMES 4
#elif (X509_MAX_CERT_ISSUER_NAMES < 1)
   #error X509_MAX_CERT_ISSUER_NAMES parameter is not valid
#endif

//Maximum number of custom extensions
#ifndef X509_MAX_CUSTOM_EXTENSIONS
   #define X509_MAX_CUSTOM_EXTENSIONS 2
#elif (X509_MAX_CUSTOM_EXTENSIONS < 1)
   #error X509_MAX_CUSTOM_EXTENSIONS parameter is not valid
#endif

//Maximum digest size
#if (X509_SHA3_512_SUPPORT == ENABLED && SHA3_512_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 64
#elif (X509_SHA512_SUPPORT == ENABLED && SHA512_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 64
#elif (X509_SHA3_384_SUPPORT == ENABLED && SHA3_384_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 48
#elif (X509_SHA384_SUPPORT == ENABLED && SHA384_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 48
#elif (X509_SHA3_256_SUPPORT == ENABLED && SHA3_256_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 32
#elif (X509_SHA256_SUPPORT == ENABLED && SHA256_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 32
#elif (X509_SHA3_224_SUPPORT == ENABLED && SHA3_224_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 28
#elif (X509_SHA224_SUPPORT == ENABLED && SHA224_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 28
#elif (X509_SHA1_SUPPORT == ENABLED && SHA1_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 20
#elif (X509_MD5_SUPPORT == ENABLED && MD5_SUPPORT == ENABLED)
   #define X509_MAX_HASH_DIGEST_SIZE 16
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief X.509 versions
 **/

typedef enum
{
   X509_VERSION_1 = 0x00,
   X509_VERSION_2 = 0x01,
   X509_VERSION_3 = 0x02,
} X509Version;


/**
 * @brief Key usage
 **/

typedef enum
{
   X509_KEY_USAGE_DIGITAL_SIGNATURE = 0x0001,
   X509_KEY_USAGE_NON_REPUDIATION   = 0x0002,
   X509_KEY_USAGE_KEY_ENCIPHERMENT  = 0x0004,
   X509_KEY_USAGE_DATA_ENCIPHERMENT = 0x0008,
   X509_KEY_USAGE_KEY_AGREEMENT     = 0x0010,
   X509_KEY_USAGE_KEY_CERT_SIGN     = 0x0020,
   X509_KEY_USAGE_CRL_SIGN          = 0x0040,
   X509_KEY_USAGE_ENCIPHER_ONLY     = 0x0080,
   X509_KEY_USAGE_DECIPHER_ONLY     = 0x0100
} X509KeyUsageBitmap;


/**
 * @brief Extended key usage
 **/

typedef enum
{
   X509_EXT_KEY_USAGE_SERVER_AUTH      = 0x01,
   X509_EXT_KEY_USAGE_CLIENT_AUTH      = 0x02,
   X509_EXT_KEY_USAGE_CODE_SIGNING     = 0x04,
   X509_EXT_KEY_USAGE_EMAIL_PROTECTION = 0x08,
   X509_EXT_KEY_USAGE_TIME_STAMPING    = 0x10,
   X509_EXT_KEY_USAGE_OCSP_SIGNING     = 0x20,
   X509_EXT_KEY_USAGE_SSH_CLIENT       = 0x40,
   X509_EXT_KEY_USAGE_SSH_SERVER       = 0x80,
   X509_EXT_KEY_USAGE_ANY              = 0xFF
} X509ExtKeyUsageBitmap;


/**
 * @brief General name types
 **/

typedef enum
{
   X509_GENERAL_NAME_TYPE_OTHER         = 0,
   X509_GENERAL_NAME_TYPE_RFC822        = 1,
   X509_GENERAL_NAME_TYPE_DNS           = 2,
   X509_GENERAL_NAME_TYPE_X400_ADDRESS  = 3,
   X509_GENERAL_NAME_TYPE_DIRECTORY     = 4,
   X509_GENERAL_NAME_TYPE_EDI_PARTY     = 5,
   X509_GENERAL_NAME_TYPE_URI           = 6,
   X509_GENERAL_NAME_TYPE_IP_ADDRESS    = 7,
   X509_GENERAL_NAME_TYPE_REGISTERED_ID = 8
} X509GeneralNameType;


/**
 * @brief Netscape certificate types
 **/

typedef enum
{
   X509_NS_CERT_TYPE_SSL_CLIENT = 0x01,
   X509_NS_CERT_TYPE_SSL_SERVER = 0x02,
   X509_NS_CERT_TYPE_SSL_CA     = 0x20
} X509NsCertTypeBitmap;


/**
 * @brief Reason flags
 **/

typedef enum
{
   X509_REASON_FLAGS_UNUSED                 = 0x0001,
   X509_REASON_FLAGS_KEY_COMPROMISE         = 0x0002,
   X509_REASON_FLAGS_CA_COMPROMISE          = 0x0004,
   X509_REASON_FLAGS_AFFILIATION_CHANGED    = 0x0008,
   X509_REASON_FLAGS_SUPERSEDED             = 0x0010,
   X509_REASON_FLAGS_CESSATION_OF_OPERATION = 0x0020,
   X509_REASON_FLAGS_CERTIFICATE_HOLD       = 0x0040,
   X509_REASON_FLAGS_PRIVILEGE_WITHDRAWN    = 0x0080,
   X509_REASON_FLAGS_AA_COMPROMISE          = 0x0100
} X509ReasonFlags;


/**
 * @brief CRL reasons
 **/

typedef enum
{
   X509_CRL_REASON_UNSPECIFIED            = 0,
   X509_CRL_REASON_KEY_COMPROMISE         = 1,
   X509_CRL_REASON_CA_COMPROMISE          = 2,
   X509_CRL_REASON_AFFILIATION_CHANGED    = 3,
   X509_CRL_REASON_SUPERSEDED             = 4,
   X509_CRL_REASON_CESSATION_OF_OPERATION = 5,
   X509_CRL_REASON_CERTIFICATE_HOLD       = 6,
   X509_CRL_REMOVE_FROM_CRL               = 8,
   X509_CRL_REASON_PRIVILEGE_WITHDRAWN    = 9,
   X509_CRL_REASON_AA_COMPROMISE          = 10
} X509CrlReasons;


/**
 * @brief Public Key types
 **/

typedef enum
{
   X509_KEY_TYPE_UNKNOWN = 0,
   X509_KEY_TYPE_RSA     = 1,
   X509_KEY_TYPE_RSA_PSS = 2,
   X509_KEY_TYPE_DSA     = 3,
   X509_KEY_TYPE_EC      = 4,
   X509_KEY_TYPE_X25519  = 5,
   X509_KEY_TYPE_ED25519 = 6,
   X509_KEY_TYPE_X448    = 7,
   X509_KEY_TYPE_ED448   = 8
} X509KeyType;


/**
 * @brief Signature algorithms
 **/

typedef enum
{
   X509_SIGN_ALGO_NONE    = 0,
   X509_SIGN_ALGO_RSA     = 1,
   X509_SIGN_ALGO_RSA_PSS = 2,
   X509_SIGN_ALGO_DSA     = 3,
   X509_SIGN_ALGO_ECDSA   = 4,
   X509_SIGN_ALGO_ED25519 = 5,
   X509_SIGN_ALGO_ED448   = 6
} X509SignatureAlgo;


/**
 * @brief Hash algorithms
 **/

typedef enum
{
   X509_HASH_ALGO_NONE     = 0,
   X509_HASH_ALGO_MD5      = 1,
   X509_HASH_ALGO_SHA1     = 2,
   X509_HASH_ALGO_SHA224   = 3,
   X509_HASH_ALGO_SHA256   = 4,
   X509_HASH_ALGO_SHA384   = 5,
   X509_HASH_ALGO_SHA512   = 6,
   X509_HASH_ALGO_SHA3_224 = 7,
   X509_HASH_ALGO_SHA3_256 = 8,
   X509_HASH_ALGO_SHA3_384 = 9,
   X509_HASH_ALGO_SHA3_512 = 10
} X509HashAlgo;


/**
 * @brief Serial number
 **/

typedef struct
{
   const uint8_t *data;
   size_t length;
} X509SerialNumber;


/**
 * @brief Issuer or subject name
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   const char_t *commonName;
   size_t commonNameLen;
   const char_t *surname;
   size_t surnameLen;
   const char_t *serialNumber;
   size_t serialNumberLen;
   const char_t *countryName;
   size_t countryNameLen;
   const char_t *localityName;
   size_t localityNameLen;
   const char_t *stateOrProvinceName;
   size_t stateOrProvinceNameLen;
   const char_t *organizationName;
   size_t organizationNameLen;
   const char_t *organizationalUnitName;
   size_t organizationalUnitNameLen;
   const char_t *title;
   size_t titleLen;
   const char_t *name;
   size_t nameLen;
   const char_t *givenName;
   size_t givenNameLen;
   const char_t *initials;
   size_t initialsLen;
   const char_t *generationQualifier;
   size_t generationQualifierLen;
   const char_t *dnQualifier;
   size_t dnQualifierLen;
   const char_t *pseudonym;
   size_t pseudonymLen;
} X509Name;


/**
 * @brief Name attribute
 **/

typedef struct
{
   const uint8_t *type;
   size_t typeLen;
   const char_t *value;
   size_t valueLen;
} X509NameAttribute;


/**
 * @brief Validity
 **/

typedef struct
{
   DateTime notBefore;
   DateTime notAfter;
} X509Validity;


/**
 * @brief RSA public key
 **/

typedef struct
{
   const uint8_t *n;
   size_t nLen;
   const uint8_t *e;
   size_t eLen;
} X509RsaPublicKey;


/**
 * @brief DSA domain parameters
 **/

typedef struct
{
   const uint8_t *p;
   size_t pLen;
   const uint8_t *q;
   size_t qLen;
   const uint8_t *g;
   size_t gLen;
} X509DsaParameters;


/**
 * @brief DSA public key
 **/

typedef struct
{
   const uint8_t *y;
   size_t yLen;
} X509DsaPublicKey;


/**
 * @brief EC parameters
 **/

typedef struct
{
   const uint8_t *namedCurve;
   size_t namedCurveLen;
} X509EcParameters;


/**
 * @brief EC public key
 **/

typedef struct
{
   const uint8_t *q;
   size_t qLen;
} X509EcPublicKey;


/**
 * @brief Subject public key information
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   const uint8_t *oid;
   size_t oidLen;
#if (RSA_SUPPORT == ENABLED)
   X509RsaPublicKey rsaPublicKey;
#endif
#if (DSA_SUPPORT == ENABLED)
   X509DsaParameters dsaParams;
   X509DsaPublicKey dsaPublicKey;
#endif
#if (EC_SUPPORT == ENABLED || ED25519_SUPPORT == ENABLED || ED448_SUPPORT == ENABLED)
   X509EcParameters ecParams;
   X509EcPublicKey ecPublicKey;
#endif
} X509SubjectPublicKeyInfo;


/**
 * @brief Basic constraints
 **/

typedef struct
{
   bool_t critical;
   bool_t cA;
   int_t pathLenConstraint;
} X509BasicConstraints;


/**
 * @brief Name constraints
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *permittedSubtrees;
   size_t permittedSubtreesLen;
   const uint8_t *excludedSubtrees;
   size_t excludedSubtreesLen;
} X509NameConstraints;


/**
 * @brief Key usage
 **/

typedef struct
{
   bool_t critical;
   uint16_t bitmap;
} X509KeyUsage;


/**
 * @brief Extended key usage
 **/

typedef struct
{
   bool_t critical;
   uint8_t bitmap;
} X509ExtendedKeyUsage;


/**
 * @brief General name
 **/

typedef struct
{
   X509GeneralNameType type;
   const char_t *value;
   size_t length;
} X509GeneralName;


/**
 * @brief Subject alternative name
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *rawData;
   size_t rawDataLen;
   uint_t numGeneralNames;
   X509GeneralName generalNames[X509_MAX_SUBJECT_ALT_NAMES];
} X509SubjectAltName;


/**
 * @brief Subject key identifier
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *value;
   size_t length;
} X509SubjectKeyId;


/**
 * @brief Authority key identifier
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *keyId;
   size_t keyIdLen;
} X509AuthorityKeyId;


/**
 * @brief Netscape certificate type
 **/

typedef struct
{
   bool_t critical;
   uint8_t bitmap;
} X509NsCertType;


/**
 * @brief X.509 certificate extension
 **/

typedef struct
{
   const uint8_t *oid;
   size_t oidLen;
   bool_t critical;
   const uint8_t *value;
   size_t valueLen;
} X509Extension;


/**
 * @brief X.509 certificate extensions
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   X509BasicConstraints basicConstraints;
   X509NameConstraints nameConstraints;
   X509KeyUsage keyUsage;
   X509ExtendedKeyUsage extKeyUsage;
   X509SubjectAltName subjectAltName;
   X509SubjectKeyId subjectKeyId;
   X509AuthorityKeyId authKeyId;
   X509NsCertType nsCertType;
   uint_t numCustomExtensions;
   X509Extension customExtensions[X509_MAX_CUSTOM_EXTENSIONS];
} X509Extensions;


/**
 * @brief RSASSA-PSS parameters
 **/

typedef struct
{
   const uint8_t *hashAlgo;
   size_t hashAlgoLen;
   const uint8_t *maskGenAlgo;
   size_t maskGenAlgoLen;
   const uint8_t *maskGenHashAlgo;
   size_t maskGenHashAlgoLen;
   size_t saltLen;
} X509RsaPssParameters;


/**
 * @brief Signature algorithm identifier
 **/

typedef struct
{
   const uint8_t *oid;
   size_t oidLen;
#if (X509_RSA_PSS_SUPPORT == ENABLED && RSA_SUPPORT == ENABLED)
   X509RsaPssParameters rsaPssParams;
#endif
} X509SignatureAlgoId;


/**
 * @brief Signature value
 **/

typedef struct
{
   const uint8_t *data;
   size_t length;
} X509SignatureValue;


/**
 * @brief TBSCertificate structure
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   X509Version version;
   X509SerialNumber serialNumber;
   X509SignatureAlgoId signatureAlgo;
   X509Name issuer;
   X509Validity validity;
   X509Name subject;
   X509SubjectPublicKeyInfo subjectPublicKeyInfo;
   X509Extensions extensions;
} X509TbsCertificate;


/**
 * @brief X.509 certificate
 **/

typedef struct
{
   X509TbsCertificate tbsCert;
   X509SignatureAlgoId signatureAlgo;
   X509SignatureValue signatureValue;
} X509CertificateInfo;


/**
 * @brief CRL reason
 **/

typedef struct
{
   bool_t critical;
   uint8_t value;
} X509CrlReason;


/**
 * @brief Invalidity date
 **/

typedef struct
{
   bool_t critical;
   DateTime value;
} X509InvalidityDate;


/**
 * @brief Certificate issuer
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *rawData;
   size_t rawDataLen;
   uint_t numGeneralNames;
   X509GeneralName generalNames[X509_MAX_CERT_ISSUER_NAMES];
} X509CertificateIssuer;


/**
 * @brief CRL extensions
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   X509CrlReason reasonCode;
   X509InvalidityDate invalidityDate;
   X509CertificateIssuer certIssuer;
} X509CrlEntryExtensions;


/**
 * @brief Revoked certificate
 **/

typedef struct
{
   X509SerialNumber userCert;
   DateTime revocationDate;
   X509CrlEntryExtensions crlEntryExtensions;
} X509RevokedCertificate;


/**
 * @brief CRL number
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *value;
   size_t length;
} X509CrlNumber;


/**
 * @brief Delta CRL indicator
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *baseCrlNumber;
   size_t baseCrlNumberLen;
} X509DeltaCrlIndicator;


/**
 * @brief Distribution point name
 **/

typedef struct
{
   bool_t critical;
   const uint8_t *fullName;
   size_t fullNameLen;
   const uint8_t *nameRelativeToCrlIssuer;
   size_t nameRelativeToCrlIssuerLen;
} X509DistrPointName;


/**
 * @brief Issuing distribution point
 **/

typedef struct
{
   bool_t critical;
   X509DistrPointName distributionPoint;
   bool_t onlyContainsUserCerts;
   bool_t onlyContainsCaCerts;
   uint16_t onlySomeReasons;
   bool_t indirectCrl;
   bool_t onlyContainsAttributeCerts;
} X509IssuingDistrPoint;


/**
 * @brief CRL extensions
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   X509CrlNumber crlNumber;
   X509DeltaCrlIndicator deltaCrlIndicator;
   X509IssuingDistrPoint issuingDistrPoint;
   X509AuthorityKeyId authKeyId;
} X509CrlExtensions;


/**
 * @brief TBSCertList structure
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   X509Version version;
   X509SignatureAlgoId signatureAlgo;
   X509Name issuer;
   DateTime thisUpdate;
   DateTime nextUpdate;
   const uint8_t *revokedCerts;
   size_t revokedCertsLen;
   X509CrlExtensions crlExtensions;
} X509TbsCertList;


/**
 * @brief CRL (Certificate Revocation List)
 **/

typedef struct
{
   X509TbsCertList tbsCertList;
   X509SignatureAlgoId signatureAlgo;
   X509SignatureValue signatureValue;
} X509CrlInfo;


/**
 * @brief PKCS#9 ChallengePassword attribute
 **/

typedef struct
{
   const char_t *value;
   size_t length;
} X509ChallengePassword;


/**
 * @brief CSR attribute
 **/

typedef struct
{
   const uint8_t *oid;
   size_t oidLen;
   const uint8_t *value;
   size_t valueLen;
} X509Attribute;


/**
 * @brief CSR attributes
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   X509ChallengePassword challengePwd;
   X509Extensions extensionReq;
} X509Attributes;


/**
 * @brief CertificationRequestInfo structure
 **/

typedef struct
{
   const uint8_t *rawData;
   size_t rawDataLen;
   X509Version version;
   X509Name subject;
   X509SubjectPublicKeyInfo subjectPublicKeyInfo;
   X509Attributes attributes;
} X509CertRequestInfo;


/**
 * @brief CSR (Certificate Signing Request)
 **/

typedef struct
{
   X509CertRequestInfo certReqInfo;
   X509SignatureAlgoId signatureAlgo;
   X509SignatureValue signatureValue;
} X509CsrInfo;


//X.509 related constants
extern const uint8_t X509_COMMON_NAME_OID[3];
extern const uint8_t X509_SURNAME_OID[3];
extern const uint8_t X509_SERIAL_NUMBER_OID[3];
extern const uint8_t X509_COUNTRY_NAME_OID[3];
extern const uint8_t X509_LOCALITY_NAME_OID[3];
extern const uint8_t X509_STATE_OR_PROVINCE_NAME_OID[3];
extern const uint8_t X509_ORGANIZATION_NAME_OID[3];
extern const uint8_t X509_ORGANIZATIONAL_UNIT_NAME_OID[3];
extern const uint8_t X509_TITLE_OID[3];
extern const uint8_t X509_NAME_OID[3];
extern const uint8_t X509_GIVEN_NAME_OID[3];
extern const uint8_t X509_INITIALS_OID[3];
extern const uint8_t X509_GENERATION_QUALIFIER_OID[3];
extern const uint8_t X509_DN_QUALIFIER_OID[3];
extern const uint8_t X509_PSEUDONYM_OID[3];

extern const uint8_t X509_SUBJECT_DIRECTORY_ATTR_OID[3];
extern const uint8_t X509_SUBJECT_KEY_ID_OID[3];
extern const uint8_t X509_KEY_USAGE_OID[3];
extern const uint8_t X509_SUBJECT_ALT_NAME_OID[3];
extern const uint8_t X509_ISSUER_ALT_NAME_OID[3];
extern const uint8_t X509_BASIC_CONSTRAINTS_OID[3];
extern const uint8_t X509_CRL_NUMBER_OID[3];
extern const uint8_t X509_REASON_CODE_OID[3];
extern const uint8_t X509_INVALIDITY_DATE_OID[3];
extern const uint8_t X509_DELTA_CRL_INDICATOR_OID[3];
extern const uint8_t X509_ISSUING_DISTR_POINT_OID[3];
extern const uint8_t X509_CERTIFICATE_ISSUER_OID[3];
extern const uint8_t X509_NAME_CONSTRAINTS_OID[3];
extern const uint8_t X509_CRL_DISTR_POINTS_OID[3];
extern const uint8_t X509_CERTIFICATE_POLICIES_OID[3];
extern const uint8_t X509_POLICY_MAPPINGS_OID[3];
extern const uint8_t X509_AUTHORITY_KEY_ID_OID[3];
extern const uint8_t X509_POLICY_CONSTRAINTS_OID[3];
extern const uint8_t X509_EXTENDED_KEY_USAGE_OID[3];
extern const uint8_t X509_FRESHEST_CRL_OID[3];
extern const uint8_t X509_INHIBIT_ANY_POLICY_OID[3];

extern const uint8_t X509_NS_CERT_TYPE_OID[9];

extern const uint8_t X509_ANY_EXT_KEY_USAGE_OID[4];
extern const uint8_t X509_KP_SERVER_AUTH_OID[8];
extern const uint8_t X509_KP_CLIENT_AUTH_OID[8];
extern const uint8_t X509_KP_CODE_SIGNING_OID[8];
extern const uint8_t X509_KP_EMAIL_PROTECTION_OID[8];
extern const uint8_t X509_KP_TIME_STAMPING_OID[8];
extern const uint8_t X509_KP_OCSP_SIGNING_OID[8];
extern const uint8_t X509_KP_SSH_CLIENT_OID[8];
extern const uint8_t X509_KP_SSH_SERVER_OID[8];

extern const uint8_t X509_CHALLENGE_PASSWORD_OID[9];
extern const uint8_t X509_EXTENSION_REQUEST_OID[9];

//X.509 related functions
bool_t x509IsSignAlgoSupported(X509SignatureAlgo signAlgo);
bool_t x509IsHashAlgoSupported(X509HashAlgo hashAlgo);

error_t x509GetSignHashAlgo(const X509SignatureAlgoId *signAlgoId,
   X509SignatureAlgo *signAlgo, const HashAlgo **hashAlgo);

X509KeyType x509GetPublicKeyType(const uint8_t *oid, size_t length);
const EcCurveInfo *x509GetCurveInfo(const uint8_t *oid, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
