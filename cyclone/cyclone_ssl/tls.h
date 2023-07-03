/**
 * @file tls.h
 * @brief TLS (Transport Layer Security)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSL Open.
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

#ifndef _TLS_H
#define _TLS_H

//Forward declaration of TlsContext structure
struct _TlsContext;
#define TlsContext struct _TlsContext

//Forward declaration of TlsEncryptionEngine structure
struct _TlsEncryptionEngine;
#define TlsEncryptionEngine struct _TlsEncryptionEngine

//Dependencies
#include "os_port.h"
#include "core/crypto.h"
#include "tls_config.h"
#include "tls_legacy.h"
#include "tls13_misc.h"
#include "dtls_misc.h"
#include "mac/hmac.h"
#include "aead/aead_algorithms.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ecdsa.h"
#include "pkc/dh.h"
#include "ecc/ecdh.h"
#include "pkix/x509_common.h"


/*
 * CycloneSSL Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneSSL Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneSSL Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneSSL Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#ifndef GPL_LICENSE_TERMS_ACCEPTED
   #error Before compiling CycloneSSL Open, you must accept the terms of the GPL license
#endif

//Version string
#define CYCLONE_SSL_VERSION_STRING "2.2.0"
//Major version
#define CYCLONE_SSL_MAJOR_VERSION 2
//Minor version
#define CYCLONE_SSL_MINOR_VERSION 2
//Revision number
#define CYCLONE_SSL_REV_NUMBER 0

//TLS version numbers
#define SSL_VERSION_3_0 0x0300
#define TLS_VERSION_1_0 0x0301
#define TLS_VERSION_1_1 0x0302
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304

//TLS support
#ifndef TLS_SUPPORT
   #define TLS_SUPPORT ENABLED
#elif (TLS_SUPPORT != ENABLED && TLS_SUPPORT != DISABLED)
   #error TLS_SUPPORT parameter is not valid
#endif

//Client mode of operation
#ifndef TLS_CLIENT_SUPPORT
   #define TLS_CLIENT_SUPPORT ENABLED
#elif (TLS_CLIENT_SUPPORT != ENABLED && TLS_CLIENT_SUPPORT != DISABLED)
   #error TLS_CLIENT_SUPPORT parameter is not valid
#endif

//Server mode of operation
#ifndef TLS_SERVER_SUPPORT
   #define TLS_SERVER_SUPPORT ENABLED
#elif (TLS_SERVER_SUPPORT != ENABLED && TLS_SERVER_SUPPORT != DISABLED)
   #error TLS_SERVER_SUPPORT parameter is not valid
#endif

//Minimum TLS version that can be negotiated
#ifndef TLS_MIN_VERSION
   #define TLS_MIN_VERSION TLS_VERSION_1_2
#elif (TLS_MIN_VERSION < TLS_VERSION_1_0)
   #error TLS_MIN_VERSION parameter is not valid
#endif

//Maximum TLS version that can be negotiated
#ifndef TLS_MAX_VERSION
   #define TLS_MAX_VERSION TLS_VERSION_1_3
#elif (TLS_MAX_VERSION > TLS_VERSION_1_3 || TLS_MAX_VERSION < TLS_MIN_VERSION)
   #error TLS_MAX_VERSION parameter is not valid
#endif

//Session resumption mechanism
#ifndef TLS_SESSION_RESUME_SUPPORT
   #define TLS_SESSION_RESUME_SUPPORT ENABLED
#elif (TLS_SESSION_RESUME_SUPPORT != ENABLED && TLS_SESSION_RESUME_SUPPORT != DISABLED)
   #error TLS_SESSION_RESUME_SUPPORT parameter is not valid
#endif

//Lifetime of session cache entries
#ifndef TLS_SESSION_CACHE_LIFETIME
   #define TLS_SESSION_CACHE_LIFETIME 3600000
#elif (TLS_SESSION_CACHE_LIFETIME < 1000)
   #error TLS_SESSION_CACHE_LIFETIME parameter is not valid
#endif

//Session ticket mechanism
#ifndef TLS_TICKET_SUPPORT
   #define TLS_TICKET_SUPPORT DISABLED
#elif (TLS_TICKET_SUPPORT != ENABLED && TLS_TICKET_SUPPORT != DISABLED)
   #error TLS_TICKET_SUPPORT parameter is not valid
#endif

//Maximum size for session tickets
#ifndef TLS_MAX_TICKET_SIZE
   #define TLS_MAX_TICKET_SIZE 1024
#elif (TLS_MAX_TICKET_SIZE < 32)
   #error TLS_MAX_TICKET_SIZE parameter is not valid
#endif

//Lifetime of session tickets
#ifndef TLS_TICKET_LIFETIME
   #define TLS_TICKET_LIFETIME 3600000
#elif (TLS_TICKET_LIFETIME < 0)
   #error TLS_TICKET_LIFETIME parameter is not valid
#endif

//SNI (Server Name Indication) extension
#ifndef TLS_SNI_SUPPORT
   #define TLS_SNI_SUPPORT ENABLED
#elif (TLS_SNI_SUPPORT != ENABLED && TLS_SNI_SUPPORT != DISABLED)
   #error TLS_SNI_SUPPORT parameter is not valid
#endif

//Maximum Fragment Length extension
#ifndef TLS_MAX_FRAG_LEN_SUPPORT
   #define TLS_MAX_FRAG_LEN_SUPPORT DISABLED
#elif (TLS_MAX_FRAG_LEN_SUPPORT != ENABLED && TLS_MAX_FRAG_LEN_SUPPORT != DISABLED)
   #error TLS_MAX_FRAG_LEN_SUPPORT parameter is not valid
#endif

//Record Size Limit extension
#ifndef TLS_RECORD_SIZE_LIMIT_SUPPORT
   #define TLS_RECORD_SIZE_LIMIT_SUPPORT ENABLED
#elif (TLS_RECORD_SIZE_LIMIT_SUPPORT != ENABLED && TLS_RECORD_SIZE_LIMIT_SUPPORT != DISABLED)
   #error TLS_RECORD_SIZE_LIMIT_SUPPORT parameter is not valid
#endif

//ALPN (Application-Layer Protocol Negotiation) extension
#ifndef TLS_ALPN_SUPPORT
   #define TLS_ALPN_SUPPORT DISABLED
#elif (TLS_ALPN_SUPPORT != ENABLED && TLS_ALPN_SUPPORT != DISABLED)
   #error TLS_ALPN_SUPPORT parameter is not valid
#endif

//Extended Master Secret extension
#ifndef TLS_EXT_MASTER_SECRET_SUPPORT
   #define TLS_EXT_MASTER_SECRET_SUPPORT ENABLED
#elif (TLS_EXT_MASTER_SECRET_SUPPORT != ENABLED && TLS_EXT_MASTER_SECRET_SUPPORT != DISABLED)
   #error TLS_EXT_MASTER_SECRET_SUPPORT parameter is not valid
#endif

//ClientHello Padding extension
#ifndef TLS_CLIENT_HELLO_PADDING_SUPPORT
   #define TLS_CLIENT_HELLO_PADDING_SUPPORT ENABLED
#elif (TLS_CLIENT_HELLO_PADDING_SUPPORT != ENABLED && TLS_CLIENT_HELLO_PADDING_SUPPORT != DISABLED)
   #error TLS_CLIENT_HELLO_PADDING_SUPPORT parameter is not valid
#endif

//Signature Algorithms Certificate extension
#ifndef TLS_SIGN_ALGOS_CERT_SUPPORT
   #define TLS_SIGN_ALGOS_CERT_SUPPORT DISABLED
#elif (TLS_SIGN_ALGOS_CERT_SUPPORT != ENABLED && TLS_SIGN_ALGOS_CERT_SUPPORT != DISABLED)
   #error TLS_SIGN_ALGOS_CERT_SUPPORT parameter is not valid
#endif

//RPK (Raw Public Key) support
#ifndef TLS_RAW_PUBLIC_KEY_SUPPORT
   #define TLS_RAW_PUBLIC_KEY_SUPPORT DISABLED
#elif (TLS_RAW_PUBLIC_KEY_SUPPORT != ENABLED && TLS_RAW_PUBLIC_KEY_SUPPORT != DISABLED)
   #error TLS_RAW_PUBLIC_KEY_SUPPORT parameter is not valid
#endif

//Secure renegotiation support
#ifndef TLS_SECURE_RENEGOTIATION_SUPPORT
   #define TLS_SECURE_RENEGOTIATION_SUPPORT DISABLED
#elif (TLS_SECURE_RENEGOTIATION_SUPPORT != ENABLED && TLS_SECURE_RENEGOTIATION_SUPPORT != DISABLED)
   #error TLS_SECURE_RENEGOTIATION_SUPPORT parameter is not valid
#endif

//Fallback SCSV support
#ifndef TLS_FALLBACK_SCSV_SUPPORT
   #define TLS_FALLBACK_SCSV_SUPPORT DISABLED
#elif (TLS_FALLBACK_SCSV_SUPPORT != ENABLED && TLS_FALLBACK_SCSV_SUPPORT != DISABLED)
   #error TLS_FALLBACK_SCSV_SUPPORT parameter is not valid
#endif

//ECC callback functions
#ifndef TLS_ECC_CALLBACK_SUPPORT
   #define TLS_ECC_CALLBACK_SUPPORT DISABLED
#elif (TLS_ECC_CALLBACK_SUPPORT != ENABLED && TLS_ECC_CALLBACK_SUPPORT != DISABLED)
   #error TLS_ECC_CALLBACK_SUPPORT parameter is not valid
#endif

//Maximum number of certificates the end entity can load
#ifndef TLS_MAX_CERTIFICATES
   #define TLS_MAX_CERTIFICATES 3
#elif (TLS_MAX_CERTIFICATES < 1)
   #error TLS_MAX_CERTIFICATES parameter is not valid
#endif

//RSA key exchange support
#ifndef TLS_RSA_KE_SUPPORT
   #define TLS_RSA_KE_SUPPORT ENABLED
#elif (TLS_RSA_KE_SUPPORT != ENABLED && TLS_RSA_KE_SUPPORT != DISABLED)
   #error TLS_RSA_KE_SUPPORT parameter is not valid
#endif

//DHE_RSA key exchange support
#ifndef TLS_DHE_RSA_KE_SUPPORT
   #define TLS_DHE_RSA_KE_SUPPORT ENABLED
#elif (TLS_DHE_RSA_KE_SUPPORT != ENABLED && TLS_DHE_RSA_KE_SUPPORT != DISABLED)
   #error TLS_DHE_RSA_KE_SUPPORT parameter is not valid
#endif

//DHE_DSS key exchange support
#ifndef TLS_DHE_DSS_KE_SUPPORT
   #define TLS_DHE_DSS_KE_SUPPORT DISABLED
#elif (TLS_DHE_DSS_KE_SUPPORT != ENABLED && TLS_DHE_DSS_KE_SUPPORT != DISABLED)
   #error TLS_DHE_DSS_KE_SUPPORT parameter is not valid
#endif

//DH_anon key exchange support (insecure)
#ifndef TLS_DH_ANON_KE_SUPPORT
   #define TLS_DH_ANON_KE_SUPPORT DISABLED
#elif (TLS_DH_ANON_KE_SUPPORT != ENABLED && TLS_DH_ANON_KE_SUPPORT != DISABLED)
   #error TLS_DH_ANON_KE_SUPPORT parameter is not valid
#endif

//ECDHE_RSA key exchange support
#ifndef TLS_ECDHE_RSA_KE_SUPPORT
   #define TLS_ECDHE_RSA_KE_SUPPORT ENABLED
#elif (TLS_ECDHE_RSA_KE_SUPPORT != ENABLED && TLS_ECDHE_RSA_KE_SUPPORT != DISABLED)
   #error TLS_ECDHE_RSA_KE_SUPPORT parameter is not valid
#endif

//ECDHE_ECDSA key exchange support
#ifndef TLS_ECDHE_ECDSA_KE_SUPPORT
   #define TLS_ECDHE_ECDSA_KE_SUPPORT ENABLED
#elif (TLS_ECDHE_ECDSA_KE_SUPPORT != ENABLED && TLS_ECDHE_ECDSA_KE_SUPPORT != DISABLED)
   #error TLS_ECDHE_ECDSA_KE_SUPPORT parameter is not valid
#endif

//ECDH_anon key exchange support (insecure)
#ifndef TLS_ECDH_ANON_KE_SUPPORT
   #define TLS_ECDH_ANON_KE_SUPPORT DISABLED
#elif (TLS_ECDH_ANON_KE_SUPPORT != ENABLED && TLS_ECDH_ANON_KE_SUPPORT != DISABLED)
   #error TLS_ECDH_ANON_KE_SUPPORT parameter is not valid
#endif

//PSK key exchange support
#ifndef TLS_PSK_KE_SUPPORT
   #define TLS_PSK_KE_SUPPORT DISABLED
#elif (TLS_PSK_KE_SUPPORT != ENABLED && TLS_PSK_KE_SUPPORT != DISABLED)
   #error TLS_PSK_KE_SUPPORT parameter is not valid
#endif

//RSA_PSK key exchange support
#ifndef TLS_RSA_PSK_KE_SUPPORT
   #define TLS_RSA_PSK_KE_SUPPORT DISABLED
#elif (TLS_RSA_PSK_KE_SUPPORT != ENABLED && TLS_RSA_PSK_KE_SUPPORT != DISABLED)
   #error TLS_RSA_PSK_KE_SUPPORT parameter is not valid
#endif

//DHE_PSK key exchange support
#ifndef TLS_DHE_PSK_KE_SUPPORT
   #define TLS_DHE_PSK_KE_SUPPORT DISABLED
#elif (TLS_DHE_PSK_KE_SUPPORT != ENABLED && TLS_DHE_PSK_KE_SUPPORT != DISABLED)
   #error TLS_DHE_PSK_KE_SUPPORT parameter is not valid
#endif

//ECDHE_PSK key exchange support
#ifndef TLS_ECDHE_PSK_KE_SUPPORT
   #define TLS_ECDHE_PSK_KE_SUPPORT DISABLED
#elif (TLS_ECDHE_PSK_KE_SUPPORT != ENABLED && TLS_ECDHE_PSK_KE_SUPPORT != DISABLED)
   #error TLS_ECDHE_PSK_KE_SUPPORT parameter is not valid
#endif

//RSA signature capability
#ifndef TLS_RSA_SIGN_SUPPORT
   #define TLS_RSA_SIGN_SUPPORT ENABLED
#elif (TLS_RSA_SIGN_SUPPORT != ENABLED && TLS_RSA_SIGN_SUPPORT != DISABLED)
   #error TLS_RSA_SIGN_SUPPORT parameter is not valid
#endif

//RSA-PSS signature capability
#ifndef TLS_RSA_PSS_SIGN_SUPPORT
   #define TLS_RSA_PSS_SIGN_SUPPORT ENABLED
#elif (TLS_RSA_PSS_SIGN_SUPPORT != ENABLED && TLS_RSA_PSS_SIGN_SUPPORT != DISABLED)
   #error TLS_RSA_PSS_SIGN_SUPPORT parameter is not valid
#endif

//DSA signature capability
#ifndef TLS_DSA_SIGN_SUPPORT
   #define TLS_DSA_SIGN_SUPPORT DISABLED
#elif (TLS_DSA_SIGN_SUPPORT != ENABLED && TLS_DSA_SIGN_SUPPORT != DISABLED)
   #error TLS_DSA_SIGN_SUPPORT parameter is not valid
#endif

//ECDSA signature capability
#ifndef TLS_ECDSA_SIGN_SUPPORT
   #define TLS_ECDSA_SIGN_SUPPORT ENABLED
#elif (TLS_ECDSA_SIGN_SUPPORT != ENABLED && TLS_ECDSA_SIGN_SUPPORT != DISABLED)
   #error TLS_ECDSA_SIGN_SUPPORT parameter is not valid
#endif

//EdDSA signature capability
#ifndef TLS_EDDSA_SIGN_SUPPORT
   #define TLS_EDDSA_SIGN_SUPPORT DISABLED
#elif (TLS_EDDSA_SIGN_SUPPORT != ENABLED && TLS_EDDSA_SIGN_SUPPORT != DISABLED)
   #error TLS_EDDSA_SIGN_SUPPORT parameter is not valid
#endif

//NULL cipher support (insecure)
#ifndef TLS_NULL_CIPHER_SUPPORT
   #define TLS_NULL_CIPHER_SUPPORT DISABLED
#elif (TLS_NULL_CIPHER_SUPPORT != ENABLED && TLS_NULL_CIPHER_SUPPORT != DISABLED)
   #error TLS_NULL_CIPHER_SUPPORT parameter is not valid
#endif

//Stream cipher support
#ifndef TLS_STREAM_CIPHER_SUPPORT
   #define TLS_STREAM_CIPHER_SUPPORT DISABLED
#elif (TLS_STREAM_CIPHER_SUPPORT != ENABLED && TLS_STREAM_CIPHER_SUPPORT != DISABLED)
   #error TLS_STREAM_CIPHER_SUPPORT parameter is not valid
#endif

//CBC block cipher support
#ifndef TLS_CBC_CIPHER_SUPPORT
   #define TLS_CBC_CIPHER_SUPPORT ENABLED
#elif (TLS_CBC_CIPHER_SUPPORT != ENABLED && TLS_CBC_CIPHER_SUPPORT != DISABLED)
   #error TLS_CBC_CIPHER_SUPPORT parameter is not valid
#endif

//CCM AEAD support
#ifndef TLS_CCM_CIPHER_SUPPORT
   #define TLS_CCM_CIPHER_SUPPORT DISABLED
#elif (TLS_CCM_CIPHER_SUPPORT != ENABLED && TLS_CCM_CIPHER_SUPPORT != DISABLED)
   #error TLS_CCM_CIPHER_SUPPORT parameter is not valid
#endif

//CCM_8 AEAD support
#ifndef TLS_CCM_8_CIPHER_SUPPORT
   #define TLS_CCM_8_CIPHER_SUPPORT DISABLED
#elif (TLS_CCM_8_CIPHER_SUPPORT != ENABLED && TLS_CCM_8_CIPHER_SUPPORT != DISABLED)
   #error TLS_CCM_8_CIPHER_SUPPORT parameter is not valid
#endif

//GCM AEAD support
#ifndef TLS_GCM_CIPHER_SUPPORT
   #define TLS_GCM_CIPHER_SUPPORT ENABLED
#elif (TLS_GCM_CIPHER_SUPPORT != ENABLED && TLS_GCM_CIPHER_SUPPORT != DISABLED)
   #error TLS_GCM_CIPHER_SUPPORT parameter is not valid
#endif

//ChaCha20Poly1305 AEAD support
#ifndef TLS_CHACHA20_POLY1305_SUPPORT
   #define TLS_CHACHA20_POLY1305_SUPPORT DISABLED
#elif (TLS_CHACHA20_POLY1305_SUPPORT != ENABLED && TLS_CHACHA20_POLY1305_SUPPORT != DISABLED)
   #error TLS_CHACHA20_POLY1305_SUPPORT parameter is not valid
#endif

//RC4 cipher support (insecure)
#ifndef TLS_RC4_SUPPORT
   #define TLS_RC4_SUPPORT DISABLED
#elif (TLS_RC4_SUPPORT != ENABLED && TLS_RC4_SUPPORT != DISABLED)
   #error TLS_RC4_SUPPORT parameter is not valid
#endif

//IDEA cipher support (insecure)
#ifndef TLS_IDEA_SUPPORT
   #define TLS_IDEA_SUPPORT DISABLED
#elif (TLS_IDEA_SUPPORT != ENABLED && TLS_IDEA_SUPPORT != DISABLED)
   #error TLS_IDEA_SUPPORT parameter is not valid
#endif

//DES cipher support (insecure)
#ifndef TLS_DES_SUPPORT
   #define TLS_DES_SUPPORT DISABLED
#elif (TLS_DES_SUPPORT != ENABLED && TLS_DES_SUPPORT != DISABLED)
   #error TLS_DES_SUPPORT parameter is not valid
#endif

//Triple DES cipher support (weak)
#ifndef TLS_3DES_SUPPORT
   #define TLS_3DES_SUPPORT DISABLED
#elif (TLS_3DES_SUPPORT != ENABLED && TLS_3DES_SUPPORT != DISABLED)
   #error TLS_3DES_SUPPORT parameter is not valid
#endif

//AES 128-bit cipher support
#ifndef TLS_AES_128_SUPPORT
   #define TLS_AES_128_SUPPORT ENABLED
#elif (TLS_AES_128_SUPPORT != ENABLED && TLS_AES_128_SUPPORT != DISABLED)
   #error TLS_AES_128_SUPPORT parameter is not valid
#endif

//AES 256-bit cipher support
#ifndef TLS_AES_256_SUPPORT
   #define TLS_AES_256_SUPPORT ENABLED
#elif (TLS_AES_256_SUPPORT != ENABLED && TLS_AES_256_SUPPORT != DISABLED)
   #error TLS_AES_256_SUPPORT parameter is not valid
#endif

//Camellia 128-bit cipher support
#ifndef TLS_CAMELLIA_128_SUPPORT
   #define TLS_CAMELLIA_128_SUPPORT DISABLED
#elif (TLS_CAMELLIA_128_SUPPORT != ENABLED && TLS_CAMELLIA_128_SUPPORT != DISABLED)
   #error TLS_CAMELLIA_128_SUPPORT parameter is not valid
#endif

//Camellia 256-bit cipher support
#ifndef TLS_CAMELLIA_256_SUPPORT
   #define TLS_CAMELLIA_256_SUPPORT DISABLED
#elif (TLS_CAMELLIA_256_SUPPORT != ENABLED && TLS_CAMELLIA_256_SUPPORT != DISABLED)
   #error TLS_CAMELLIA_256_SUPPORT parameter is not valid
#endif

//ARIA 128-bit cipher support
#ifndef TLS_ARIA_128_SUPPORT
   #define TLS_ARIA_128_SUPPORT DISABLED
#elif (TLS_ARIA_128_SUPPORT != ENABLED && TLS_ARIA_128_SUPPORT != DISABLED)
   #error TLS_ARIA_128_SUPPORT parameter is not valid
#endif

//ARIA 256-bit cipher support
#ifndef TLS_ARIA_256_SUPPORT
   #define TLS_ARIA_256_SUPPORT DISABLED
#elif (TLS_ARIA_256_SUPPORT != ENABLED && TLS_ARIA_256_SUPPORT != DISABLED)
   #error TLS_ARIA_256_SUPPORT parameter is not valid
#endif

//SEED cipher support
#ifndef TLS_SEED_SUPPORT
   #define TLS_SEED_SUPPORT DISABLED
#elif (TLS_SEED_SUPPORT != ENABLED && TLS_SEED_SUPPORT != DISABLED)
   #error TLS_SEED_SUPPORT parameter is not valid
#endif

//MD5 hash support (insecure)
#ifndef TLS_MD5_SUPPORT
   #define TLS_MD5_SUPPORT DISABLED
#elif (TLS_MD5_SUPPORT != ENABLED && TLS_MD5_SUPPORT != DISABLED)
   #error TLS_MD5_SUPPORT parameter is not valid
#endif

//SHA-1 hash support (weak)
#ifndef TLS_SHA1_SUPPORT
   #define TLS_SHA1_SUPPORT ENABLED
#elif (TLS_SHA1_SUPPORT != ENABLED && TLS_SHA1_SUPPORT != DISABLED)
   #error TLS_SHA1_SUPPORT parameter is not valid
#endif

//SHA-224 hash support (weak)
#ifndef TLS_SHA224_SUPPORT
   #define TLS_SHA224_SUPPORT DISABLED
#elif (TLS_SHA224_SUPPORT != ENABLED && TLS_SHA224_SUPPORT != DISABLED)
   #error TLS_SHA224_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef TLS_SHA256_SUPPORT
   #define TLS_SHA256_SUPPORT ENABLED
#elif (TLS_SHA256_SUPPORT != ENABLED && TLS_SHA256_SUPPORT != DISABLED)
   #error TLS_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef TLS_SHA384_SUPPORT
   #define TLS_SHA384_SUPPORT ENABLED
#elif (TLS_SHA384_SUPPORT != ENABLED && TLS_SHA384_SUPPORT != DISABLED)
   #error TLS_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef TLS_SHA512_SUPPORT
   #define TLS_SHA512_SUPPORT DISABLED
#elif (TLS_SHA512_SUPPORT != ENABLED && TLS_SHA512_SUPPORT != DISABLED)
   #error TLS_SHA512_SUPPORT parameter is not valid
#endif

//FFDHE key exchange mechanism
#ifndef TLS_FFDHE_SUPPORT
   #define TLS_FFDHE_SUPPORT DISABLED
#elif (TLS_FFDHE_SUPPORT != ENABLED && TLS_FFDHE_SUPPORT != DISABLED)
   #error TLS_FFDHE_SUPPORT parameter is not valid
#endif

//ffdhe2048 group support
#ifndef TLS_FFDHE2048_SUPPORT
   #define TLS_FFDHE2048_SUPPORT ENABLED
#elif (TLS_FFDHE2048_SUPPORT != ENABLED && TLS_FFDHE2048_SUPPORT != DISABLED)
   #error TLS_FFDHE2048_SUPPORT parameter is not valid
#endif

//ffdhe3072 group support
#ifndef TLS_FFDHE3072_SUPPORT
   #define TLS_FFDHE3072_SUPPORT DISABLED
#elif (TLS_FFDHE3072_SUPPORT != ENABLED && TLS_FFDHE3072_SUPPORT != DISABLED)
   #error TLS_FFDHE3072_SUPPORT parameter is not valid
#endif

//ffdhe4096 group support
#ifndef TLS_FFDHE4096_SUPPORT
   #define TLS_FFDHE4096_SUPPORT DISABLED
#elif (TLS_FFDHE4096_SUPPORT != ENABLED && TLS_FFDHE4096_SUPPORT != DISABLED)
   #error TLS_FFDHE4096_SUPPORT parameter is not valid
#endif

//secp160k1 elliptic curve support (weak)
#ifndef TLS_SECP160K1_SUPPORT
   #define TLS_SECP160K1_SUPPORT DISABLED
#elif (TLS_SECP160K1_SUPPORT != ENABLED && TLS_SECP160K1_SUPPORT != DISABLED)
   #error TLS_SECP160K1_SUPPORT parameter is not valid
#endif

//secp160r1 elliptic curve support (weak)
#ifndef TLS_SECP160R1_SUPPORT
   #define TLS_SECP160R1_SUPPORT DISABLED
#elif (TLS_SECP160R1_SUPPORT != ENABLED && TLS_SECP160R1_SUPPORT != DISABLED)
   #error TLS_SECP160R1_SUPPORT parameter is not valid
#endif

//secp160r2 elliptic curve support (weak)
#ifndef TLS_SECP160R2_SUPPORT
   #define TLS_SECP160R2_SUPPORT DISABLED
#elif (TLS_SECP160R2_SUPPORT != ENABLED && TLS_SECP160R2_SUPPORT != DISABLED)
   #error TLS_SECP160R2_SUPPORT parameter is not valid
#endif

//secp192k1 elliptic curve support
#ifndef TLS_SECP192K1_SUPPORT
   #define TLS_SECP192K1_SUPPORT DISABLED
#elif (TLS_SECP192K1_SUPPORT != ENABLED && TLS_SECP192K1_SUPPORT != DISABLED)
   #error TLS_SECP192K1_SUPPORT parameter is not valid
#endif

//secp192r1 elliptic curve support (NIST P-192)
#ifndef TLS_SECP192R1_SUPPORT
   #define TLS_SECP192R1_SUPPORT DISABLED
#elif (TLS_SECP192R1_SUPPORT != ENABLED && TLS_SECP192R1_SUPPORT != DISABLED)
   #error TLS_SECP192R1_SUPPORT parameter is not valid
#endif

//secp224k1 elliptic curve support
#ifndef TLS_SECP224K1_SUPPORT
   #define TLS_SECP224K1_SUPPORT DISABLED
#elif (TLS_SECP224K1_SUPPORT != ENABLED && TLS_SECP224K1_SUPPORT != DISABLED)
   #error TLS_SECP224K1_SUPPORT parameter is not valid
#endif

//secp224r1 elliptic curve support (NIST P-224)
#ifndef TLS_SECP224R1_SUPPORT
   #define TLS_SECP224R1_SUPPORT DISABLED
#elif (TLS_SECP224R1_SUPPORT != ENABLED && TLS_SECP224R1_SUPPORT != DISABLED)
   #error TLS_SECP224R1_SUPPORT parameter is not valid
#endif

//secp256k1 elliptic curve support
#ifndef TLS_SECP256K1_SUPPORT
   #define TLS_SECP256K1_SUPPORT DISABLED
#elif (TLS_SECP256K1_SUPPORT != ENABLED && TLS_SECP256K1_SUPPORT != DISABLED)
   #error TLS_SECP256K1_SUPPORT parameter is not valid
#endif

//secp256r1 elliptic curve support (NIST P-256)
#ifndef TLS_SECP256R1_SUPPORT
   #define TLS_SECP256R1_SUPPORT ENABLED
#elif (TLS_SECP256R1_SUPPORT != ENABLED && TLS_SECP256R1_SUPPORT != DISABLED)
   #error TLS_SECP256R1_SUPPORT parameter is not valid
#endif

//secp384r1 elliptic curve support (NIST P-384)
#ifndef TLS_SECP384R1_SUPPORT
   #define TLS_SECP384R1_SUPPORT ENABLED
#elif (TLS_SECP384R1_SUPPORT != ENABLED && TLS_SECP384R1_SUPPORT != DISABLED)
   #error TLS_SECP384R1_SUPPORT parameter is not valid
#endif

//secp521r1 elliptic curve support (NIST P-521)
#ifndef TLS_SECP521R1_SUPPORT
   #define TLS_SECP521R1_SUPPORT DISABLED
#elif (TLS_SECP521R1_SUPPORT != ENABLED && TLS_SECP521R1_SUPPORT != DISABLED)
   #error TLS_SECP521R1_SUPPORT parameter is not valid
#endif

//brainpoolP256r1 elliptic curve support
#ifndef TLS_BRAINPOOLP256R1_SUPPORT
   #define TLS_BRAINPOOLP256R1_SUPPORT DISABLED
#elif (TLS_BRAINPOOLP256R1_SUPPORT != ENABLED && TLS_BRAINPOOLP256R1_SUPPORT != DISABLED)
   #error TLS_BRAINPOOLP256R1_SUPPORT parameter is not valid
#endif

//brainpoolP384r1 elliptic curve support
#ifndef TLS_BRAINPOOLP384R1_SUPPORT
   #define TLS_BRAINPOOLP384R1_SUPPORT DISABLED
#elif (TLS_BRAINPOOLP384R1_SUPPORT != ENABLED && TLS_BRAINPOOLP384R1_SUPPORT != DISABLED)
   #error TLS_BRAINPOOLP384R1_SUPPORT parameter is not valid
#endif

//brainpoolP512r1 elliptic curve support
#ifndef TLS_BRAINPOOLP512R1_SUPPORT
   #define TLS_BRAINPOOLP512R1_SUPPORT DISABLED
#elif (TLS_BRAINPOOLP512R1_SUPPORT != ENABLED && TLS_BRAINPOOLP512R1_SUPPORT != DISABLED)
   #error TLS_BRAINPOOLP512R1_SUPPORT parameter is not valid
#endif

//Curve25519 elliptic curve support
#ifndef TLS_X25519_SUPPORT
   #define TLS_X25519_SUPPORT DISABLED
#elif (TLS_X25519_SUPPORT != ENABLED && TLS_X25519_SUPPORT != DISABLED)
   #error TLS_X25519_SUPPORT parameter is not valid
#endif

//Curve448 elliptic curve support
#ifndef TLS_X448_SUPPORT
   #define TLS_X448_SUPPORT DISABLED
#elif (TLS_X448_SUPPORT != ENABLED && TLS_X448_SUPPORT != DISABLED)
   #error TLS_X448_SUPPORT parameter is not valid
#endif

//Ed25519 elliptic curve support
#ifndef TLS_ED25519_SUPPORT
   #define TLS_ED25519_SUPPORT ENABLED
#elif (TLS_ED25519_SUPPORT != ENABLED && TLS_ED25519_SUPPORT != DISABLED)
   #error TLS_ED25519_SUPPORT parameter is not valid
#endif

//Ed448 elliptic curve support
#ifndef TLS_ED448_SUPPORT
   #define TLS_ED448_SUPPORT DISABLED
#elif (TLS_ED448_SUPPORT != ENABLED && TLS_ED448_SUPPORT != DISABLED)
   #error TLS_ED448_SUPPORT parameter is not valid
#endif

//Certificate key usage verification
#ifndef TLS_CERT_KEY_USAGE_SUPPORT
   #define TLS_CERT_KEY_USAGE_SUPPORT ENABLED
#elif (TLS_CERT_KEY_USAGE_SUPPORT != ENABLED && TLS_CERT_KEY_USAGE_SUPPORT != DISABLED)
   #error TLS_CERT_KEY_USAGE_SUPPORT parameter is not valid
#endif

//Key logging (for debugging purpose only)
#ifndef TLS_KEY_LOG_SUPPORT
   #define TLS_KEY_LOG_SUPPORT DISABLED
#elif (TLS_KEY_LOG_SUPPORT != ENABLED && TLS_KEY_LOG_SUPPORT != DISABLED)
   #error TLS_KEY_LOG_SUPPORT parameter is not valid
#endif

//Maximum acceptable length for server names
#ifndef TLS_MAX_SERVER_NAME_LEN
   #define TLS_MAX_SERVER_NAME_LEN 255
#elif (TLS_MAX_SERVER_NAME_LEN < 1)
   #error TLS_MAX_SERVER_NAME_LEN parameter is not valid
#endif

//Minimum acceptable size for Diffie-Hellman prime modulus
#ifndef TLS_MIN_DH_MODULUS_SIZE
   #define TLS_MIN_DH_MODULUS_SIZE 1024
#elif (TLS_MIN_DH_MODULUS_SIZE < 512)
   #error TLS_MIN_DH_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for Diffie-Hellman prime modulus
#ifndef TLS_MAX_DH_MODULUS_SIZE
   #define TLS_MAX_DH_MODULUS_SIZE 2048
#elif (TLS_MAX_DH_MODULUS_SIZE < TLS_MIN_DH_MODULUS_SIZE)
   #error TLS_MAX_DH_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for RSA modulus
#ifndef TLS_MIN_RSA_MODULUS_SIZE
   #define TLS_MIN_RSA_MODULUS_SIZE 1024
#elif (TLS_MIN_RSA_MODULUS_SIZE < 512)
   #error TLS_MIN_RSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for RSA modulus
#ifndef TLS_MAX_RSA_MODULUS_SIZE
   #define TLS_MAX_RSA_MODULUS_SIZE 4096
#elif (TLS_MAX_RSA_MODULUS_SIZE < TLS_MIN_RSA_MODULUS_SIZE)
   #error TLS_MAX_RSA_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for DSA prime modulus
#ifndef TLS_MIN_DSA_MODULUS_SIZE
   #define TLS_MIN_DSA_MODULUS_SIZE 1024
#elif (TLS_MIN_DSA_MODULUS_SIZE < 512)
   #error TLS_MIN_DSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for DSA prime modulus
#ifndef TLS_MAX_DSA_MODULUS_SIZE
   #define TLS_MAX_DSA_MODULUS_SIZE 4096
#elif (TLS_MAX_DSA_MODULUS_SIZE < TLS_MIN_DSA_MODULUS_SIZE)
   #error TLS_MAX_DSA_MODULUS_SIZE parameter is not valid
#endif

//Master secret size
#ifndef TLS_MASTER_SECRET_SIZE
   #define TLS_MASTER_SECRET_SIZE 48
#elif (TLS_MASTER_SECRET_SIZE < 48)
   #error TLS_MASTER_SECRET_SIZE parameter is not valid
#endif

//Maximum size for premaster secret
#ifndef TLS_PREMASTER_SECRET_SIZE
   #define TLS_PREMASTER_SECRET_SIZE (TLS_MAX_DH_MODULUS_SIZE / 8)
#elif (TLS_PREMASTER_SECRET_SIZE < 48)
   #error TLS_PREMASTER_SECRET_SIZE parameter is not valid
#endif

//Maximum number of consecutive warning alerts
#ifndef TLS_MAX_WARNING_ALERTS
   #define TLS_MAX_WARNING_ALERTS 5
#elif (TLS_MAX_WARNING_ALERTS < 0)
   #error TLS_MAX_WARNING_ALERTS parameter is not valid
#endif

//Maximum number of consecutive empty records
#ifndef TLS_MAX_EMPTY_RECORDS
   #define TLS_MAX_EMPTY_RECORDS 10
#elif (TLS_MAX_EMPTY_RECORDS < 0)
   #error TLS_MAX_EMPTY_RECORDS parameter is not valid
#endif

//Maximum number of consecutive ChangeCipherSpec messages
#ifndef TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES
   #define TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES 5
#elif (TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES < 0)
   #error TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES parameter is not valid
#endif

//Maximum number of consecutive KeyUpdate messages
#ifndef TLS_MAX_KEY_UPDATE_MESSAGES
   #define TLS_MAX_KEY_UPDATE_MESSAGES 5
#elif (TLS_MAX_KEY_UPDATE_MESSAGES < 0)
   #error TLS_MAX_KEY_UPDATE_MESSAGES parameter is not valid
#endif

//Application specific context (TLS context)
#ifndef TLS_PRIVATE_CONTEXT
   #define TLS_PRIVATE_CONTEXT
#endif

//Application specific context (encryption engine)
#ifndef TLS_PRIVATE_ENCRYPTION_ENGINE
   #define TLS_PRIVATE_ENCRYPTION_ENGINE
#endif

//Allocate memory block
#ifndef tlsAllocMem
   #define tlsAllocMem(size) osAllocMem(size)
#endif

//Deallocate memory block
#ifndef tlsFreeMem
   #define tlsFreeMem(p) osFreeMem(p)
#endif

//Support for Diffie-Hellman?
#if ((TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2) && \
   (TLS_DH_ANON_KE_SUPPORT == ENABLED || TLS_DHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_DHE_DSS_KE_SUPPORT == ENABLED || TLS_DHE_PSK_KE_SUPPORT == ENABLED))
   #define TLS_DH_SUPPORT ENABLED
#elif ((TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3) && \
   (TLS13_DHE_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED))
   #define TLS_DH_SUPPORT ENABLED
#else
   #define TLS_DH_SUPPORT DISABLED
#endif

//Support for ECDH?
#if ((TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2) && \
   (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED))
   #define TLS_ECDH_SUPPORT ENABLED
#elif ((TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3) && \
   (TLS13_ECDHE_KE_SUPPORT == ENABLED || TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED))
   #define TLS_ECDH_SUPPORT ENABLED
#else
   #define TLS_ECDH_SUPPORT DISABLED
#endif

//Support for RSA?
#if ((TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2) && \
   (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED || \
   TLS_RSA_KE_SUPPORT == ENABLED || TLS_DHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED))
   #define TLS_RSA_SUPPORT ENABLED
#elif ((TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3) && \
   (TLS_RSA_SIGN_SUPPORT == ENABLED || TLS_RSA_PSS_SIGN_SUPPORT == ENABLED))
   #define TLS_RSA_SUPPORT ENABLED
#else
   #define TLS_RSA_SUPPORT DISABLED
#endif

//Support for PSK?
#if ((TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2) && \
   (TLS_PSK_KE_SUPPORT == ENABLED || TLS_RSA_PSK_KE_SUPPORT == ENABLED || \
   TLS_DHE_PSK_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED))
   #define TLS_PSK_SUPPORT ENABLED
#elif ((TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3) && \
   (TLS13_PSK_KE_SUPPORT == ENABLED || TLS13_PSK_DHE_KE_SUPPORT == ENABLED || \
   TLS13_PSK_ECDHE_KE_SUPPORT == ENABLED))
   #define TLS_PSK_SUPPORT ENABLED
#else
   #define TLS_PSK_SUPPORT DISABLED
#endif

//Maximum size for HKDF digests
#if (TLS_SHA384_SUPPORT == ENABLED)
   #define TLS_MAX_HKDF_DIGEST_SIZE 48
#else
   #define TLS_MAX_HKDF_DIGEST_SIZE 32
#endif

//Bind TLS to a particular socket
#define tlsSetSocket(context, socket) tlsSetSocketCallbacks(context, \
   (TlsSocketSendCallback) socketSend, (TlsSocketReceiveCallback) socketReceive, \
   (TlsSocketHandle) socket)

//Minimum plaintext record length
#define TLS_MIN_RECORD_LENGTH 512
//Maximum plaintext record length
#define TLS_MAX_RECORD_LENGTH 16384
//Data overhead caused by record encryption
#define TLS_MAX_RECORD_OVERHEAD 512
//Size of client and server random values
#define TLS_RANDOM_SIZE 32

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief TLS transport protocols
 **/

typedef enum
{
   TLS_TRANSPORT_PROTOCOL_STREAM   = 0,
   TLS_TRANSPORT_PROTOCOL_DATAGRAM = 1
} TlsTransportProtocol;


/**
 * @brief TLS connection end
 **/

typedef enum
{
   TLS_CONNECTION_END_CLIENT = 0,
   TLS_CONNECTION_END_SERVER = 1
} TlsConnectionEnd;


/**
 * @brief Client authentication mode
 **/

typedef enum
{
   TLS_CLIENT_AUTH_NONE     = 0,
   TLS_CLIENT_AUTH_OPTIONAL = 1,
   TLS_CLIENT_AUTH_REQUIRED = 2
} TlsClientAuthMode;


/**
 * @brief Early data status
 **/

typedef enum
{
   TLS_EARLY_DATA_REJECTED = 0,
   TLS_EARLY_DATA_ACCEPTED = 1
} TlsEarlyDataStatus;


/**
 * @brief Flags used by read and write functions
 **/

typedef enum
{
   TLS_FLAG_PEEK       = 0x0200,
   TLS_FLAG_WAIT_ALL   = 0x0800,
   TLS_FLAG_BREAK_CHAR = 0x1000,
   TLS_FLAG_BREAK_CRLF = 0x100A,
   TLS_FLAG_WAIT_ACK   = 0x2000,
   TLS_FLAG_NO_DELAY   = 0x4000,
   TLS_FLAG_DELAY      = 0x8000
} TlsFlags;


//The TLS_FLAG_BREAK macro causes the read function to stop reading
//data whenever the specified break character is encountered
#define TLS_FLAG_BREAK(c) (TLS_FLAG_BREAK_CHAR | LSB(c))


/**
 * @brief Content type
 **/

typedef enum
{
   TLS_TYPE_NONE               = 0,
   TLS_TYPE_CHANGE_CIPHER_SPEC = 20,
   TLS_TYPE_ALERT              = 21,
   TLS_TYPE_HANDSHAKE          = 22,
   TLS_TYPE_APPLICATION_DATA   = 23,
   TLS_TYPE_HEARTBEAT          = 24,
   TLS_TYPE_TLS12_CID          = 25,
   TLS_TYPE_ACK                = 26
} TlsContentType;


/**
 * @brief Handshake message type
 **/

typedef enum
{
   TLS_TYPE_HELLO_REQUEST          = 0,
   TLS_TYPE_CLIENT_HELLO           = 1,
   TLS_TYPE_SERVER_HELLO           = 2,
   TLS_TYPE_HELLO_VERIFY_REQUEST   = 3,
   TLS_TYPE_NEW_SESSION_TICKET     = 4,
   TLS_TYPE_END_OF_EARLY_DATA      = 5,
   TLS_TYPE_HELLO_RETRY_REQUEST    = 6,
   TLS_TYPE_ENCRYPTED_EXTENSIONS   = 8,
   TLS_TYPE_REQUEST_CONNECTION_ID  = 9,
   TLS_TYPE_NEW_CONNECTION_ID      = 10,
   TLS_TYPE_CERTIFICATE            = 11,
   TLS_TYPE_SERVER_KEY_EXCHANGE    = 12,
   TLS_TYPE_CERTIFICATE_REQUEST    = 13,
   TLS_TYPE_SERVER_HELLO_DONE      = 14,
   TLS_TYPE_CERTIFICATE_VERIFY     = 15,
   TLS_TYPE_CLIENT_KEY_EXCHANGE    = 16,
   TLS_TYPE_FINISHED               = 20,
   TLS_TYPE_CERTIFICATE_URL        = 21,
   TLS_TYPE_CERTIFICATE_STATUS     = 22,
   TLS_TYPE_SUPPLEMENTAL_DATA      = 23,
   TLS_TYPE_KEY_UPDATE             = 24,
   TLS_TYPE_COMPRESSED_CERTIFICATE = 25,
   TLS_TYPE_EKT_KEY                = 26,
   TLS_TYPE_MESSAGE_HASH           = 254
} TlsMessageType;


/**
 * @brief Alert level
 **/

typedef enum
{
   TLS_ALERT_LEVEL_WARNING = 1,
   TLS_ALERT_LEVEL_FATAL   = 2,
} TlsAlertLevel;


/**
 * @brief Alert description
 **/

typedef enum
{
   TLS_ALERT_CLOSE_NOTIFY                    = 0,
   TLS_ALERT_UNEXPECTED_MESSAGE              = 10,
   TLS_ALERT_BAD_RECORD_MAC                  = 20,
   TLS_ALERT_DECRYPTION_FAILED               = 21,
   TLS_ALERT_RECORD_OVERFLOW                 = 22,
   TLS_ALERT_DECOMPRESSION_FAILURE           = 30,
   TLS_ALERT_HANDSHAKE_FAILURE               = 40,
   TLS_ALERT_NO_CERTIFICATE                  = 41,
   TLS_ALERT_BAD_CERTIFICATE                 = 42,
   TLS_ALERT_UNSUPPORTED_CERTIFICATE         = 43,
   TLS_ALERT_CERTIFICATE_REVOKED             = 44,
   TLS_ALERT_CERTIFICATE_EXPIRED             = 45,
   TLS_ALERT_CERTIFICATE_UNKNOWN             = 46,
   TLS_ALERT_ILLEGAL_PARAMETER               = 47,
   TLS_ALERT_UNKNOWN_CA                      = 48,
   TLS_ALERT_ACCESS_DENIED                   = 49,
   TLS_ALERT_DECODE_ERROR                    = 50,
   TLS_ALERT_DECRYPT_ERROR                   = 51,
   TLS_ALERT_TOO_MANY_CIDS_REQUESTED         = 52,
   TLS_ALERT_EXPORT_RESTRICTION              = 60,
   TLS_ALERT_PROTOCOL_VERSION                = 70,
   TLS_ALERT_INSUFFICIENT_SECURITY           = 71,
   TLS_ALERT_INTERNAL_ERROR                  = 80,
   TLS_ALERT_INAPPROPRIATE_FALLBACK          = 86,
   TLS_ALERT_USER_CANCELED                   = 90,
   TLS_ALERT_NO_RENEGOTIATION                = 100,
   TLS_ALERT_MISSING_EXTENSION               = 109,
   TLS_ALERT_UNSUPPORTED_EXTENSION           = 110,
   TLS_ALERT_CERTIFICATE_UNOBTAINABLE        = 111,
   TLS_ALERT_UNRECOGNIZED_NAME               = 112,
   TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
   TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE      = 114,
   TLS_ALERT_UNKNOWN_PSK_IDENTITY            = 115,
   TLS_ALERT_CERTIFICATE_REQUIRED            = 116,
   TLS_ALERT_NO_APPLICATION_PROTOCOL         = 120
} TlsAlertDescription;


/**
 * @brief Compression methods
 **/

typedef enum
{
   TLS_COMPRESSION_METHOD_NULL    = 0,
   TLS_COMPRESSION_METHOD_DEFLATE = 1
} TlsCompressMethod;


/**
 * @brief Key exchange methods
 **/

typedef enum
{
   TLS_KEY_EXCH_NONE        = 0,
   TLS_KEY_EXCH_RSA         = 1,
   TLS_KEY_EXCH_DH_RSA      = 2,
   TLS_KEY_EXCH_DHE_RSA     = 3,
   TLS_KEY_EXCH_DH_DSS      = 4,
   TLS_KEY_EXCH_DHE_DSS     = 5,
   TLS_KEY_EXCH_DH_ANON     = 6,
   TLS_KEY_EXCH_ECDH_RSA    = 7,
   TLS_KEY_EXCH_ECDHE_RSA   = 8,
   TLS_KEY_EXCH_ECDH_ECDSA  = 9,
   TLS_KEY_EXCH_ECDHE_ECDSA = 10,
   TLS_KEY_EXCH_ECDH_ANON   = 11,
   TLS_KEY_EXCH_PSK         = 12,
   TLS_KEY_EXCH_RSA_PSK     = 13,
   TLS_KEY_EXCH_DHE_PSK     = 14,
   TLS_KEY_EXCH_ECDHE_PSK   = 15,
   TLS_KEY_EXCH_SRP_SHA     = 16,
   TLS_KEY_EXCH_SRP_SHA_RSA = 17,
   TLS_KEY_EXCH_SRP_SHA_DSS = 18,
   TLS13_KEY_EXCH_DHE       = 19,
   TLS13_KEY_EXCH_ECDHE     = 20,
   TLS13_KEY_EXCH_PSK       = 21,
   TLS13_KEY_EXCH_PSK_DHE   = 22,
   TLS13_KEY_EXCH_PSK_ECDHE = 23
} TlsKeyExchMethod;


/**
 * @brief Certificate formats
 **/

typedef enum
{
   TLS_CERT_FORMAT_X509           = 0,
   TLS_CERT_FORMAT_OPENPGP        = 1,
   TLS_CERT_FORMAT_RAW_PUBLIC_KEY = 2,
   TLS_CERT_FORMAT_1609DOT2       = 3
} TlsCertificateFormat;


/**
 * @brief Certificate types
 **/

typedef enum
{
   TLS_CERT_NONE             = 0,
   TLS_CERT_RSA_SIGN         = 1,
   TLS_CERT_DSS_SIGN         = 2,
   TLS_CERT_RSA_FIXED_DH     = 3,
   TLS_CERT_DSS_FIXED_DH     = 4,
   TLS_CERT_RSA_EPHEMERAL_DH = 5,
   TLS_CERT_DSS_EPHEMERAL_DH = 6,
   TLS_CERT_FORTEZZA_DMS     = 20,
   TLS_CERT_ECDSA_SIGN       = 64,
   TLS_CERT_RSA_FIXED_ECDH   = 65,
   TLS_CERT_ECDSA_FIXED_ECDH = 66,
   TLS_CERT_GOST_SIGN256     = 67,
   TLS_CERT_GOST_SIGN512     = 68,
   TLS_CERT_RSA_PSS_SIGN     = 256, //For internal use only
   TLS_CERT_ED25519_SIGN     = 257, //For internal use only
   TLS_CERT_ED448_SIGN       = 258  //For internal use only
} TlsCertificateType;


/**
 * @brief Hash algorithms
 **/

typedef enum
{
   TLS_HASH_ALGO_NONE      = 0,
   TLS_HASH_ALGO_MD5       = 1,
   TLS_HASH_ALGO_SHA1      = 2,
   TLS_HASH_ALGO_SHA224    = 3,
   TLS_HASH_ALGO_SHA256    = 4,
   TLS_HASH_ALGO_SHA384    = 5,
   TLS_HASH_ALGO_SHA512    = 6,
   TLS_HASH_ALGO_INTRINSIC = 8
} TlsHashAlgo;


/**
 * @brief Signature algorithms
 **/

typedef enum
{
   TLS_SIGN_ALGO_ANONYMOUS                          = 0,
   TLS_SIGN_ALGO_RSA                                = 1,
   TLS_SIGN_ALGO_DSA                                = 2,
   TLS_SIGN_ALGO_ECDSA                              = 3,
   TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA256                = 4,
   TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA384                = 5,
   TLS_SIGN_ALGO_RSA_PSS_RSAE_SHA512                = 6,
   TLS_SIGN_ALGO_ED25519                            = 7,
   TLS_SIGN_ALGO_ED448                              = 8,
   TLS_SIGN_ALGO_RSA_PSS_PSS_SHA256                 = 9,
   TLS_SIGN_ALGO_RSA_PSS_PSS_SHA384                 = 10,
   TLS_SIGN_ALGO_RSA_PSS_PSS_SHA512                 = 11,
   TLS_SIGN_ALGO_ECDSA_BRAINPOOLP256R1_TLS13_SHA256 = 26,
   TLS_SIGN_ALGO_ECDSA_BRAINPOOLP384R1_TLS13_SHA384 = 27,
   TLS_SIGN_ALGO_ECDSA_BRAINPOOLP512R1_TLS13_SHA512 = 28,
   TLS_SIGN_ALGO_GOSTR34102012_256                  = 64,
   TLS_SIGN_ALGO_GOSTR34102012_512                  = 65
} TlsSignatureAlgo;


/**
 * @brief TLS extension types
 **/

typedef enum
{
   TLS_EXT_SERVER_NAME               = 0,
   TLS_EXT_MAX_FRAGMENT_LENGTH       = 1,
   TLS_EXT_CLIENT_CERTIFICATE_URL    = 2,
   TLS_EXT_TRUSTED_CA_KEYS           = 3,
   TLS_EXT_TRUNCATED_HMAC            = 4,
   TLS_EXT_STATUS_REQUEST            = 5,
   TLS_EXT_USER_MAPPING              = 6,
   TLS_EXT_CLIENT_AUTHZ              = 7,
   TLS_EXT_SERVER_AUTHZ              = 8,
   TLS_EXT_CERT_TYPE                 = 9,
   TLS_EXT_SUPPORTED_GROUPS          = 10,
   TLS_EXT_EC_POINT_FORMATS          = 11,
   TLS_EXT_SRP                       = 12,
   TLS_EXT_SIGNATURE_ALGORITHMS      = 13,
   TLS_EXT_USE_SRTP                  = 14,
   TLS_EXT_HEARTBEAT                 = 15,
   TLS_EXT_ALPN                      = 16,
   TLS_EXT_STATUS_REQUEST_V2         = 17,
   TLS_EXT_SIGNED_CERT_TIMESTAMP     = 18,
   TLS_EXT_CLIENT_CERT_TYPE          = 19,
   TLS_EXT_SERVER_CERT_TYPE          = 20,
   TLS_EXT_PADDING                   = 21,
   TLS_EXT_ENCRYPT_THEN_MAC          = 22,
   TLS_EXT_EXTENDED_MASTER_SECRET    = 23,
   TLS_EXT_TOKEN_BINDING             = 24,
   TLS_EXT_CACHED_INFO               = 25,
   TLS_EXT_COMPRESS_CERTIFICATE      = 27,
   TLS_EXT_RECORD_SIZE_LIMIT         = 28,
   TLS_EXT_PWD_PROTECT               = 29,
   TLS_EXT_PWD_CLEAR                 = 30,
   TLS_EXT_PASSWORD_SALT             = 31,
   TLS_EXT_TICKET_PINNING            = 32,
   TLS_EXT_TLS_CERT_WITH_EXTERN_PSK  = 33,
   TLS_EXT_SESSION_TICKET            = 35,
   TLS_EXT_SUPPORTED_EKT_CIPHERS     = 39,
   TLS_EXT_PRE_SHARED_KEY            = 41,
   TLS_EXT_EARLY_DATA                = 42,
   TLS_EXT_SUPPORTED_VERSIONS        = 43,
   TLS_EXT_COOKIE                    = 44,
   TLS_EXT_PSK_KEY_EXCHANGE_MODES    = 45,
   TLS_EXT_CERTIFICATE_AUTHORITIES   = 47,
   TLS_EXT_OID_FILTERS               = 48,
   TLS_EXT_POST_HANDSHAKE_AUTH       = 49,
   TLS_EXT_SIGNATURE_ALGORITHMS_CERT = 50,
   TLS_EXT_KEY_SHARE                 = 51,
   TLS_EXT_TRANSPARENCY_INFO         = 52,
   TLS_EXT_CONNECTION_ID             = 54,
   TLS_EXT_EXTERNAL_ID_HASH          = 55,
   TLS_EXT_EXTERNAL_SESSION_ID       = 56,
   TLS_EXT_QUIC_TRANSPORT_PARAMETERS = 57,
   TLS_EXT_DNSSEC_CHAIN              = 59,
   TLS_EXT_RENEGOTIATION_INFO        = 65281
} TlsExtensionType;


/**
 * @brief Name type
 **/

typedef enum
{
   TLS_NAME_TYPE_HOSTNAME = 0
} TlsNameType;


/**
 * @brief Maximum fragment length
 **/

typedef enum
{
   TLS_MAX_FRAGMENT_LENGTH_512  = 1,
   TLS_MAX_FRAGMENT_LENGTH_1024 = 2,
   TLS_MAX_FRAGMENT_LENGTH_2048 = 3,
   TLS_MAX_FRAGMENT_LENGTH_4096 = 4
} TlsMaxFragmentLength;


/**
 * @brief Named groups
 **/

typedef enum
{
   TLS_GROUP_NONE                  = 0,
   TLS_GROUP_SECT163K1             = 1,     //RFC 4492
   TLS_GROUP_SECT163R1             = 2,     //RFC 4492
   TLS_GROUP_SECT163R2             = 3,     //RFC 4492
   TLS_GROUP_SECT193R1             = 4,     //RFC 4492
   TLS_GROUP_SECT193R2             = 5,     //RFC 4492
   TLS_GROUP_SECT233K1             = 6,     //RFC 4492
   TLS_GROUP_SECT233R1             = 7,     //RFC 4492
   TLS_GROUP_SECT239K1             = 8,     //RFC 4492
   TLS_GROUP_SECT283K1             = 9,     //RFC 4492
   TLS_GROUP_SECT283R1             = 10,    //RFC 4492
   TLS_GROUP_SECT409K1             = 11,    //RFC 4492
   TLS_GROUP_SECT409R1             = 12,    //RFC 4492
   TLS_GROUP_SECT571K1             = 13,    //RFC 4492
   TLS_GROUP_SECT571R1             = 14,    //RFC 4492
   TLS_GROUP_SECP160K1             = 15,    //RFC 4492
   TLS_GROUP_SECP160R1             = 16,    //RFC 4492
   TLS_GROUP_SECP160R2             = 17,    //RFC 4492
   TLS_GROUP_SECP192K1             = 18,    //RFC 4492
   TLS_GROUP_SECP192R1             = 19,    //RFC 4492
   TLS_GROUP_SECP224K1             = 20,    //RFC 4492
   TLS_GROUP_SECP224R1             = 21,    //RFC 4492
   TLS_GROUP_SECP256K1             = 22,    //RFC 4492
   TLS_GROUP_SECP256R1             = 23,    //RFC 4492
   TLS_GROUP_SECP384R1             = 24,    //RFC 4492
   TLS_GROUP_SECP521R1             = 25,    //RFC 4492
   TLS_GROUP_BRAINPOOLP256R1       = 26,    //RFC 7027
   TLS_GROUP_BRAINPOOLP384R1       = 27,    //RFC 7027
   TLS_GROUP_BRAINPOOLP512R1       = 28,    //RFC 7027
   TLS_GROUP_ECDH_X25519           = 29,    //RFC 8422
   TLS_GROUP_ECDH_X448             = 30,    //RFC 8422
   TLS_GROUP_BRAINPOOLP256R1_TLS13 = 31,    //RFC 8734
   TLS_GROUP_BRAINPOOLP384R1_TLS13 = 32,    //RFC 8734
   TLS_GROUP_BRAINPOOLP512R1_TLS13 = 33,    //RFC 8734
   TLS_GROUP_GC256A                = 34,    //RFC 9189
   TLS_GROUP_GC256B                = 35,    //RFC 9189
   TLS_GROUP_GC256C                = 36,    //RFC 9189
   TLS_GROUP_GC256D                = 37,    //RFC 9189
   TLS_GROUP_GC512A                = 38,    //RFC 9189
   TLS_GROUP_GC512B                = 39,    //RFC 9189
   TLS_GROUP_GC512C                = 40,    //RFC 9189
   TLS_GROUP_SM2                   = 41,    //RFC 8998
   TLS_GROUP_FFDHE2048             = 256,   //RFC 7919
   TLS_GROUP_FFDHE3072             = 257,   //RFC 7919
   TLS_GROUP_FFDHE4096             = 258,   //RFC 7919
   TLS_GROUP_FFDHE6144             = 259,   //RFC 7919
   TLS_GROUP_FFDHE8192             = 260,   //RFC 7919
   TLS_GROUP_FFDHE_MAX             = 511,   //RFC 7919
   TLS_GROUP_EXPLICIT_PRIME_CURVE  = 65281, //RFC 4492
   TLS_GROUP_EXPLICIT_CHAR2_CURVE  = 65282  //RFC 4492
} TlsNamedGroup;


/**
 * @brief EC point formats
 **/

typedef enum
{
   TLS_EC_POINT_FORMAT_UNCOMPRESSED               = 0,
   TLS_EC_POINT_FORMAT_ANSI_X962_COMPRESSED_PRIME = 1,
   TLS_EC_POINT_FORMAT_ANSI_X962_COMPRESSED_CHAR2 = 2
} TlsEcPointFormat;


/**
 * @brief EC curve types
 **/

typedef enum
{
   TLS_EC_CURVE_TYPE_EXPLICIT_PRIME = 1,
   TLS_EC_CURVE_TYPE_EXPLICIT_CHAR2 = 2,
   TLS_EC_CURVE_TYPE_NAMED_CURVE    = 3
} TlsEcCurveType;


/**
 * @brief TLS FSM states
 **/

typedef enum
{
   TLS_STATE_INIT                        = 0,
   TLS_STATE_CLIENT_HELLO                = 1,
   TLS_STATE_CLIENT_HELLO_2              = 2,
   TLS_STATE_EARLY_DATA                  = 3,
   TLS_STATE_HELLO_VERIFY_REQUEST        = 4,
   TLS_STATE_HELLO_RETRY_REQUEST         = 5,
   TLS_STATE_SERVER_HELLO                = 6,
   TLS_STATE_SERVER_HELLO_2              = 7,
   TLS_STATE_SERVER_HELLO_3              = 8,
   TLS_STATE_HANDSHAKE_TRAFFIC_KEYS      = 9,
   TLS_STATE_ENCRYPTED_EXTENSIONS        = 10,
   TLS_STATE_SERVER_CERTIFICATE          = 11,
   TLS_STATE_SERVER_KEY_EXCHANGE         = 12,
   TLS_STATE_SERVER_CERTIFICATE_VERIFY   = 13,
   TLS_STATE_CERTIFICATE_REQUEST         = 14,
   TLS_STATE_SERVER_HELLO_DONE           = 15,
   TLS_STATE_CLIENT_CERTIFICATE          = 16,
   TLS_STATE_CLIENT_KEY_EXCHANGE         = 17,
   TLS_STATE_CLIENT_CERTIFICATE_VERIFY   = 18,
   TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC   = 19,
   TLS_STATE_CLIENT_CHANGE_CIPHER_SPEC_2 = 20,
   TLS_STATE_CLIENT_FINISHED             = 21,
   TLS_STATE_CLIENT_APP_TRAFFIC_KEYS     = 22,
   TLS_STATE_SERVER_CHANGE_CIPHER_SPEC   = 23,
   TLS_STATE_SERVER_CHANGE_CIPHER_SPEC_2 = 24,
   TLS_STATE_SERVER_FINISHED             = 25,
   TLS_STATE_END_OF_EARLY_DATA           = 26,
   TLS_STATE_SERVER_APP_TRAFFIC_KEYS     = 27,
   TLS_STATE_NEW_SESSION_TICKET          = 28,
   TLS_STATE_KEY_UPDATE                  = 29,
   TLS_STATE_APPLICATION_DATA            = 30,
   TLS_STATE_CLOSING                     = 31,
   TLS_STATE_CLOSED                      = 32
} TlsState;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief Sequence number
 **/

typedef __start_packed struct
{
   uint8_t b[8];
} TlsSequenceNumber;


/**
 * @brief Cipher suites
 **/

typedef __start_packed struct
{
   uint16_t length;  //0-1
   uint16_t value[]; //2
} __end_packed TlsCipherSuites;


/**
 * @brief Compression methods
 **/

typedef __start_packed struct
{
   uint8_t length;  //0
   uint8_t value[]; //1
} __end_packed TlsCompressMethods;


/**
 * @brief Signature algorithm
 **/

typedef __start_packed struct
{
   uint8_t hash;      //0
   uint8_t signature; //1
} __end_packed TlsSignHashAlgo;


/**
 * @brief List of signature algorithms
 **/

typedef __start_packed struct
{
   uint16_t length;         //0-1
   TlsSignHashAlgo value[]; //2
} __end_packed TlsSignHashAlgos;


/**
 * @brief List of certificates
 **/

typedef __start_packed struct
{
   uint8_t length[3]; //0-2
   uint8_t value[];   //3
} __end_packed TlsCertificateList;


/**
 * @brief List of certificate authorities
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsCertAuthorities;


/**
 * @brief TLS extension
 **/

typedef __start_packed struct
{
   uint16_t type;   //0-1
   uint16_t length; //2-3
   uint8_t value[]; //4
} __end_packed TlsExtension;


/**
 * @brief List of TLS extensions
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsExtensionList;


/**
 * @brief List of supported versions
 **/

typedef __start_packed struct
{
   uint8_t length;   //0
   uint16_t value[]; //1
} __end_packed TlsSupportedVersionList;


/**
 * @brief Server name
 **/

typedef __start_packed struct
{
   uint8_t type;      //0
   uint16_t length;   //1-2
   char_t hostname[]; //2
} __end_packed TlsServerName;


/**
 * @brief List of server names
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsServerNameList;


/**
 * @brief Protocol name
 **/

typedef __start_packed struct
{
   uint8_t length; //0
   char_t value[]; //1
} __end_packed TlsProtocolName;


/**
 * @brief List of protocol names
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsProtocolNameList;


/**
 * @brief List of supported groups
 **/

typedef __start_packed struct
{
   uint16_t length;  //0-1
   uint16_t value[]; //2
} __end_packed TlsSupportedGroupList;


/**
 * @brief List of supported EC point formats
 **/

typedef __start_packed struct
{
   uint8_t length;  //0
   uint8_t value[]; //1
} __end_packed TlsEcPointFormatList;


/**
 * @brief List of supported certificate types
 **/

typedef __start_packed struct
{
   uint8_t length;  //0
   uint8_t value[]; //1
} __end_packed TlsCertTypeList;


/**
 * @brief Renegotiated connection
 **/

typedef __start_packed struct
{
   uint8_t length;  //0
   uint8_t value[]; //1
} __end_packed TlsRenegoInfo;


/**
 * @brief PSK identity
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsPskIdentity;


/**
 * @brief PSK identity hint
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsPskIdentityHint;


/**
 * @brief Digitally-signed element (TLS 1.0 and TLS 1.1)
 **/

typedef __start_packed struct
{
   uint16_t length; //0-1
   uint8_t value[]; //2
} __end_packed TlsDigitalSignature;


/**
 * @brief Digitally-signed element (TLS 1.2)
 **/

typedef __start_packed struct
{
   TlsSignHashAlgo algorithm; //0-1
   uint16_t length;           //2-3
   uint8_t value[];           //4
} __end_packed Tls12DigitalSignature;


/**
 * @brief TLS record
 **/

typedef __start_packed struct
{
   uint8_t type;     //0
   uint16_t version; //1-2
   uint16_t length;  //3-4
   uint8_t data[];   //5
} __end_packed TlsRecord;


/**
 * @brief TLS handshake message
 **/

typedef __start_packed struct
{
   uint8_t msgType;   //0
   uint8_t length[3]; //1-3
   uint8_t data[];    //4
} __end_packed TlsHandshake;


/**
 * @brief HelloRequest message
 **/

typedef void TlsHelloRequest;


/**
 * @brief ClientHello message
 **/

typedef __start_packed struct
{
   uint16_t clientVersion; //0-1
   uint8_t random[32];     //2-33
   uint8_t sessionIdLen;   //34
   uint8_t sessionId[];    //35
} __end_packed TlsClientHello;


/**
 * @brief ServerHello message
 **/

typedef __start_packed struct
{
   uint16_t serverVersion; //0-1
   uint8_t random[32];     //2-33
   uint8_t sessionIdLen;   //34
   uint8_t sessionId[];    //35
} __end_packed TlsServerHello;


/**
 * @brief Certificate message
 **/

typedef void TlsCertificate;


/**
 * @brief ServerKeyExchange message
 **/

typedef void TlsServerKeyExchange;


/**
 * @brief CertificateRequest message
 **/

typedef __start_packed struct
{
   uint8_t certificateTypesLen;  //0
   uint8_t certificateTypes[];   //1
} __end_packed TlsCertificateRequest;


/**
 * @brief ServerHelloDone message
 **/

typedef void TlsServerHelloDone;


/**
 * @brief ClientKeyExchange message
 **/

typedef void TlsClientKeyExchange;


/**
 * @brief CertificateVerify message
 **/

typedef void TlsCertificateVerify;


/**
 * @brief NewSessionTicket message
 **/

typedef __start_packed struct
{
   uint32_t ticketLifetimeHint; //0-3
   uint16_t ticketLen;          //4-5
   uint8_t ticket[];            //6
} __end_packed TlsNewSessionTicket;


/**
 * @brief Finished message
 **/

typedef void TlsFinished;


/**
 * @brief ChangeCipherSpec message
 **/

typedef __start_packed struct
{
   uint8_t type; //0
} __end_packed TlsChangeCipherSpec;


/**
 * @brief Alert message
 **/

typedef __start_packed struct
{
   uint8_t level;       //0
   uint8_t description; //1
} __end_packed TlsAlert;


/**
 * @brief Session state information
 **/

typedef __start_packed struct
{
   uint16_t version;                       ///<Protocol version
   uint16_t cipherSuite;                   ///<Cipher suite identifier
   uint8_t secret[TLS_MASTER_SECRET_SIZE]; ///<Master secret
   systime_t ticketTimestamp;              ///<Timestamp to manage ticket lifetime
   uint32_t ticketLifetime;                ///<Lifetime of the ticket
#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   bool_t extendedMasterSecret;            ///<Extended master secret computation
#endif
} __end_packed TlsPlaintextSessionState;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif


/**
 * @brief Socket handle
 **/

typedef void *TlsSocketHandle;


/**
 * @brief Socket send callback function
 **/

typedef error_t (*TlsSocketSendCallback)(TlsSocketHandle handle,
   const void *data, size_t length, size_t *written, uint_t flags);


/**
 * @brief Socket receive callback function
 **/

typedef error_t (*TlsSocketReceiveCallback)(TlsSocketHandle handle,
   void *data, size_t size, size_t *received, uint_t flags);


/**
 * @brief ALPN callback function
 **/

typedef error_t (*TlsAlpnCallback)(TlsContext *context,
   const char_t *selectedProtocol);


/**
 * @brief Pre-shared key callback function
 **/

typedef error_t (*TlsPskCallback)(TlsContext *context,
   const uint8_t *pskIdentity, size_t pskIdentityLen);


/**
 * @brief Certificate verification callback function
 **/

typedef error_t (*TlsCertVerifyCallback)(TlsContext *context,
   const X509CertificateInfo *certInfo, uint_t pathLen, void *param);


/**
 * @brief Raw public key verification callback function
 **/

typedef error_t (*TlsRpkVerifyCallback)(TlsContext *context,
   const uint8_t *rawPublicKey, size_t rawPublicKeyLen);


/**
 * @brief Ticket encryption callback function
 **/

typedef error_t (*TlsTicketEncryptCallback)(TlsContext *context,
   const uint8_t *plaintext, size_t plaintextLen, uint8_t *ciphertext,
   size_t *ciphertextLen, void *param);


/**
 * @brief Ticket decryption callback function
 **/

typedef error_t (*TlsTicketDecryptCallback)(TlsContext *context,
   const uint8_t *ciphertext, size_t ciphertextLen, uint8_t *plaintext,
   size_t *plaintextLen, void *param);


/**
 * @brief ECDH key agreement callback function
 **/

typedef error_t (*TlsEcdhCallback)(TlsContext *context);


/**
 * @brief ECDSA signature generation callback function
 **/

typedef error_t (*TlsEcdsaSignCallback)(TlsContext *context,
   const uint8_t *digest, size_t digestLen, EcdsaSignature *signature);


/**
 * @brief ECDSA signature verification callback function
 **/

typedef error_t (*TlsEcdsaVerifyCallback)(TlsContext *context,
   const uint8_t *digest, size_t digestLen, EcdsaSignature *signature);


/**
 * @brief Key logging callback function (for debugging purpose only)
 **/

typedef void (*TlsKeyLogCallback)(TlsContext *context, const char_t *key);


/**
 * @brief Structure describing a cipher suite
 **/

typedef struct
{
   uint16_t identifier;
   const char_t *name;
   TlsKeyExchMethod keyExchMethod;
   const CipherAlgo *cipherAlgo;
   CipherMode cipherMode;
   const HashAlgo *hashAlgo;
   const HashAlgo *prfHashAlgo;
   uint8_t macKeyLen;
   uint8_t encKeyLen;
   uint8_t fixedIvLen;
   uint8_t recordIvLen;
   uint8_t authTagLen;
   uint8_t verifyDataLen;
} TlsCipherSuiteInfo;


/**
 * @brief TLS session state
 **/

typedef struct
{
   uint16_t version;                       ///<TLS protocol version
   uint16_t cipherSuite;                   ///<Cipher suite identifier
   systime_t timestamp;                    ///<Time stamp to manage entry lifetime
   uint8_t secret[TLS_MASTER_SECRET_SIZE]; ///<Master secret (TLS 1.2) or ticket PSK (TLS 1.3)
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   uint8_t sessionId[32];                  ///<Session identifier
   size_t sessionIdLen;                    ///<Length of the session identifier
   bool_t extendedMasterSecret;            ///<Extended master secret computation
#endif
   uint8_t *ticket;                        ///<Session ticket
   size_t ticketLen;                       ///<Length of the session ticket
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   systime_t ticketTimestamp;              ///<Timestamp to manage ticket lifetime
   uint32_t ticketLifetime;                ///<Lifetime of the ticket
   uint32_t ticketAgeAdd;                  ///<Random value used to obscure the age of the ticket
   TlsHashAlgo ticketHashAlgo;             ///<Hash algorithm associated with the ticket
   char_t *ticketAlpn;                     ///<ALPN protocol associated with the ticket
   uint32_t maxEarlyDataSize;              ///<Maximum amount of 0-RTT data that the client is allowed to send
#endif
#if (TLS_SNI_SUPPORT == ENABLED)
   char_t *serverName;                     ///<ServerName extension
#endif
} TlsSessionState;


/**
 * @brief Session cache
 **/

typedef struct
{
   OsMutex mutex;              ///<Mutex preventing simultaneous access to the cache
   uint_t size;                ///<Maximum number of entries
   TlsSessionState sessions[]; ///<Cache entries
} TlsCache;


/**
 * @brief Certificate descriptor
 **/

typedef struct
{
   const char_t *certChain;   ///<End entity certificate chain (PEM format)
   size_t certChainLen;       ///<Length of the certificate chain
   const char_t *privateKey;  ///<Private key (PEM format)
   size_t privateKeyLen;      ///<Length of the private key
   TlsCertificateType type;   ///<End entity certificate type
   TlsSignatureAlgo signAlgo; ///<Signature algorithm used to sign the end entity certificate
   TlsHashAlgo hashAlgo;      ///<Hash algorithm used to sign the end entity certificate
   TlsNamedGroup namedCurve;  ///<Named curve used to generate the EC public key
} TlsCertDesc;


/**
 * @brief Hello extensions
 **/

typedef struct
{
   const TlsSupportedVersionList *supportedVersionList; ///<SupportedVersions extension (ClientHello)
   const TlsExtension *selectedVersion;                 ///<SupportedVersions extension (ServerHello)
   const TlsServerNameList *serverNameList;             ///<ServerName extension
   const TlsSupportedGroupList *supportedGroupList;     ///<SupportedGroups extension
   const TlsEcPointFormatList *ecPointFormatList;       ///<EcPointFormats extension
   const TlsSignHashAlgos *signAlgoList;                ///<SignatureAlgorithms extension
   const TlsSignHashAlgos *certSignAlgoList;            ///<SignatureAlgorithmsCert extension
#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   const TlsExtension *maxFragLen;                      ///<MaxFragmentLength extension
#endif
#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   const TlsExtension *recordSizeLimit;                 ///<RecordSizeLimit extension
#endif
#if (TLS_ALPN_SUPPORT == ENABLED)
   const TlsProtocolNameList *protocolNameList;         ///<ALPN extension
#endif
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   const TlsCertTypeList *clientCertTypeList;           ///<ClientCertType extension
   const TlsExtension *clientCertType;
   const TlsCertTypeList *serverCertTypeList;           ///<ServerCertType extension
   const TlsExtension *serverCertType;
#endif
#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   const TlsExtension *extendedMasterSecret;            ///<ExtendedMasterSecret extension
#endif
#if (TLS_TICKET_SUPPORT == ENABLED)
   const TlsExtension *sessionTicket;                   ///<SessionTicket extension
#endif
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   const TlsRenegoInfo *renegoInfo;                     ///<RenegotiationInfo extension
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   const Tls13Cookie *cookie;                           ///<Cookie extension
   const Tls13KeyShareList *keyShareList;               ///<KeyShare extension (ClientHello)
   const TlsExtension *selectedGroup;                   ///<KeyShare extension (HelloRetryRequest)
   const Tls13KeyShareEntry *serverShare;               ///<KeyShare extension (ServerHello)
   const Tls13PskKeModeList *pskKeModeList;             ///<PskKeyExchangeModes extension
   const Tls13PskIdentityList *identityList;            ///<PreSharedKey extension (ClientHello)
   const Tls13PskBinderList *binderList;
   const TlsExtension *selectedIdentity;                ///<PreSharedKey extension (ServerHello)
   const TlsExtension *earlyDataIndication;             ///<EarlyData extension
#endif
} TlsHelloExtensions;


/**
 * @brief Encryption engine
 **/

struct _TlsEncryptionEngine
{
   uint16_t version;              ///<Negotiated TLS version
   uint8_t macKey[48];            ///<MAC key
   size_t macKeyLen;              ///<Length of the MAC key
   uint8_t encKey[48];            ///<Encryption key
   size_t encKeyLen;              ///<Length of the encryption key
   uint8_t iv[16];                ///<Initialization vector
   size_t fixedIvLen;             ///<Length of the fixed part of the IV
   size_t recordIvLen;            ///<Length of the IV
   size_t authTagLen;             ///<Length of the authentication tag
   const CipherAlgo *cipherAlgo;  ///<Cipher algorithm
   void *cipherContext;           ///<Cipher context
   CipherMode cipherMode;         ///<Cipher mode of operation
   const HashAlgo *hashAlgo;      ///<Hash algorithm for MAC operations
   HmacContext *hmacContext;      ///<HMAC context
#if (TLS_GCM_CIPHER_SUPPORT == ENABLED)
   GcmContext *gcmContext;        ///<GCM context
#endif
   TlsSequenceNumber seqNum;      ///<TLS sequence number
#if (DTLS_SUPPORT == ENABLED)
   uint16_t epoch;                ///<Counter value incremented on every cipher state change
   DtlsSequenceNumber dtlsSeqNum; ///<Record sequence number
#endif
#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   size_t recordSizeLimit;        ///<Maximum size of record in octets
   TLS_PRIVATE_ENCRYPTION_ENGINE  ///<Application specific context
#endif
};


/**
 * @brief TLS context
 *
 * An opaque data structure that represents a TLS connection
 *
 **/

struct _TlsContext
{
   TlsState state;                           ///<TLS handshake finite state machine
   TlsTransportProtocol transportProtocol;   ///<Transport protocol (stream or datagram)
   TlsConnectionEnd entity;                  ///<Client or server operation

   TlsSocketHandle socketHandle;             ///<Socket handle
   TlsSocketSendCallback socketSendCallback;       ///<Socket send callback function
   TlsSocketReceiveCallback socketReceiveCallback; ///<Socket receive callback function

   const PrngAlgo *prngAlgo;                 ///<Pseudo-random number generator to be used
   void *prngContext;                        ///<Pseudo-random number generator context

   const uint16_t *cipherSuites;             ///<List of supported cipher suites
   uint_t numCipherSuites;                   ///<Number of cipher suites in the list

   const uint16_t *supportedGroups;          ///<List of supported named groups
   uint_t numSupportedGroups;                ///<Number of named groups in the list

   char_t *serverName;                       ///<Fully qualified DNS hostname of the server

#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
   TlsEcdhCallback ecdhCallback;
   TlsEcdsaSignCallback ecdsaSignCallback;
   TlsEcdsaVerifyCallback ecdsaVerifyCallback;
#endif

   TlsCertDesc certs[TLS_MAX_CERTIFICATES];  ///<End entity certificates (PEM format)
   uint_t numCerts;                          ///<Number of certificates available
   const char_t *trustedCaList;              ///<List of trusted CA (PEM format)
   size_t trustedCaListLen;                  ///<Number of trusted CA in the list
   TlsCertVerifyCallback certVerifyCallback; ///<Certificate verification callback function
   void *certVerifyParam;                    ///<Opaque pointer passed to the certificate verification callback
   TlsCertDesc *cert;                        ///<Pointer to the currently selected certificate

   TlsCache *cache;                          ///<TLS session cache
   uint8_t sessionId[32];                    ///<Session identifier
   size_t sessionIdLen;                      ///<Length of the session identifier

   uint16_t clientVersion;                   ///<Latest version supported by the client
   uint16_t version;                         ///<Negotiated TLS version
   uint16_t versionMin;                      ///<Minimum version accepted by the implementation
   uint16_t versionMax;                      ///<Maximum version accepted by the implementation

   uint8_t *cookie;                          ///<Cookie
   size_t cookieLen;                         ///<Length of the cookie

   uint8_t *ticket;                          ///<Session ticket
   size_t ticketLen;                         ///<Length of the session ticket
   systime_t ticketTimestamp;                ///<Timestamp to manage ticket lifetime
   uint32_t ticketLifetime;                  ///<Lifetime of the ticket

   TlsCipherSuiteInfo cipherSuite;           ///<Negotiated cipher suite
   TlsKeyExchMethod keyExchMethod;           ///<Key exchange method
   TlsSignatureAlgo signAlgo;                ///<Signature algorithm to be used
   TlsHashAlgo signHashAlgo;                 ///<Hash algorithm used for signing
   uint16_t namedGroup;                      ///<ECDHE or FFDHE named group

   TlsCertificateType peerCertType;          ///<Peer's certificate type
   TlsClientAuthMode clientAuthMode;         ///<Client authentication mode
   bool_t clientCertRequested;               ///<This flag tells whether the client certificate is requested

   bool_t resume;                            ///<The connection is established by resuming a session
   bool_t fatalAlertSent;                    ///<A fatal alert message has been sent
   bool_t fatalAlertReceived;                ///<A fatal alert message has been received from the peer
   bool_t closeNotifySent;                   ///<A closure alert has been sent
   bool_t closeNotifyReceived;               ///<A closure alert has been received from the peer

   uint8_t *txBuffer;                        ///<TX buffer
   size_t txBufferSize;                      ///<TX buffer size
   size_t txBufferMaxLen;                    ///<Maximum number of plaintext data the TX buffer can hold
   TlsContentType txBufferType;              ///<Type of data that resides in the TX buffer
   size_t txBufferLen;                       ///<Number of bytes that are pending to be sent
   size_t txBufferPos;                       ///<Current position in TX buffer
   size_t txRecordLen;                       ///<Length of the TLS record
   size_t txRecordPos;                       ///<Current position in the TLS record

   uint8_t *rxBuffer;                        ///<RX buffer
   size_t rxBufferSize;                      ///<RX buffer size
   size_t rxBufferMaxLen;                    ///<Maximum number of plaintext data the RX buffer can hold
   TlsContentType rxBufferType;              ///<Type of data that resides in the RX buffer
   size_t rxBufferLen;                       ///<Number of bytes available for reading
   size_t rxBufferPos;                       ///<Current position in RX buffer
   size_t rxRecordLen;                       ///<Length of the TLS record
   size_t rxRecordPos;                       ///<Current position in the TLS record

   uint8_t clientRandom[TLS_RANDOM_SIZE];    ///<Client random value
   uint8_t serverRandom[TLS_RANDOM_SIZE];    ///<Server random value
   uint8_t premasterSecret[TLS_PREMASTER_SECRET_SIZE]; ///<Premaster secret
   size_t premasterSecretLen;                ///<Length of the premaster secret
   uint8_t clientVerifyData[64];             ///<Client verify data
   size_t clientVerifyDataLen;               ///<Length of the client verify data
   uint8_t serverVerifyData[64];             ///<Server verify data
   size_t serverVerifyDataLen;               ///<Length of the server verify data

   TlsEncryptionEngine encryptionEngine;     ///<Encryption engine
   TlsEncryptionEngine decryptionEngine;     ///<Decryption engine

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_0)
   size_t txLastRecordLen;                   ///<Length of the previous TLS record
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_1)
   Md5Context *transcriptMd5Context;         ///<MD5 context used to compute verify data
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   uint8_t masterSecret[TLS_MASTER_SECRET_SIZE]; ///<Master secret
   uint8_t keyBlock[192];                    ///<Key material
   HmacContext hmacContext;                  ///<HMAC context
   Sha1Context *transcriptSha1Context;       ///<SHA-1 context used to compute verify data
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   HashContext *transcriptHashContext;       ///<Hash context used to compute verify data
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   uint16_t preferredGroup;                  ///<Preferred ECDHE or FFDHE named group
   systime_t clientHelloTimestamp;           ///<Time at which the ClientHello message was sent
   bool_t updatedClientHelloReceived;        ///<An updated ClientHello message has been received
   uint8_t *certRequestContext;              ///<Certificate request context
   size_t certRequestContextLen;             ///<Length of the certificate request context
   int_t selectedIdentity;                   ///<Selected PSK identity
   bool_t pskKeModeSupported;                ///<PSK key establishment supported by the client

   uint8_t secret[TLS_MAX_HKDF_DIGEST_SIZE];
   uint8_t clientEarlyTrafficSecret[TLS_MAX_HKDF_DIGEST_SIZE];
   uint8_t clientHsTrafficSecret[TLS_MAX_HKDF_DIGEST_SIZE];
   uint8_t serverHsTrafficSecret[TLS_MAX_HKDF_DIGEST_SIZE];
   uint8_t clientAppTrafficSecret[TLS_MAX_HKDF_DIGEST_SIZE];
   uint8_t serverAppTrafficSecret[TLS_MAX_HKDF_DIGEST_SIZE];
   uint8_t exporterMasterSecret[TLS_MAX_HKDF_DIGEST_SIZE];
   uint8_t resumptionMasterSecret[TLS_MAX_HKDF_DIGEST_SIZE];

   uint_t newSessionTicketCount;             ///<Number of NewSessionTicket messages that have been sent

   uint8_t ticketPsk[TLS_MAX_HKDF_DIGEST_SIZE]; ///<PSK associated with the ticket
   size_t ticketPskLen;                      ///<Length of the PSK associated with the ticket
   uint32_t ticketAgeAdd;                    ///<Random value used to obscure the age of the ticket
   uint32_t ticketNonce;                     ///<A per-ticket value that is unique across all tickets issued
   uint16_t ticketCipherSuite;               ///<Cipher suite associated with the ticket
   TlsHashAlgo ticketHashAlgo;               ///<Hash algorithm associated with the ticket
   char_t *ticketAlpn;                       ///<ALPN protocol associated with the ticket

   size_t maxEarlyDataSize;                  ///<Maximum amount of 0-RTT data that the client is allowed to send
   size_t earlyDataLen;                      ///<Total amount of 0-RTT data that have been sent by the client
   bool_t earlyDataEnabled;                  ///<EarlyData is enabled
   bool_t earlyDataRejected;                 ///<The 0-RTT data have been rejected by the server
   bool_t earlyDataExtReceived;              ///<The EarlyData extension has been received
   TlsSequenceNumber earlyDataSeqNum;        ///<Early data sequence number
#endif

#if (TLS_DH_SUPPORT == ENABLED)
   DhContext dhContext;                      ///<Diffie-Hellman context
#endif

#if (TLS_ECDH_SUPPORT == ENABLED)
   EcdhContext ecdhContext;                  ///<ECDH context
   bool_t ecPointFormatsExtReceived;         ///<The EcPointFormats extension has been received
#endif

#if (TLS_RSA_SUPPORT == ENABLED)
   RsaPublicKey peerRsaPublicKey;            ///<Peer's RSA public key
#endif

#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
   DsaPublicKey peerDsaPublicKey;            ///<Peer's DSA public key
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_EDDSA_SIGN_SUPPORT == ENABLED)
   EcDomainParameters peerEcParams;          ///<Peer's EC domain parameters
   EcPublicKey peerEcPublicKey;              ///<Peer's EC public key
#endif

#if (TLS_PSK_SUPPORT == ENABLED)
   uint8_t *psk;                             ///<Pre-shared key
   size_t pskLen;                            ///<Length of the pre-shared key, in bytes
   char_t *pskIdentity;                      ///<PSK identity
   char_t *pskIdentityHint;                  ///<PSK identity hint
   TlsPskCallback pskCallback;               ///<PSK callback function
   uint16_t pskCipherSuite;                  ///<Cipher suite associated with the PSK
   TlsHashAlgo pskHashAlgo;                  ///<Hash algorithm associated with the PSK
#endif

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   size_t maxFragLen;                        ///<Maximum plaintext fragment length
   bool_t maxFragLenExtReceived;             ///<The MaxFragmentLength extension has been received
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   size_t recordSizeLimit;                   ///<Maximum record size the peer is willing to receive
   bool_t recordSizeLimitExtReceived;        ///<The RecordSizeLimit extension has been received
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
   bool_t unknownProtocolsAllowed;           ///<Unknown ALPN protocols allowed
   char_t *protocolList;                     ///<List of supported ALPN protocols
   char_t *selectedProtocol;                 ///<Selected ALPN protocol
   TlsAlpnCallback alpnCallback;             ///<ALPN callback function
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   bool_t emsExtReceived;                    ///<The ExtendedMasterSecret extension has been received
#endif

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   TlsCertificateFormat certFormat;          ///<Certificate format
   TlsCertificateFormat peerCertFormat;      ///<Peer's certificate format
   TlsRpkVerifyCallback rpkVerifyCallback;   ///<Raw public key verification callback function
   bool_t clientCertTypeExtReceived;         ///<The ClientCertType extension has been received
   bool_t serverCertTypeExtReceived;         ///<The ServerCertType extension has been received
#endif

#if (TLS_TICKET_SUPPORT == ENABLED)
   bool_t sessionTicketEnabled;              ///<Session ticket mechanism enabled
   bool_t sessionTicketExtReceived;          ///<The SessionTicket extension has been received
   bool_t sessionTicketExtSent;              ///<The SessionTicket extension has been sent
   TlsTicketEncryptCallback ticketEncryptCallback; ///<Ticket encryption callback function
   TlsTicketDecryptCallback ticketDecryptCallback; ///<Ticket decryption callback function
   void *ticketParam;                        ///<Opaque pointer passed to the ticket callbacks
#endif

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   bool_t secureRenegoEnabled;               ///<Secure renegotiation enabled
   bool_t secureRenegoFlag;                  ///<Secure renegotiation flag
#endif

#if (TLS_FALLBACK_SCSV_SUPPORT == ENABLED)
   bool_t fallbackScsvEnabled;               ///<Support for FALLBACK_SCSV
#endif

#if (TLS_KEY_LOG_SUPPORT == ENABLED)
   TlsKeyLogCallback keyLogCallback;         ///<Key logging callback (for debugging purpose only)
#endif

#if (TLS_MAX_WARNING_ALERTS > 0)
   uint_t alertCount;                        ///<Count of consecutive warning alerts
#endif

#if (TLS_MAX_EMPTY_RECORDS > 0)
   uint_t emptyRecordCount;                  ///<Count of consecutive empty records
#endif

#if (TLS_MAX_CHANGE_CIPHER_SPEC_MESSAGES > 0)
   uint_t changeCipherSpecCount;             ///<Count of consecutive ChangeCipherSpec messages
#endif

#if (TLS_MAX_KEY_UPDATE_MESSAGES > 0)
   uint_t keyUpdateCount;                    ///<Count of consecutive KeyUpdate messages
#endif

#if (DTLS_SUPPORT == ENABLED)
   size_t pmtu;                              ///<PMTU value
   systime_t timeout;                        ///<Timeout for blocking calls
   systime_t startTime;

   DtlsCookieGenerateCallback cookieGenerateCallback; ///<Cookie generation callback function
   DtlsCookieVerifyCallback cookieVerifyCallback;     ///<Cookie verification callback function
   void *cookieParam;                        ///<Opaque pointer passed to the cookie callbacks

   uint_t retransmitCount;                   ///<Retransmission counter
   systime_t retransmitTimestamp;            ///<Time at which the datagram was sent
   systime_t retransmitTimeout;              ///<Retransmission timeout

   uint16_t txMsgSeq;                        ///<Send sequence number
   size_t txDatagramLen;                     ///<Length of the outgoing datagram, in bytes

   uint16_t rxMsgSeq;                        ///<Next receive sequence number
   size_t rxFragQueueLen;                    ///<Length of the reassembly queue
   size_t rxDatagramLen;                     ///<Length of the incoming datagram, in bytes
   size_t rxDatagramPos;
   uint16_t rxRecordVersion;                 ///<Version of the incoming record

   TlsEncryptionEngine prevEncryptionEngine;
#endif

#if (DTLS_SUPPORT == ENABLED && DTLS_REPLAY_DETECTION_SUPPORT == ENABLED)
   bool_t replayDetectionEnabled;           ///<Anti-replay mechanism enabled
   uint32_t replayWindow[(DTLS_REPLAY_WINDOW_SIZE + 31) / 32];
#endif

   TLS_PRIVATE_CONTEXT                       ///<Application specific context
};


//TLS application programming interface (API)
TlsContext *tlsInit(void);
TlsState tlsGetState(TlsContext *context);

error_t tlsSetSocketCallbacks(TlsContext *context,
   TlsSocketSendCallback socketSendCallback,
   TlsSocketReceiveCallback socketReceiveCallback, TlsSocketHandle handle);

error_t tlsSetVersion(TlsContext *context, uint16_t versionMin,
   uint16_t versionMax);

error_t tlsSetTransportProtocol(TlsContext *context,
   TlsTransportProtocol transportProtocol);

error_t tlsSetConnectionEnd(TlsContext *context, TlsConnectionEnd entity);

error_t tlsSetPrng(TlsContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t tlsSetServerName(TlsContext *context, const char_t *serverName);
const char_t *tlsGetServerName(TlsContext *context);

error_t tlsSetCache(TlsContext *context, TlsCache *cache);
error_t tlsSetClientAuthMode(TlsContext *context, TlsClientAuthMode mode);

error_t tlsSetBufferSize(TlsContext *context, size_t txBufferSize,
   size_t rxBufferSize);

error_t tlsSetMaxFragmentLength(TlsContext *context, size_t maxFragLen);

error_t tlsSetCipherSuites(TlsContext *context, const uint16_t *cipherSuites,
   uint_t length);

error_t tlsSetSupportedGroups(TlsContext *context, const uint16_t *groups,
   uint_t length);

error_t tlsSetPreferredGroup(TlsContext *context, uint16_t group);

error_t tlsSetDhParameters(TlsContext *context, const char_t *params,
   size_t length);

error_t tlsSetEcdhCallback(TlsContext *context, TlsEcdhCallback ecdhCallback);

error_t tlsSetEcdsaSignCallback(TlsContext *context,
   TlsEcdsaSignCallback ecdsaSignCallback);

error_t tlsSetEcdsaVerifyCallback(TlsContext *context,
   TlsEcdsaVerifyCallback ecdsaVerifyCallback);

error_t tlsSetKeyLogCallback(TlsContext *context,
   TlsKeyLogCallback keyLogCallback);

error_t tlsAllowUnknownAlpnProtocols(TlsContext *context, bool_t allowed);
error_t tlsSetAlpnProtocolList(TlsContext *context, const char_t *protocolList);
error_t tlsSetAlpnCallback(TlsContext *context, TlsAlpnCallback alpnCallback);
const char_t *tlsGetAlpnProtocol(TlsContext *context);

error_t tlsSetPsk(TlsContext *context, const uint8_t *psk, size_t length);
error_t tlsSetPskIdentity(TlsContext *context, const char_t *pskIdentity);
error_t tlsSetPskIdentityHint(TlsContext *context, const char_t *pskIdentityHint);
error_t tlsSetPskCallback(TlsContext *context, TlsPskCallback pskCallback);

error_t tlsSetRpkVerifyCallback(TlsContext *context,
   TlsRpkVerifyCallback rpkVerifyCallback);

error_t tlsSetTrustedCaList(TlsContext *context,
   const char_t *trustedCaList, size_t length);

error_t tlsAddCertificate(TlsContext *context, const char_t *certChain,
   size_t certChainLen, const char_t *privateKey, size_t privateKeyLen);

error_t tlsSetCertificateVerifyCallback(TlsContext *context,
   TlsCertVerifyCallback certVerifyCallback, void *param);

error_t tlsEnableSessionTickets(TlsContext *context, bool_t enabled);
error_t tlsEnableSecureRenegotiation(TlsContext *context, bool_t enabled);
error_t tlsEnableFallbackScsv(TlsContext *context, bool_t enabled);

error_t tlsSetTicketCallbacks(TlsContext *context,
   TlsTicketEncryptCallback ticketEncryptCallback,
   TlsTicketDecryptCallback ticketDecryptCallback, void *param);

error_t tlsSetPmtu(TlsContext *context, size_t pmtu);
error_t tlsSetTimeout(TlsContext *context, systime_t timeout);

error_t tlsSetCookieCallbacks(TlsContext *context,
   DtlsCookieGenerateCallback cookieGenerateCallback,
   DtlsCookieVerifyCallback cookieVerifyCallback, void *param);

error_t tlsEnableReplayDetection(TlsContext *context, bool_t enabled);

error_t tlsSetMaxEarlyDataSize(TlsContext *context, size_t maxEarlyDataSize);

error_t tlsWriteEarlyData(TlsContext *context, const void *data,
   size_t length, size_t *written, uint_t flags);

error_t tlsConnect(TlsContext *context);

TlsEarlyDataStatus tlsGetEarlyDataStatus(TlsContext *context);

error_t tlsWrite(TlsContext *context, const void *data,
   size_t length, size_t *written, uint_t flags);

error_t tlsRead(TlsContext *context, void *data,
   size_t size, size_t *received, uint_t flags);

bool_t tlsIsTxReady(TlsContext *context);
bool_t tlsIsRxReady(TlsContext *context);

error_t tlsShutdown(TlsContext *context);
error_t tlsShutdownEx(TlsContext *context, bool_t waitForCloseNotify);

void tlsFree(TlsContext *context);

error_t tlsInitSessionState(TlsSessionState *session);

error_t tlsSaveSessionState(const TlsContext *context,
   TlsSessionState *session);

error_t tlsRestoreSessionState(TlsContext *context,
   const TlsSessionState *session);

void tlsFreeSessionState(TlsSessionState *session);

TlsCache *tlsInitCache(uint_t size);
void tlsFreeCache(TlsCache *cache);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
