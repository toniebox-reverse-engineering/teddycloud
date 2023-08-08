/**
 * @file tls_config.h
 * @brief CycloneSSL configuration file
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

#ifndef _TLS_CONFIG_H
#define _TLS_CONFIG_H

#define TLS_PRIVATE_CONTEXT       \
    char client_cert_issuer[128]; \
    char client_cert_subject[32]; \
    char client_cert_serial[64];

// Desired trace level (for debugging purposes)
#define TLS_TRACE_LEVEL TRACE_LEVEL_WARNING

// TLS support
#define TLS_SUPPORT ENABLED
// DTLS support
#define DTLS_SUPPORT DISABLED

//Key logging
#define TLS_KEY_LOG_SUPPORT ENABLED

// Client mode of operation
#define TLS_CLIENT_SUPPORT ENABLED
// Server mode of operation
#define TLS_SERVER_SUPPORT ENABLED

// Minimum version that can be negotiated
#define TLS_MIN_VERSION TLS_VERSION_1_2
// Maximum version that can be negotiated
#define TLS_MAX_VERSION TLS_VERSION_1_2

// Session resumption mechanism
#define TLS_SESSION_RESUME_SUPPORT ENABLED
// Lifetime of session cache entries
#define TLS_SESSION_CACHE_LIFETIME 3600000

// Session ticket mechanism
#define TLS_TICKET_SUPPORT DISABLED
// Lifetime of session tickets
#define TLS_TICKET_LIFETIME 3600000

// SNI (Server Name Indication) extension
#define TLS_SNI_SUPPORT ENABLED
// Maximum Fragment Length extension
#define TLS_MAX_FRAG_LEN_SUPPORT ENABLED
// Record Size Limit extension
#define TLS_RECORD_SIZE_LIMIT_SUPPORT ENABLED
// ALPN (Application-Layer Protocol Negotiation) extension
#define TLS_ALPN_SUPPORT ENABLED
// Extended Master Secret extension
#define TLS_EXT_MASTER_SECRET_SUPPORT ENABLED
// ClientHello Padding extension
#define TLS_CLIENT_HELLO_PADDING_SUPPORT ENABLED
// Signature Algorithms Certificate extension
#define TLS_SIGN_ALGOS_CERT_SUPPORT ENABLED
// RPK (Raw Public Key) support
#define TLS_RAW_PUBLIC_KEY_SUPPORT ENABLED
// Secure renegotiation support
#define TLS_SECURE_RENEGOTIATION_SUPPORT ENABLED
// Fallback SCSV support
#define TLS_FALLBACK_SCSV_SUPPORT DISABLED

// Maximum number of certificates the end entity can load
#define TLS_MAX_CERTIFICATES 4

// RSA key exchange support
#define TLS_RSA_KE_SUPPORT DISABLED
// DHE_RSA key exchange support
#define TLS_DHE_RSA_KE_SUPPORT ENABLED
// DHE_DSS key exchange support
#define TLS_DHE_DSS_KE_SUPPORT DISABLED
// DH_anon key exchange support (insecure)
#define TLS_DH_ANON_KE_SUPPORT DISABLED
// ECDHE_RSA key exchange support
#define TLS_ECDHE_RSA_KE_SUPPORT ENABLED
// ECDHE_ECDSA key exchange support
#define TLS_ECDHE_ECDSA_KE_SUPPORT DISABLED
// ECDH_anon key exchange support (insecure)
#define TLS_ECDH_ANON_KE_SUPPORT DISABLED
// PSK key exchange support
#define TLS_PSK_KE_SUPPORT DISABLED
// RSA_PSK key exchange support
#define TLS_RSA_PSK_KE_SUPPORT DISABLED
// DHE_PSK key exchange support
#define TLS_DHE_PSK_KE_SUPPORT DISABLED
// ECDHE_PSK key exchange support
#define TLS_ECDHE_PSK_KE_SUPPORT DISABLED

// DHE key exchange support (TLS 1.3)
#define TLS13_DHE_KE_SUPPORT DISABLED
// ECDHE key exchange support (TLS 1.3)
#define TLS13_ECDHE_KE_SUPPORT DISABLED
// PSK-only key exchange support (TLS 1.3)
#define TLS13_PSK_KE_SUPPORT DISABLED
// PSK with DHE key exchange support (TLS 1.3)
#define TLS13_PSK_DHE_KE_SUPPORT DISABLED
// PSK with ECDHE key exchange support (TLS 1.3)
#define TLS13_PSK_ECDHE_KE_SUPPORT DISABLED

// RSA signature capability
#define TLS_RSA_SIGN_SUPPORT ENABLED
// RSA-PSS signature capability
#define TLS_RSA_PSS_SIGN_SUPPORT DISABLED
// DSA signature capability
#define TLS_DSA_SIGN_SUPPORT DISABLED
// ECDSA signature capability
#define TLS_ECDSA_SIGN_SUPPORT DISABLED
// EdDSA signature capability
#define TLS_EDDSA_SIGN_SUPPORT DISABLED

// NULL cipher support (insecure)
#define TLS_NULL_CIPHER_SUPPORT DISABLED
// Stream cipher support
#define TLS_STREAM_CIPHER_SUPPORT DISABLED
// CBC block cipher support
#define TLS_CBC_CIPHER_SUPPORT ENABLED
// CCM AEAD support
#define TLS_CCM_CIPHER_SUPPORT DISABLED
// CCM_8 AEAD support
#define TLS_CCM_8_CIPHER_SUPPORT DISABLED
// GCM AEAD support
#define TLS_GCM_CIPHER_SUPPORT ENABLED
// ChaCha20Poly1305 AEAD support
#define TLS_CHACHA20_POLY1305_SUPPORT DISABLED

// RC4 cipher support (insecure)
#define TLS_RC4_SUPPORT DISABLED
// IDEA cipher support (insecure)
#define TLS_IDEA_SUPPORT DISABLED
// DES cipher support (insecure)
#define TLS_DES_SUPPORT DISABLED
// Triple DES cipher support (weak)
#define TLS_3DES_SUPPORT DISABLED
// AES 128-bit cipher support
#define TLS_AES_128_SUPPORT ENABLED
// AES 256-bit cipher support
#define TLS_AES_256_SUPPORT ENABLED
// Camellia 128-bit cipher support
#define TLS_CAMELLIA_128_SUPPORT DISABLED
// Camellia 256-bit cipher support
#define TLS_CAMELLIA_256_SUPPORT DISABLED
// ARIA 128-bit cipher support
#define TLS_ARIA_128_SUPPORT DISABLED
// ARIA 256-bit cipher support
#define TLS_ARIA_256_SUPPORT DISABLED
// SEED cipher support
#define TLS_SEED_SUPPORT DISABLED

// MD5 hash support (insecure)
#define TLS_MD5_SUPPORT DISABLED
// SHA-1 hash support (weak)
#define TLS_SHA1_SUPPORT ENABLED
// SHA-224 hash support (weak)
#define TLS_SHA224_SUPPORT DISABLED
// SHA-256 hash support
#define TLS_SHA256_SUPPORT ENABLED
// SHA-384 hash support
#define TLS_SHA384_SUPPORT ENABLED
// SHA-512 hash support
#define TLS_SHA512_SUPPORT DISABLED

// FFDHE key exchange mechanism
#define TLS_FFDHE_SUPPORT DISABLED
// ffdhe2048 group support
#define TLS_FFDHE2048_SUPPORT DISABLED
// ffdhe3072 group support
#define TLS_FFDHE3072_SUPPORT DISABLED
// ffdhe4096 group support
#define TLS_FFDHE4096_SUPPORT DISABLED

// secp160k1 elliptic curve support (weak)
#define TLS_SECP160K1_SUPPORT DISABLED
// secp160r1 elliptic curve support (weak)
#define TLS_SECP160R1_SUPPORT DISABLED
// secp160r2 elliptic curve support (weak)
#define TLS_SECP160R2_SUPPORT DISABLED
// secp192k1 elliptic curve support (weak)
#define TLS_SECP192K1_SUPPORT DISABLED
// secp192r1 elliptic curve support (weak)
#define TLS_SECP192R1_SUPPORT DISABLED
// secp224k1 elliptic curve support
#define TLS_SECP224K1_SUPPORT DISABLED
// secp224r1 elliptic curve support
#define TLS_SECP224R1_SUPPORT DISABLED
// secp256k1 elliptic curve support
#define TLS_SECP256K1_SUPPORT DISABLED
// secp256r1 elliptic curve support
#define TLS_SECP256R1_SUPPORT ENABLED
// secp384r1 elliptic curve support
#define TLS_SECP384R1_SUPPORT DISABLED
// secp521r1 elliptic curve support
#define TLS_SECP521R1_SUPPORT DISABLED
// brainpoolP256r1 elliptic curve support
#define TLS_BRAINPOOLP256R1_SUPPORT DISABLED
// brainpoolP384r1 elliptic curve support
#define TLS_BRAINPOOLP384R1_SUPPORT DISABLED
// brainpoolP512r1 elliptic curve support
#define TLS_BRAINPOOLP512R1_SUPPORT DISABLED
// Curve25519 elliptic curve support
#define TLS_X25519_SUPPORT ENABLED
// Curve448 elliptic curve support
#define TLS_X448_SUPPORT DISABLED
// Ed25519 elliptic curve support
#define TLS_ED25519_SUPPORT DISABLED
// Ed448 elliptic curve support
#define TLS_ED448_SUPPORT DISABLED

#endif
