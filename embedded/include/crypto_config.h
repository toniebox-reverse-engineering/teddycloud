/**
 * @file crypto_config.h
 * @brief CycloneCRYPTO configuration file
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

#ifndef _CRYPTO_CONFIG_H
#define _CRYPTO_CONFIG_H

// Desired trace level (for debugging purposes)
#define CRYPTO_TRACE_LEVEL TRACE_LEVEL_INFO

// Multiple precision integer support
#define MPI_SUPPORT ENABLED
// Assembly optimizations for time-critical routines
#define MPI_ASM_SUPPORT DISABLED

// Base64 encoding support
#define BASE64_SUPPORT ENABLED
// Base64url encoding support
#define BASE64URL_SUPPORT DISABLED

// MD2 hash support
#define MD2_SUPPORT DISABLED
// MD4 hash support
#define MD4_SUPPORT DISABLED
// MD5 hash support
#define MD5_SUPPORT DISABLED
// RIPEMD-128 hash support
#define RIPEMD128_SUPPORT DISABLED
// RIPEMD-160 hash support
#define RIPEMD160_SUPPORT DISABLED
// SHA-1 hash support
#define SHA1_SUPPORT ENABLED
// SHA-224 hash support
#define SHA224_SUPPORT DISABLED
// SHA-256 hash support
#define SHA256_SUPPORT ENABLED
// SHA-384 hash support
#define SHA384_SUPPORT ENABLED
// SHA-512 hash support
#define SHA512_SUPPORT ENABLED
// SHA-512/224 hash support
#define SHA512_224_SUPPORT DISABLED
// SHA-512/256 hash support
#define SHA512_256_SUPPORT DISABLED
// SHA3-224 hash support
#define SHA3_224_SUPPORT DISABLED
// SHA3-256 hash support
#define SHA3_256_SUPPORT DISABLED
// SHA3-384 hash support
#define SHA3_384_SUPPORT DISABLED
// SHA3-512 hash support
#define SHA3_512_SUPPORT DISABLED
// SHAKE support
#define SHAKE_SUPPORT DISABLED
// cSHAKE support
#define CSHAKE_SUPPORT DISABLED
// Keccak support
#define KECCAK_SUPPORT DISABLED
// BLAKE2b support
#define BLAKE2B_SUPPORT DISABLED
// BLAKE2b-160 hash support
#define BLAKE2B160_SUPPORT DISABLED
// BLAKE2b-256 hash support
#define BLAKE2B256_SUPPORT DISABLED
// BLAKE2b-384 hash support
#define BLAKE2B384_SUPPORT DISABLED
// BLAKE2b-512 hash support
#define BLAKE2B512_SUPPORT DISABLED
// BLAKE2s support
#define BLAKE2S_SUPPORT DISABLED
// BLAKE2s-128 hash support
#define BLAKE2S128_SUPPORT DISABLED
// BLAKE2s-160 hash support
#define BLAKE2S160_SUPPORT DISABLED
// BLAKE2s-224 hash support
#define BLAKE2S224_SUPPORT DISABLED
// BLAKE2s-256 hash support
#define BLAKE2S256_SUPPORT DISABLED
// Tiger hash support
#define TIGER_SUPPORT DISABLED
// Whirlpool hash support
#define WHIRLPOOL_SUPPORT DISABLED

// CMAC support
#define CMAC_SUPPORT DISABLED
// HMAC support
#define HMAC_SUPPORT ENABLED
// GMAC support
#define GMAC_SUPPORT DISABLED
// KMAC support
#define KMAC_SUPPORT DISABLED

// RC2 support
#define RC2_SUPPORT DISABLED
// RC4 support
#define RC4_SUPPORT DISABLED
// RC6 support
#define RC6_SUPPORT DISABLED
// CAST-128 support
#define CAST128_SUPPORT DISABLED
// CAST-256 support
#define CAST256_SUPPORT DISABLED
// IDEA support
#define IDEA_SUPPORT DISABLED
// DES support
#define DES_SUPPORT DISABLED
// Triple DES support
#define DES3_SUPPORT DISABLED
// AES support
#define AES_SUPPORT ENABLED
// Blowfish support
#define BLOWFISH_SUPPORT DISABLED
// Twofish support
#define TWOFISH_SUPPORT DISABLED
// MARS support
#define MARS_SUPPORT DISABLED
// Serpent support
#define SERPENT_SUPPORT DISABLED
// Camellia support
#define CAMELLIA_SUPPORT DISABLED
// SEED support
#define SEED_SUPPORT DISABLED
// ARIA support
#define ARIA_SUPPORT DISABLED
// PRESENT support
#define PRESENT_SUPPORT DISABLED
// Trivium support
#define TRIVIUM_SUPPORT DISABLED

// ECB mode support
#define ECB_SUPPORT DISABLED
// CBC mode support
#define CBC_SUPPORT ENABLED
// CFB mode support
#define CFB_SUPPORT DISABLED
// OFB mode support
#define OFB_SUPPORT DISABLED
// CTR mode support
#define CTR_SUPPORT DISABLED
// XTS mode support
#define XTS_SUPPORT DISABLED
// CCM mode support
#define CCM_SUPPORT DISABLED
// GCM mode support
#define GCM_SUPPORT ENABLED

// ChaCha support
#define CHACHA_SUPPORT DISABLED
// Poly1305 support
#define POLY1305_SUPPORT DISABLED
// ChaCha20Poly1305 support
#define CHACHA20_POLY1305_SUPPORT DISABLED

// Diffie-Hellman support
#define DH_SUPPORT ENABLED
// RSA support
#define RSA_SUPPORT ENABLED
// DSA support
#define DSA_SUPPORT DISABLED

// Elliptic curve cryptography support
#define EC_SUPPORT ENABLED
// ECDH support
#define ECDH_SUPPORT ENABLED
// ECDSA support
#define ECDSA_SUPPORT DISABLED

// secp112r1 elliptic curve support
#define SECP112R1_SUPPORT DISABLED
// secp112r2 elliptic curve support
#define SECP112R2_SUPPORT DISABLED
// secp128r1 elliptic curve support
#define SECP128R1_SUPPORT DISABLED
// secp128r2 elliptic curve support
#define SECP128R2_SUPPORT DISABLED
// secp160k1 elliptic curve support
#define SECP160K1_SUPPORT DISABLED
// secp160r1 elliptic curve support
#define SECP160R1_SUPPORT DISABLED
// secp160r2 elliptic curve support
#define SECP160R2_SUPPORT DISABLED
// secp192k1 elliptic curve support
#define SECP192K1_SUPPORT DISABLED
// secp192r1 elliptic curve support (NIST P-192)
#define SECP192R1_SUPPORT DISABLED
// secp224k1 elliptic curve support
#define SECP224K1_SUPPORT DISABLED
// secp224r1 elliptic curve support (NIST P-224)
#define SECP224R1_SUPPORT ENABLED
// secp256k1 elliptic curve support
#define SECP256K1_SUPPORT DISABLED
// secp256r1 elliptic curve support (NIST P-256)
#define SECP256R1_SUPPORT ENABLED
// secp384r1 elliptic curve support (NIST P-384)
#define SECP384R1_SUPPORT DISABLED
// secp521r1 elliptic curve support (NIST P-521)
#define SECP521R1_SUPPORT DISABLED
// brainpoolP160r1 elliptic curve support
#define BRAINPOOLP160R1_SUPPORT DISABLED
// brainpoolP192r1 elliptic curve support
#define BRAINPOOLP192R1_SUPPORT DISABLED
// brainpoolP224r1 elliptic curve support
#define BRAINPOOLP224R1_SUPPORT DISABLED
// brainpoolP256r1 elliptic curve support
#define BRAINPOOLP256R1_SUPPORT DISABLED
// brainpoolP320r1 elliptic curve support
#define BRAINPOOLP320R1_SUPPORT DISABLED
// brainpoolP384r1 elliptic curve support
#define BRAINPOOLP384R1_SUPPORT DISABLED
// brainpoolP512r1 elliptic curve support
#define BRAINPOOLP512R1_SUPPORT DISABLED
// Curve25519 elliptic curve support
#define X25519_SUPPORT DISABLED
// Curve448 elliptic curve support
#define X448_SUPPORT DISABLED
// Ed25519 elliptic curve support
#define ED25519_SUPPORT DISABLED
// Ed448 elliptic curve support
#define ED448_SUPPORT DISABLED

// HKDF support
#define HKDF_SUPPORT DISABLED
// PBKDF support
#define PBKDF_SUPPORT DISABLED
// bcrypt support
#define BCRYPT_SUPPORT DISABLED
// scrypt support
#define SCRYPT_SUPPORT DISABLED

// RSA certificate support
#define X509_RSA_SUPPORT ENABLED
// RSA-PSS certificate support
#define X509_RSA_PSS_SUPPORT DISABLED
// DSA certificate support
#define X509_DSA_SUPPORT DISABLED
// Ed25519 certificate support
#define X509_ED25519_SUPPORT DISABLED
// Ed448 certificate support
#define X509_ED448_SUPPORT DISABLED

#endif
