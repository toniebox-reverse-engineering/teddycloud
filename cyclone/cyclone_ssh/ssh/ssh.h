/**
 * @file ssh.h
 * @brief Secure Shell (SSH)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSH Open.
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

#ifndef _SSH_H
#define _SSH_H

//Dependencies
#include "ssh_config.h"
#include "ssh_legacy.h"
#include "ssh_types.h"
#include "ssh_cert_parse.h"
#include "core/net.h"
#include "core/crypto.h"
#include "cipher/cipher_algorithms.h"
#include "cipher_modes/cipher_modes.h"
#include "hash/hash_algorithms.h"
#include "mac/mac_algorithms.h"
#include "aead/aead_algorithms.h"
#include "pkc/dh.h"
#include "ecc/ecdh.h"


/*
 * CycloneSSH Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneCRYPTO Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneCRYPTO Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneCRYPTO Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#ifndef GPL_LICENSE_TERMS_ACCEPTED
   #error Before compiling CycloneSSH Open, you must accept the terms of the GPL license
#endif

//Version string
#define CYCLONE_SSH_VERSION_STRING "2.2.0"
//Major version
#define CYCLONE_SSH_MAJOR_VERSION 2
//Minor version
#define CYCLONE_SSH_MINOR_VERSION 2
//Revision number
#define CYCLONE_SSH_REV_NUMBER 0

//SSH support
#ifndef SSH_SUPPORT
   #define SSH_SUPPORT ENABLED
#elif (SSH_SUPPORT != ENABLED && SSH_SUPPORT != DISABLED)
   #error SSH_SUPPORT parameter is not valid
#endif

//SSH client support
#ifndef SSH_CLIENT_SUPPORT
   #define SSH_CLIENT_SUPPORT ENABLED
#elif (SSH_CLIENT_SUPPORT != ENABLED && SSH_CLIENT_SUPPORT != DISABLED)
   #error SSH_CLIENT_SUPPORT parameter is not valid
#endif

//SSH server support
#ifndef SSH_SERVER_SUPPORT
   #define SSH_SERVER_SUPPORT ENABLED
#elif (SSH_SERVER_SUPPORT != ENABLED && SSH_SERVER_SUPPORT != DISABLED)
   #error SSH_SERVER_SUPPORT parameter is not valid
#endif

//Public key authentication support
#ifndef SSH_PUBLIC_KEY_AUTH_SUPPORT
   #define SSH_PUBLIC_KEY_AUTH_SUPPORT ENABLED
#elif (SSH_PUBLIC_KEY_AUTH_SUPPORT != ENABLED && SSH_PUBLIC_KEY_AUTH_SUPPORT != DISABLED)
   #error SSH_PUBLIC_KEY_AUTH_SUPPORT parameter is not valid
#endif

//Password authentication support
#ifndef SSH_PASSWORD_AUTH_SUPPORT
   #define SSH_PASSWORD_AUTH_SUPPORT ENABLED
#elif (SSH_PASSWORD_AUTH_SUPPORT != ENABLED && SSH_PASSWORD_AUTH_SUPPORT != DISABLED)
   #error SSH_PASSWORD_AUTH_SUPPORT parameter is not valid
#endif

//Certificate support (OpenSSH format)
#ifndef SSH_CERT_SUPPORT
   #define SSH_CERT_SUPPORT DISABLED
#elif (SSH_CERT_SUPPORT != ENABLED && SSH_CERT_SUPPORT != DISABLED)
   #error SSH_CERT_SUPPORT parameter is not valid
#endif

//Extension negotiation mechanism
#ifndef SSH_EXT_INFO_SUPPORT
   #define SSH_EXT_INFO_SUPPORT DISABLED
#elif (SSH_EXT_INFO_SUPPORT != ENABLED && SSH_EXT_INFO_SUPPORT != DISABLED)
   #error SSH_EXT_INFO_SUPPORT parameter is not valid
#endif

//"server-sig-algs" extension support
#ifndef SSH_SERVER_SIG_ALGS_EXT_SUPPORT
   #define SSH_SERVER_SIG_ALGS_EXT_SUPPORT ENABLED
#elif (SSH_SERVER_SIG_ALGS_EXT_SUPPORT != ENABLED && SSH_SERVER_SIG_ALGS_EXT_SUPPORT != DISABLED)
   #error SSH_SERVER_SIG_ALGS_EXT_SUPPORT parameter is not valid
#endif

//"global-requests-ok" extension support
#ifndef SSH_GLOBAL_REQ_OK_EXT_SUPPORT
   #define SSH_GLOBAL_REQ_OK_EXT_SUPPORT DISABLED
#elif (SSH_GLOBAL_REQ_OK_EXT_SUPPORT != ENABLED && SSH_GLOBAL_REQ_OK_EXT_SUPPORT != DISABLED)
   #error SSH_GLOBAL_REQ_OK_EXT_SUPPORT parameter is not valid
#endif

//Signature generation/verification callback functions
#ifndef SSH_SIGN_CALLBACK_SUPPORT
   #define SSH_SIGN_CALLBACK_SUPPORT DISABLED
#elif (SSH_SIGN_CALLBACK_SUPPORT != ENABLED && SSH_SIGN_CALLBACK_SUPPORT != DISABLED)
   #error SSH_SIGN_CALLBACK_SUPPORT parameter is not valid
#endif

//ECDH callback functions
#ifndef SSH_ECDH_CALLBACK_SUPPORT
   #define SSH_ECDH_CALLBACK_SUPPORT DISABLED
#elif (SSH_ECDH_CALLBACK_SUPPORT != ENABLED && SSH_ECDH_CALLBACK_SUPPORT != DISABLED)
   #error SSH_ECDH_CALLBACK_SUPPORT parameter is not valid
#endif

//Maximum number of keys the SSH entity can load
#ifndef SSH_MAX_HOST_KEYS
   #define SSH_MAX_HOST_KEYS 3
#elif (SSH_MAX_HOST_KEYS < 1)
   #error SSH_MAX_HOST_KEYS parameter is not valid
#endif

//Maximum number of simultaneous connections
#ifndef SSH_MAX_CONNECTIONS
   #define SSH_MAX_CONNECTIONS 10
#elif (SSH_MAX_CONNECTIONS < 1)
   #error SSH_MAX_CONNECTIONS parameter is not valid
#endif

//Maximum number of global request callbacks that can be attached
#ifndef SSH_MAX_GLOBAL_REQ_CALLBACKS
   #define SSH_MAX_GLOBAL_REQ_CALLBACKS 3
#elif (SSH_MAX_GLOBAL_REQ_CALLBACKS < 1)
   #error SSH_MAX_GLOBAL_REQ_CALLBACKS parameter is not valid
#endif

//Maximum number of channel request callbacks that can be attached
#ifndef SSH_MAX_CHANNEL_REQ_CALLBACKS
   #define SSH_MAX_CHANNEL_REQ_CALLBACKS 3
#elif (SSH_MAX_CHANNEL_REQ_CALLBACKS < 1)
   #error SSH_MAX_CHANNEL_REQ_CALLBACKS parameter is not valid
#endif

//Maximum number of channel open callbacks that can be attached
#ifndef SSH_MAX_CHANNEL_OPEN_CALLBACKS
   #define SSH_MAX_CHANNEL_OPEN_CALLBACKS 1
#elif (SSH_MAX_CHANNEL_OPEN_CALLBACKS < 1)
   #error SSH_MAX_CHANNEL_OPEN_CALLBACKS parameter is not valid
#endif

//Maximum number of connection open callbacks that can be attached
#ifndef SSH_MAX_CONN_OPEN_CALLBACKS
   #define SSH_MAX_CONN_OPEN_CALLBACKS 1
#elif (SSH_MAX_CONN_OPEN_CALLBACKS < 1)
   #error SSH_MAX_CONN_OPEN_CALLBACKS parameter is not valid
#endif

//Maximum number of connection close callbacks that can be attached
#ifndef SSH_MAX_CONN_CLOSE_CALLBACKS
   #define SSH_MAX_CONN_CLOSE_CALLBACKS 1
#elif (SSH_MAX_CONN_CLOSE_CALLBACKS < 1)
   #error SSH_MAX_CONN_CLOSE_CALLBACKS parameter is not valid
#endif

//Maximum number of authentication attempts
#ifndef SSH_MAX_AUTH_ATTEMPTS
   #define SSH_MAX_AUTH_ATTEMPTS 10
#elif (SSH_MAX_AUTH_ATTEMPTS < 1 && SSH_MAX_AUTH_ATTEMPTS > 20)
   #error SSH_MAX_AUTH_ATTEMPTS parameter is not valid
#endif

//Maximum packet size
#ifndef SSH_MAX_PACKET_SIZE
   #define SSH_MAX_PACKET_SIZE 2048
#elif (SSH_MAX_PACKET_SIZE < 128)
   #error SSH_MAX_PACKET_SIZE parameter is not valid
#endif

//Size of channel TX/RX buffers
#ifndef SSH_CHANNEL_BUFFER_SIZE
   #define SSH_CHANNEL_BUFFER_SIZE 2048
#elif (SSH_CHANNEL_BUFFER_SIZE < 128)
   #error SSH_CHANNEL_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of identification string
#ifndef SSH_MAX_ID_LEN
   #define SSH_MAX_ID_LEN 80
#elif (SSH_MAX_ID_LEN < 1)
   #error SSH_MAX_ID_LEN parameter is not valid
#endif

//Maximum length of the user name
#ifndef SSH_MAX_USERNAME_LEN
   #define SSH_MAX_USERNAME_LEN 32
#elif (SSH_MAX_USERNAME_LEN < 0)
   #error SSH_MAX_USERNAME_LEN parameter is not valid
#endif

//Maximum length of the password
#ifndef SSH_MAX_PASSWORD_LEN
   #define SSH_MAX_PASSWORD_LEN 32
#elif (SSH_MAX_PASSWORD_LEN < 0)
   #error SSH_MAX_PASSWORD_LEN parameter is not valid
#endif

//Maximum length of password change prompt
#ifndef SSH_MAX_PASSWORD_CHANGE_PROMPT_LEN
   #define SSH_MAX_PASSWORD_CHANGE_PROMPT_LEN 0
#elif (SSH_MAX_PASSWORD_CHANGE_PROMPT_LEN < 0)
   #error SSH_MAX_PASSWORD_CHANGE_PROMPT_LEN parameter is not valid
#endif

//Encrypt-then-MAC mode support
#ifndef SSH_ETM_SUPPORT
   #define SSH_ETM_SUPPORT DISABLED
#elif (SSH_ETM_SUPPORT != ENABLED && SSH_ETM_SUPPORT != DISABLED)
   #error SSH_ETM_SUPPORT parameter is not valid
#endif

//Stream cipher support (insecure)
#ifndef SSH_STREAM_CIPHER_SUPPORT
   #define SSH_STREAM_CIPHER_SUPPORT DISABLED
#elif (SSH_STREAM_CIPHER_SUPPORT != ENABLED && SSH_STREAM_CIPHER_SUPPORT != DISABLED)
   #error SSH_STREAM_CIPHER_SUPPORT parameter is not valid
#endif

//CBC cipher mode support (weak)
#ifndef SSH_CBC_CIPHER_SUPPORT
   #define SSH_CBC_CIPHER_SUPPORT DISABLED
#elif (SSH_CBC_CIPHER_SUPPORT != ENABLED && SSH_CBC_CIPHER_SUPPORT != DISABLED)
   #error SSH_CBC_CIPHER_SUPPORT parameter is not valid
#endif

//CTR cipher mode support
#ifndef SSH_CTR_CIPHER_SUPPORT
   #define SSH_CTR_CIPHER_SUPPORT ENABLED
#elif (SSH_CTR_CIPHER_SUPPORT != ENABLED && SSH_CTR_CIPHER_SUPPORT != DISABLED)
   #error SSH_CTR_CIPHER_SUPPORT parameter is not valid
#endif

//GCM AEAD support (OpenSSH variant)
#ifndef SSH_GCM_CIPHER_SUPPORT
   #define SSH_GCM_CIPHER_SUPPORT ENABLED
#elif (SSH_GCM_CIPHER_SUPPORT != ENABLED && SSH_GCM_CIPHER_SUPPORT != DISABLED)
   #error SSH_GCM_CIPHER_SUPPORT parameter is not valid
#endif

//GCM AEAD support (RFC 5647 variant)
#ifndef SSH_RFC5647_SUPPORT
   #define SSH_RFC5647_SUPPORT DISABLED
#elif (SSH_RFC5647_SUPPORT != ENABLED && SSH_RFC5647_SUPPORT != DISABLED)
   #error SSH_RFC5647_SUPPORT parameter is not valid
#endif

//ChaCha20Poly1305 AEAD support
#ifndef SSH_CHACHA20_POLY1305_SUPPORT
   #define SSH_CHACHA20_POLY1305_SUPPORT DISABLED
#elif (SSH_CHACHA20_POLY1305_SUPPORT != ENABLED && SSH_CHACHA20_POLY1305_SUPPORT != DISABLED)
   #error SSH_CHACHA20_POLY1305_SUPPORT parameter is not valid
#endif

//RC4 128-bit cipher support (insecure)
#ifndef SSH_RC4_128_SUPPORT
   #define SSH_RC4_128_SUPPORT DISABLED
#elif (SSH_RC4_128_SUPPORT != ENABLED && SSH_RC4_128_SUPPORT != DISABLED)
   #error SSH_RC4_128_SUPPORT parameter is not valid
#endif

//RC4 256-bit cipher support (insecure)
#ifndef SSH_RC4_256_SUPPORT
   #define SSH_RC4_256_SUPPORT DISABLED
#elif (SSH_RC4_256_SUPPORT != ENABLED && SSH_RC4_256_SUPPORT != DISABLED)
   #error SSH_RC4_256_SUPPORT parameter is not valid
#endif

//CAST-128 cipher support (insecure)
#ifndef SSH_CAST128_SUPPORT
   #define SSH_CAST128_SUPPORT DISABLED
#elif (SSH_CAST128_SUPPORT != ENABLED && SSH_CAST128_SUPPORT != DISABLED)
   #error SSH_CAST128_SUPPORT parameter is not valid
#endif

//IDEA cipher support (insecure)
#ifndef SSH_IDEA_SUPPORT
   #define SSH_IDEA_SUPPORT DISABLED
#elif (SSH_IDEA_SUPPORT != ENABLED && SSH_IDEA_SUPPORT != DISABLED)
   #error SSH_IDEA_SUPPORT parameter is not valid
#endif

//Blowfish cipher support (insecure)
#ifndef SSH_BLOWFISH_SUPPORT
   #define SSH_BLOWFISH_SUPPORT DISABLED
#elif (SSH_BLOWFISH_SUPPORT != ENABLED && SSH_BLOWFISH_SUPPORT != DISABLED)
   #error SSH_BLOWFISH_SUPPORT parameter is not valid
#endif

//Triple DES cipher support (weak)
#ifndef SSH_3DES_SUPPORT
   #define SSH_3DES_SUPPORT DISABLED
#elif (SSH_3DES_SUPPORT != ENABLED && SSH_3DES_SUPPORT != DISABLED)
   #error SSH_3DES_SUPPORT parameter is not valid
#endif

//AES 128-bit cipher support
#ifndef SSH_AES_128_SUPPORT
   #define SSH_AES_128_SUPPORT ENABLED
#elif (SSH_AES_128_SUPPORT != ENABLED && SSH_AES_128_SUPPORT != DISABLED)
   #error SSH_AES_128_SUPPORT parameter is not valid
#endif

//AES 192-bit cipher support
#ifndef SSH_AES_192_SUPPORT
   #define SSH_AES_192_SUPPORT ENABLED
#elif (SSH_AES_192_SUPPORT != ENABLED && SSH_AES_192_SUPPORT != DISABLED)
   #error SSH_AES_192_SUPPORT parameter is not valid
#endif

//AES 256-bit cipher support
#ifndef SSH_AES_256_SUPPORT
   #define SSH_AES_256_SUPPORT ENABLED
#elif (SSH_AES_256_SUPPORT != ENABLED && SSH_AES_256_SUPPORT != DISABLED)
   #error SSH_AES_256_SUPPORT parameter is not valid
#endif

//Twofish 128-bit cipher support
#ifndef SSH_TWOFISH_128_SUPPORT
   #define SSH_TWOFISH_128_SUPPORT DISABLED
#elif (SSH_TWOFISH_128_SUPPORT != ENABLED && SSH_TWOFISH_128_SUPPORT != DISABLED)
   #error SSH_TWOFISH_128_SUPPORT parameter is not valid
#endif

//Twofish 192-bit cipher support
#ifndef SSH_TWOFISH_192_SUPPORT
   #define SSH_TWOFISH_192_SUPPORT DISABLED
#elif (SSH_TWOFISH_192_SUPPORT != ENABLED && SSH_TWOFISH_192_SUPPORT != DISABLED)
   #error SSH_TWOFISH_192_SUPPORT parameter is not valid
#endif

//Twofish 256-bit cipher support
#ifndef SSH_TWOFISH_256_SUPPORT
   #define SSH_TWOFISH_256_SUPPORT DISABLED
#elif (SSH_TWOFISH_256_SUPPORT != ENABLED && SSH_TWOFISH_256_SUPPORT != DISABLED)
   #error SSH_TWOFISH_256_SUPPORT parameter is not valid
#endif

//Serpent 128-bit cipher support
#ifndef SSH_SERPENT_128_SUPPORT
   #define SSH_SERPENT_128_SUPPORT DISABLED
#elif (SSH_SERPENT_128_SUPPORT != ENABLED && SSH_SERPENT_128_SUPPORT != DISABLED)
   #error SSH_SERPENT_128_SUPPORT parameter is not valid
#endif

//Serpent 192-bit cipher support
#ifndef SSH_SERPENT_192_SUPPORT
   #define SSH_SERPENT_192_SUPPORT DISABLED
#elif (SSH_SERPENT_192_SUPPORT != ENABLED && SSH_SERPENT_192_SUPPORT != DISABLED)
   #error SSH_SERPENT_192_SUPPORT parameter is not valid
#endif

//Serpent 256-bit cipher support
#ifndef SSH_SERPENT_256_SUPPORT
   #define SSH_SERPENT_256_SUPPORT DISABLED
#elif (SSH_SERPENT_256_SUPPORT != ENABLED && SSH_SERPENT_256_SUPPORT != DISABLED)
   #error SSH_SERPENT_256_SUPPORT parameter is not valid
#endif

//Camellia 128-bit cipher support
#ifndef SSH_CAMELLIA_128_SUPPORT
   #define SSH_CAMELLIA_128_SUPPORT DISABLED
#elif (SSH_CAMELLIA_128_SUPPORT != ENABLED && SSH_CAMELLIA_128_SUPPORT != DISABLED)
   #error SSH_CAMELLIA_128_SUPPORT parameter is not valid
#endif

//Camellia 192-bit cipher support
#ifndef SSH_CAMELLIA_192_SUPPORT
   #define SSH_CAMELLIA_192_SUPPORT DISABLED
#elif (SSH_CAMELLIA_192_SUPPORT != ENABLED && SSH_CAMELLIA_192_SUPPORT != DISABLED)
   #error SSH_CAMELLIA_192_SUPPORT parameter is not valid
#endif

//Camellia 256-bit cipher support
#ifndef SSH_CAMELLIA_256_SUPPORT
   #define SSH_CAMELLIA_256_SUPPORT DISABLED
#elif (SSH_CAMELLIA_256_SUPPORT != ENABLED && SSH_CAMELLIA_256_SUPPORT != DISABLED)
   #error SSH_CAMELLIA_256_SUPPORT parameter is not valid
#endif

//SEED cipher support
#ifndef SSH_SEED_SUPPORT
   #define SSH_SEED_SUPPORT DISABLED
#elif (SSH_SEED_SUPPORT != ENABLED && SSH_SEED_SUPPORT != DISABLED)
   #error SSH_SEED_SUPPORT parameter is not valid
#endif

//MD5 hash support (insecure)
#ifndef SSH_MD5_SUPPORT
   #define SSH_MD5_SUPPORT DISABLED
#elif (SSH_MD5_SUPPORT != ENABLED && SSH_MD5_SUPPORT != DISABLED)
   #error SSH_MD5_SUPPORT parameter is not valid
#endif

//MD5/96 hash support (insecure)
#ifndef SSH_MD5_96_SUPPORT
   #define SSH_MD5_96_SUPPORT DISABLED
#elif (SSH_MD5_96_SUPPORT != ENABLED && SSH_MD5_96_SUPPORT != DISABLED)
   #error SSH_MD5_96_SUPPORT parameter is not valid
#endif

//RIPEMD-160 hash support (weak)
#ifndef SSH_RIPEMD160_SUPPORT
   #define SSH_RIPEMD160_SUPPORT DISABLED
#elif (SSH_RIPEMD160_SUPPORT != ENABLED && SSH_RIPEMD160_SUPPORT != DISABLED)
   #error SSH_RIPEMD160_SUPPORT parameter is not valid
#endif

//SHA-1 hash support (weak)
#ifndef SSH_SHA1_SUPPORT
   #define SSH_SHA1_SUPPORT ENABLED
#elif (SSH_SHA1_SUPPORT != ENABLED && SSH_SHA1_SUPPORT != DISABLED)
   #error SSH_SHA1_SUPPORT parameter is not valid
#endif

//SHA-1/96 hash support (insecure)
#ifndef SSH_SHA1_96_SUPPORT
   #define SSH_SHA1_96_SUPPORT DISABLED
#elif (SSH_SHA1_96_SUPPORT != ENABLED && SSH_SHA1_96_SUPPORT != DISABLED)
   #error SSH_SHA1_96_SUPPORT parameter is not valid
#endif

//SHA-224 hash support (weak)
#ifndef SSH_SHA224_SUPPORT
   #define SSH_SHA224_SUPPORT DISABLED
#elif (SSH_SHA224_SUPPORT != ENABLED && SSH_SHA224_SUPPORT != DISABLED)
   #error SSH_SHA224_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef SSH_SHA256_SUPPORT
   #define SSH_SHA256_SUPPORT ENABLED
#elif (SSH_SHA256_SUPPORT != ENABLED && SSH_SHA256_SUPPORT != DISABLED)
   #error SSH_SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef SSH_SHA384_SUPPORT
   #define SSH_SHA384_SUPPORT ENABLED
#elif (SSH_SHA384_SUPPORT != ENABLED && SSH_SHA384_SUPPORT != DISABLED)
   #error SSH_SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef SSH_SHA512_SUPPORT
   #define SSH_SHA512_SUPPORT ENABLED
#elif (SSH_SHA512_SUPPORT != ENABLED && SSH_SHA512_SUPPORT != DISABLED)
   #error SSH_SHA512_SUPPORT parameter is not valid
#endif

//RSA key exchange support
#ifndef SSH_RSA_KEX_SUPPORT
   #define SSH_RSA_KEX_SUPPORT DISABLED
#elif (SSH_RSA_KEX_SUPPORT != ENABLED && SSH_RSA_KEX_SUPPORT != DISABLED)
   #error SSH_RSA_KEX_SUPPORT parameter is not valid
#endif

//Diffie-Hellman key exchange support
#ifndef SSH_DH_KEX_SUPPORT
   #define SSH_DH_KEX_SUPPORT ENABLED
#elif (SSH_DH_KEX_SUPPORT != ENABLED && SSH_DH_KEX_SUPPORT != DISABLED)
   #error SSH_DH_KEX_SUPPORT parameter is not valid
#endif

//DH GEX key exchange support
#ifndef SSH_DH_GEX_KEX_SUPPORT
   #define SSH_DH_GEX_KEX_SUPPORT DISABLED
#elif (SSH_DH_GEX_KEX_SUPPORT != ENABLED && SSH_DH_GEX_KEX_SUPPORT != DISABLED)
   #error SSH_DH_GEX_KEX_SUPPORT parameter is not valid
#endif

//ECDH key exchange support
#ifndef SSH_ECDH_KEX_SUPPORT
   #define SSH_ECDH_KEX_SUPPORT ENABLED
#elif (SSH_ECDH_KEX_SUPPORT != ENABLED && SSH_ECDH_KEX_SUPPORT != DISABLED)
   #error SSH_ECDH_KEX_SUPPORT parameter is not valid
#endif

//Post-quantum hybrid key exchange support
#ifndef SSH_HBR_KEX_SUPPORT
   #define SSH_HBR_KEX_SUPPORT DISABLED
#elif (SSH_HBR_KEX_SUPPORT != ENABLED && SSH_HBR_KEX_SUPPORT != DISABLED)
   #error SSH_HBR_KEX_SUPPORT parameter is not valid
#endif

//RSA signature support
#ifndef SSH_RSA_SIGN_SUPPORT
   #define SSH_RSA_SIGN_SUPPORT ENABLED
#elif (SSH_RSA_SIGN_SUPPORT != ENABLED && SSH_RSA_SIGN_SUPPORT != DISABLED)
   #error SSH_RSA_SIGN_SUPPORT parameter is not valid
#endif

//DSA signature support
#ifndef SSH_DSA_SIGN_SUPPORT
   #define SSH_DSA_SIGN_SUPPORT ENABLED
#elif (SSH_DSA_SIGN_SUPPORT != ENABLED && SSH_DSA_SIGN_SUPPORT != DISABLED)
   #error SSH_DSA_SIGN_SUPPORT parameter is not valid
#endif

//ECDSA signature support
#ifndef SSH_ECDSA_SIGN_SUPPORT
   #define SSH_ECDSA_SIGN_SUPPORT ENABLED
#elif (SSH_ECDSA_SIGN_SUPPORT != ENABLED && SSH_ECDSA_SIGN_SUPPORT != DISABLED)
   #error SSH_ECDSA_SIGN_SUPPORT parameter is not valid
#endif

//Ed25519 signature support
#ifndef SSH_ED25519_SIGN_SUPPORT
   #define SSH_ED25519_SIGN_SUPPORT ENABLED
#elif (SSH_ED25519_SIGN_SUPPORT != ENABLED && SSH_ED25519_SIGN_SUPPORT != DISABLED)
   #error SSH_ED25519_SIGN_SUPPORT parameter is not valid
#endif

//Ed448 signature support
#ifndef SSH_ED448_SIGN_SUPPORT
   #define SSH_ED448_SIGN_SUPPORT DISABLED
#elif (SSH_ED448_SIGN_SUPPORT != ENABLED && SSH_ED448_SIGN_SUPPORT != DISABLED)
   #error SSH_ED448_SIGN_SUPPORT parameter is not valid
#endif

//NIST P-256 elliptic curve support
#ifndef SSH_NISTP256_SUPPORT
   #define SSH_NISTP256_SUPPORT ENABLED
#elif (SSH_NISTP256_SUPPORT != ENABLED && SSH_NISTP256_SUPPORT != DISABLED)
   #error SSH_NISTP256_SUPPORT parameter is not valid
#endif

//NIST P-384 elliptic curve support
#ifndef SSH_NISTP384_SUPPORT
   #define SSH_NISTP384_SUPPORT ENABLED
#elif (SSH_NISTP384_SUPPORT != ENABLED && SSH_NISTP384_SUPPORT != DISABLED)
   #error SSH_NISTP384_SUPPORT parameter is not valid
#endif

//NIST P-521 elliptic curve support
#ifndef SSH_NISTP521_SUPPORT
   #define SSH_NISTP521_SUPPORT ENABLED
#elif (SSH_NISTP521_SUPPORT != ENABLED && SSH_NISTP521_SUPPORT != DISABLED)
   #error SSH_NISTP521_SUPPORT parameter is not valid
#endif

//Curve25519 elliptic curve support
#ifndef SSH_CURVE25519_SUPPORT
   #define SSH_CURVE25519_SUPPORT ENABLED
#elif (SSH_CURVE25519_SUPPORT != ENABLED && SSH_CURVE25519_SUPPORT != DISABLED)
   #error SSH_CURVE25519_SUPPORT parameter is not valid
#endif

//Curve448 elliptic curve support
#ifndef SSH_CURVE448_SUPPORT
   #define SSH_CURVE448_SUPPORT DISABLED
#elif (SSH_CURVE448_SUPPORT != ENABLED && SSH_CURVE448_SUPPORT != DISABLED)
   #error SSH_CURVE448_SUPPORT parameter is not valid
#endif

//Streamlined NTRU Prime support
#ifndef SSH_SNTRUP761_SUPPORT
   #define SSH_SNTRUP761_SUPPORT DISABLED
#elif (SSH_SNTRUP761_SUPPORT != ENABLED && SSH_SNTRUP761_SUPPORT != DISABLED)
   #error SSH_SNTRUP761_SUPPORT parameter is not valid
#endif

//Maximum number of transient RSA keys that can be loaded
#ifndef SSH_MAX_RSA_KEYS
   #define SSH_MAX_RSA_KEYS 2
#elif (SSH_MAX_RSA_KEYS < 1)
   #error SSH_MAX_RSA_KEYS parameter is not valid
#endif

//Maximum number of Diffie-Hellman groups that can be loaded
#ifndef SSH_MAX_DH_GEX_GROUPS
   #define SSH_MAX_DH_GEX_GROUPS 2
#elif (SSH_MAX_DH_GEX_GROUPS < 1)
   #error SSH_MAX_DH_GEX_GROUPS parameter is not valid
#endif

//Minimum acceptable size for Diffie-Hellman prime modulus
#ifndef SSH_MIN_DH_MODULUS_SIZE
   #define SSH_MIN_DH_MODULUS_SIZE 1024
#elif (SSH_MIN_DH_MODULUS_SIZE < 1024)
   #error SSH_MIN_DH_MODULUS_SIZE parameter is not valid
#endif

//Preferred size for Diffie-Hellman prime modulus
#ifndef SSH_PREFERRED_DH_MODULUS_SIZE
   #define SSH_PREFERRED_DH_MODULUS_SIZE 2048
#elif (SSH_PREFERRED_DH_MODULUS_SIZE < SSH_MIN_DH_MODULUS_SIZE)
   #error SSH_PREFERRED_DH_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for Diffie-Hellman prime modulus
#ifndef SSH_MAX_DH_MODULUS_SIZE
   #define SSH_MAX_DH_MODULUS_SIZE 3072
#elif (SSH_MAX_DH_MODULUS_SIZE < SSH_PREFERRED_DH_MODULUS_SIZE)
   #error SSH_MAX_DH_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for RSA modulus
#ifndef SSH_MIN_RSA_MODULUS_SIZE
   #define SSH_MIN_RSA_MODULUS_SIZE 1024
#elif (SSH_MIN_RSA_MODULUS_SIZE < 512)
   #error SSH_MIN_RSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for RSA modulus
#ifndef SSH_MAX_RSA_MODULUS_SIZE
   #define SSH_MAX_RSA_MODULUS_SIZE 4096
#elif (SSH_MAX_RSA_MODULUS_SIZE < SSH_MIN_RSA_MODULUS_SIZE)
   #error SSH_MAX_RSA_MODULUS_SIZE parameter is not valid
#endif

//Minimum acceptable size for DSA prime modulus
#ifndef SSH_MIN_DSA_MODULUS_SIZE
   #define SSH_MIN_DSA_MODULUS_SIZE 1024
#elif (SSH_MIN_DSA_MODULUS_SIZE < 512)
   #error SSH_MIN_DSA_MODULUS_SIZE parameter is not valid
#endif

//Maximum acceptable size for DSA prime modulus
#ifndef SSH_MAX_DSA_MODULUS_SIZE
   #define SSH_MAX_DSA_MODULUS_SIZE 4096
#elif (SSH_MAX_DSA_MODULUS_SIZE < SSH_MIN_DSA_MODULUS_SIZE)
   #error SSH_MAX_DSA_MODULUS_SIZE parameter is not valid
#endif

//Allocate memory block
#ifndef sshAllocMem
   #define sshAllocMem(size) osAllocMem(size)
#endif

//Deallocate memory block
#ifndef sshFreeMem
   #define sshFreeMem(p) osFreeMem(p)
#endif

//HMAC support
#if (SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   #define SSH_HMAC_SUPPORT ENABLED
#elif (SSH_CBC_CIPHER_SUPPORT == ENABLED)
   #define SSH_HMAC_SUPPORT ENABLED
#elif (SSH_CTR_CIPHER_SUPPORT == ENABLED)
   #define SSH_HMAC_SUPPORT ENABLED
#else
   #define SSH_HMAC_SUPPORT DISABLED
#endif

//Maximum key size (encryption algorithms)
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   #define SSH_MAX_ENC_KEY_SIZE 64
#else
   #define SSH_MAX_ENC_KEY_SIZE 32
#endif

//Maximum block size (encryption algorithms)
#if (SSH_AES_128_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE AES_BLOCK_SIZE
#elif (SSH_AES_192_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE AES_BLOCK_SIZE
#elif (SSH_AES_256_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE AES_BLOCK_SIZE
#elif (SSH_TWOFISH_128_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE TWOFISH_BLOCK_SIZE
#elif (SSH_TWOFISH_192_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE TWOFISH_BLOCK_SIZE
#elif (SSH_TWOFISH_256_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE TWOFISH_BLOCK_SIZE
#elif (SSH_SERPENT_128_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE SERPENT_BLOCK_SIZE
#elif (SSH_SERPENT_192_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE SERPENT_BLOCK_SIZE
#elif (SSH_SERPENT_256_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE SERPENT_BLOCK_SIZE
#elif (SSH_CAMELLIA_128_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE CAMELLIA_BLOCK_SIZE
#elif (SSH_CAMELLIA_192_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE CAMELLIA_BLOCK_SIZE
#elif (SSH_CAMELLIA_256_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE CAMELLIA_BLOCK_SIZE
#elif (SSH_SEED_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE SEED_BLOCK_SIZE
#elif (SSH_CAST128_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE CAST128_BLOCK_SIZE
#elif (SSH_IDEA_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE IDEA_BLOCK_SIZE
#elif (SSH_BLOWFISH_SUPPORT == ENABLED)
   #define SSH_MAX_CIPHER_BLOCK_SIZE BLOWFISH_BLOCK_SIZE
#else
   #define SSH_MAX_CIPHER_BLOCK_SIZE DES3_BLOCK_SIZE
#endif

//Maximum digest size (MAC algorithms)
#if (SSH_SHA512_SUPPORT == ENABLED)
   #define SSH_MAX_HASH_DIGEST_SIZE SHA512_DIGEST_SIZE
#elif (SSH_SHA384_SUPPORT == ENABLED)
   #define SSH_MAX_HASH_DIGEST_SIZE SHA384_DIGEST_SIZE
#elif (SSH_SHA256_SUPPORT == ENABLED)
   #define SSH_MAX_HASH_DIGEST_SIZE SHA256_DIGEST_SIZE
#elif (SSH_SHA1_SUPPORT == ENABLED || SSH_SHA1_96_SUPPORT == ENABLED)
   #define SSH_MAX_HASH_DIGEST_SIZE SHA1_DIGEST_SIZE
#elif (SSH_RIPEMD160_SUPPORT == ENABLED)
   #define SSH_MAX_HASH_DIGEST_SIZE RIPEMD160_DIGEST_SIZE
#else
   #define SSH_MAX_HASH_DIGEST_SIZE MD5_DIGEST_SIZE
#endif

//Maximum shared secret length (RSA key exchange)
#if (SSH_RSA_KEX_SUPPORT == ENABLED)
   #define SSH_MAX_RSA_SHARED_SECRET_LEN ((SSH_MAX_RSA_MODULUS_SIZE + 47) / 8)
#else
   #define SSH_MAX_RSA_SHARED_SECRET_LEN 0
#endif

//Maximum shared secret length (Diffie-Hellman key exchange)
#if (SSH_DH_KEX_SUPPORT == ENABLED || SSH_DH_GEX_KEX_SUPPORT == ENABLED)
   #define SSH_MAX_DH_SHARED_SECRET_LEN ((SSH_MAX_DH_MODULUS_SIZE + 47) / 8)
#else
   #define SSH_MAX_DH_SHARED_SECRET_LEN 0
#endif

//Maximum shared secret length (ECDH key exchange)
#if (SSH_ECDH_KEX_SUPPORT == ENABLED && SSH_NISTP521_SUPPORT == ENABLED)
   #define SSH_MAX_ECDH_SHARED_SECRET_LEN 71
#elif (SSH_ECDH_KEX_SUPPORT == ENABLED && SSH_CURVE448_SUPPORT == ENABLED)
   #define SSH_MAX_ECDH_SHARED_SECRET_LEN 61
#elif (SSH_ECDH_KEX_SUPPORT == ENABLED && SSH_NISTP384_SUPPORT == ENABLED)
   #define SSH_MAX_ECDH_SHARED_SECRET_LEN 53
#else
   #define SSH_MAX_ECDH_SHARED_SECRET_LEN 37
#endif

//Maximum shared secret length (PQ-hybrid key exchange)
#if (SSH_HBR_KEX_SUPPORT == ENABLED)
   #define SSH_MAX_HBR_SHARED_SECRET_LEN 68
#else
   #define SSH_MAX_HBR_SHARED_SECRET_LEN 0
#endif

//Maximum shared secret length
#if (SSH_MAX_RSA_SHARED_SECRET_LEN >= SSH_MAX_DH_SHARED_SECRET_LEN && \
   SSH_MAX_RSA_SHARED_SECRET_LEN >= SSH_MAX_ECDH_SHARED_SECRET_LEN && \
   SSH_MAX_RSA_SHARED_SECRET_LEN >= SSH_MAX_HBR_SHARED_SECRET_LEN)
   #define SSH_MAX_SHARED_SECRET_LEN SSH_MAX_RSA_SHARED_SECRET_LEN
#elif (SSH_MAX_DH_SHARED_SECRET_LEN >= SSH_MAX_RSA_SHARED_SECRET_LEN && \
   SSH_MAX_DH_SHARED_SECRET_LEN >= SSH_MAX_ECDH_SHARED_SECRET_LEN && \
   SSH_MAX_DH_SHARED_SECRET_LEN >= SSH_MAX_HBR_SHARED_SECRET_LEN)
   #define SSH_MAX_SHARED_SECRET_LEN SSH_MAX_DH_SHARED_SECRET_LEN
#elif (SSH_MAX_ECDH_SHARED_SECRET_LEN >= SSH_MAX_RSA_SHARED_SECRET_LEN && \
   SSH_MAX_ECDH_SHARED_SECRET_LEN >= SSH_MAX_DH_SHARED_SECRET_LEN && \
   SSH_MAX_ECDH_SHARED_SECRET_LEN >= SSH_MAX_HBR_SHARED_SECRET_LEN)
   #define SSH_MAX_SHARED_SECRET_LEN SSH_MAX_ECDH_SHARED_SECRET_LEN
#else
   #define SSH_MAX_SHARED_SECRET_LEN SSH_MAX_HBR_SHARED_SECRET_LEN
#endif

//SSH port number
#define SSH_PORT 22

//Cookie size
#define SSH_COOKIE_SIZE 16
//Data overhead caused by mpint encoding
#define SSH_MAX_MPINT_OVERHEAD 5
//Data overhead caused by packet encryption
#define SSH_MAX_PACKET_OVERHEAD 128

//Size of buffer used for input/output operations
#define SSH_BUFFER_SIZE (SSH_MAX_PACKET_SIZE + SSH_MAX_PACKET_OVERHEAD)

//Forward declaration of SshContext structure
struct _SshContext;
#define SshContext struct _SshContext

//Forward declaration of SshConnection structure
struct _SshConnection;
#define SshConnection struct _SshConnection

//Forward declaration of SshChannel structure
struct _SshChannel;
#define SshChannel struct _SshChannel

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Mode of operation
 **/

typedef enum
{
   SSH_OPERATION_MODE_CLIENT = 0,
   SSH_OPERATION_MODE_SERVER = 1
} SshOperationMode;


/**
 * @brief Authentication status
 **/

typedef enum
{
   SSH_AUTH_STATUS_FAILURE          = 0,
   SSH_AUTH_STATUS_SUCCESS          = 1,
   SSH_AUTH_STATUS_PASSWORD_EXPIRED = 2
} SshAuthStatus;


/**
 * @brief Flags used by read and write functions
 **/

typedef enum
{
   SSH_FLAG_EOF        = 0x0100,
   SSH_FLAG_WAIT_ALL   = 0x0800,
   SSH_FLAG_BREAK_CHAR = 0x1000,
   SSH_FLAG_BREAK_CRLF = 0x100A,
   SSH_FLAG_NO_DELAY   = 0x4000,
   SSH_FLAG_DELAY      = 0x8000
} SshChannelFlags;

//The SSH_FLAG_BREAK macro causes the read function to stop reading
//data whenever the specified break character is encountered
#define SSH_FLAG_BREAK(c) (SSH_FLAG_BREAK_CHAR | LSB(c))


/**
 * @brief SSH message types
 **/

typedef enum
{
   SSH_MSG_INVALID                   = 0,
   SSH_MSG_DISCONNECT                = 1,
   SSH_MSG_IGNORE                    = 2,
   SSH_MSG_UNIMPLEMENTED             = 3,
   SSH_MSG_DEBUG                     = 4,
   SSH_MSG_SERVICE_REQUEST           = 5,
   SSH_MSG_SERVICE_ACCEPT            = 6,
   SSH_MSG_EXT_INFO                  = 7,
   SSH_MSG_NEWCOMPRESS               = 8,
   SSH_MSG_KEXINIT                   = 20,
   SSH_MSG_NEWKEYS                   = 21,
   SSH_MSG_KEX_MIN                   = 30,
   SSH_MSG_KEX_MAX                   = 49,
   SSH_MSG_KEXRSA_PUBKEY             = 30,
   SSH_MSG_KEXRSA_SECRET             = 31,
   SSH_MSG_KEXRSA_DONE               = 32,
   SSH_MSG_KEX_DH_INIT               = 30,
   SSH_MSG_KEX_DH_REPLY              = 31,
   SSH_MSG_KEX_DH_GEX_REQUEST_OLD    = 30,
   SSH_MSG_KEX_DH_GEX_REQUEST        = 34,
   SSH_MSG_KEX_DH_GEX_GROUP          = 31,
   SSH_MSG_KEX_DH_GEX_INIT           = 32,
   SSH_MSG_KEX_DH_GEX_REPLY          = 33,
   SSH_MSG_KEX_ECDH_INIT             = 30,
   SSH_MSG_KEX_ECDH_REPLY            = 31,
   SSH_MSG_HBR_INIT                  = 30,
   SSH_MSG_HBR_REPLY                 = 31,
   SSH_MSG_USERAUTH_REQUEST          = 50,
   SSH_MSG_USERAUTH_FAILURE          = 51,
   SSH_MSG_USERAUTH_SUCCESS          = 52,
   SSH_MSG_USERAUTH_BANNER           = 53,
   SSH_MSG_USERAUTH_MIN              = 60,
   SSH_MSG_USERAUTH_MAX              = 79,
   SSH_MSG_USERAUTH_PK_OK            = 60,
   SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60,
   SSH_MSG_USERAUTH_INFO_REQUEST     = 60,
   SSH_MSG_USERAUTH_INFO_RESPONSE    = 61,
   SSH_MSG_GLOBAL_REQUEST            = 80,
   SSH_MSG_REQUEST_SUCCESS           = 81,
   SSH_MSG_REQUEST_FAILURE           = 82,
   SSH_MSG_CHANNEL_OPEN              = 90,
   SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
   SSH_MSG_CHANNEL_OPEN_FAILURE      = 92,
   SSH_MSG_CHANNEL_WINDOW_ADJUST     = 93,
   SSH_MSG_CHANNEL_DATA              = 94,
   SSH_MSG_CHANNEL_EXTENDED_DATA     = 95,
   SSH_MSG_CHANNEL_EOF               = 96,
   SSH_MSG_CHANNEL_CLOSE             = 97,
   SSH_MSG_CHANNEL_REQUEST           = 98,
   SSH_MSG_CHANNEL_SUCCESS           = 99,
   SSH_MSG_CHANNEL_FAILURE           = 100
} SshMessageType;


/**
 * @brief Disconnection messages reason codes
 **/

typedef enum
{
   SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    = 1,
   SSH_DISCONNECT_PROTOCOL_ERROR                 = 2,
   SSH_DISCONNECT_KEY_EXCHANGE_FAILED            = 3,
   SSH_DISCONNECT_RESERVED                       = 4,
   SSH_DISCONNECT_MAC_ERROR                      = 5,
   SSH_DISCONNECT_COMPRESSION_ERROR              = 6,
   SSH_DISCONNECT_SERVICE_NOT_AVAILABLE          = 7,
   SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
   SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        = 9,
   SSH_DISCONNECT_CONNECTION_LOST                = 10,
   SSH_DISCONNECT_BY_APPLICATION                 = 11,
   SSH_DISCONNECT_TOO_MANY_CONNECTIONS           = 12,
   SSH_DISCONNECT_AUTH_CANCELLED_BY_USER         = 13,
   SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
   SSH_DISCONNECT_ILLEGAL_USER_NAME              = 15
} SshDisconnectReasonCode;


/**
 * @brief Channel connection failure reason codes
 **/

typedef enum
{
   SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
   SSH_OPEN_CONNECT_FAILED              = 2,
   SSH_OPEN_UNKNOWN_CHANNEL_TYPE        = 3,
   SSH_OPEN_RESOURCE_SHORTAGE           = 4
} SshOpenFailureReasonCode;


/**
 * @brief SSH connection state
 **/

typedef enum
{
   SSH_CONN_STATE_CLOSED             = 0,
   SSH_CONN_STATE_CLIENT_ID          = 1,
   SSH_CONN_STATE_SERVER_ID          = 2,
   SSH_CONN_STATE_CLIENT_KEX_INIT    = 3,
   SSH_CONN_STATE_SERVER_KEX_INIT    = 4,
   SSH_CONN_STATE_KEX_RSA_PUB_KEY    = 5,
   SSH_CONN_STATE_KEX_RSA_SECRET     = 6,
   SSH_CONN_STATE_KEX_RSA_DONE       = 7,
   SSH_CONN_STATE_KEX_DH_INIT        = 8,
   SSH_CONN_STATE_KEX_DH_REPLY       = 9,
   SSH_CONN_STATE_KEX_DH_GEX_REQUEST = 10,
   SSH_CONN_STATE_KEX_DH_GEX_GROUP   = 11,
   SSH_CONN_STATE_KEX_DH_GEX_INIT    = 12,
   SSH_CONN_STATE_KEX_DH_GEX_REPLY   = 13,
   SSH_CONN_STATE_KEX_ECDH_INIT      = 14,
   SSH_CONN_STATE_KEX_ECDH_REPLY     = 15,
   SSH_CONN_STATE_KEX_HBR_INIT       = 16,
   SSH_CONN_STATE_KEX_HBR_REPLY      = 17,
   SSH_CONN_STATE_CLIENT_NEW_KEYS    = 18,
   SSH_CONN_STATE_SERVER_NEW_KEYS    = 19,
   SSH_CONN_STATE_CLIENT_EXT_INFO    = 20,
   SSH_CONN_STATE_SERVER_EXT_INFO_1  = 21,
   SSH_CONN_STATE_SERVER_EXT_INFO_2  = 22,
   SSH_CONN_STATE_SERVICE_REQUEST    = 23,
   SSH_CONN_STATE_SERVICE_ACCEPT     = 24,
   SSH_CONN_STATE_USER_AUTH_BANNER   = 25,
   SSH_CONN_STATE_USER_AUTH_REQUEST  = 26,
   SSH_CONN_STATE_USER_AUTH_REPLY    = 27,
   SSH_CONN_STATE_USER_AUTH_SUCCESS  = 28,
   SSH_CONN_STATE_OPEN               = 29,
   SSH_CONN_STATE_DISCONNECT         = 30
} SshConnectionState;


/**
 * @brief SSH channel state
 **/

typedef enum
{
   SSH_CHANNEL_STATE_UNUSED   = 0,
   SSH_CHANNEL_STATE_RESERVED = 1,
   SSH_CHANNEL_STATE_OPEN     = 2,
   SSH_CHANNEL_STATE_CLOSED   = 3
} SshChannelState;


/**
 * @brief SSH request states
 **/

typedef enum
{
   SSH_REQUEST_STATE_IDLE    = 0,
   SSH_REQUEST_STATE_PENDING = 1,
   SSH_REQUEST_STATE_SUCCESS = 2,
   SSH_REQUEST_STATE_FAILURE = 3
} SshRequestState;


/**
 * @brief SSH channel events
 **/

typedef enum
{
   SSH_CHANNEL_EVENT_TIMEOUT     = 0x0000,
   SSH_CHANNEL_EVENT_CONNECTED   = 0x0001,
   SSH_CHANNEL_EVENT_CLOSED      = 0x0002,
   SSH_CHANNEL_EVENT_TX_READY    = 0x0004,
   SSH_CHANNEL_EVENT_TX_DONE     = 0x0008,
   SSH_CHANNEL_EVENT_TX_ACKED    = 0x0010,
   SSH_CHANNEL_EVENT_TX_SHUTDOWN = 0x0020,
   SSH_CHANNEL_EVENT_RX_READY    = 0x0040,
   SSH_CHANNEL_EVENT_RX_SHUTDOWN = 0x0080,
} SshChannelEvent;


/**
 * @brief Transient RSA key (for RSA key exchange)
 **/

typedef struct
{
   uint_t modulusSize;       ///<Length of the modulus, in bits
   const char_t *publicKey;  ///<RSA public key (PEM, SSH2 or OpenSSH format)
   size_t publicKeyLen;      ///<Length of the RSA public key
   const char_t *privateKey; ///<RSA private key (PEM or OpenSSH format)
   size_t privateKeyLen;     ///<Length of the RSA private key
} SshRsaKey;


/**
 * @brief Diffie-Hellman group
 **/

typedef struct
{
   uint_t dhModulusSize;   ///<Length of the prime modulus, in bits
   const char_t *dhParams; ///<Diffie-Hellman parameters (PEM format)
   size_t dhParamsLen;     ///<Length of the Diffie-Hellman parameters
} SshDhGexGroup;


/**
 * @brief Host key
 **/

typedef struct
{
   const char_t *keyFormatId;   ///<Key format identifier
   const char_t *publicKey;     ///<Public key (PEM, SSH2 or OpenSSH format)
   size_t publicKeyLen;         ///<Length of the public key
   const char_t *privateKey;    ///<Private key (PEM or OpenSSH format)
   size_t privateKeyLen;        ///<Length of the private key
#if (SSH_CLIENT_SUPPORT == ENABLED)
   const char_t *publicKeyAlgo; ///<Public key algorithm to use during user authentication
#endif
} SshHostKey;


/**
 * @brief Host key algorithm
 **/

typedef struct
{
   const char_t *publicKeyAlgo; ///<Public key algorithm
   const char_t *keyFormatId;   ///<Key format identifier
   const char_t *signFormatId;  ///<Signature format identifier
} SshHostKeyAlgo;


/**
 * @brief Host key verification callback function
 **/

typedef error_t (*SshHostKeyVerifyCallback)(SshConnection *connection,
   const uint8_t *hostKey, size_t hostKeyLen);


/**
 * @brief Certificate verification callback function
 **/

typedef error_t (*SshCertVerifyCallback)(SshConnection *connection,
   const SshCertificate *cert);


/**
 * @brief CA public key verification callback function
 **/

typedef error_t (*SshCaPublicKeyVerifyCallback)(SshConnection *connection,
   const uint8_t *publicKey, size_t publicKeyLen);


/**
 * @brief Public key authentication callback function
 **/

typedef error_t (*SshPublicKeyAuthCallback)(SshConnection *connection,
   const char_t *user, const uint8_t *publicKey, size_t publicKeyLen);


/**
 * @brief Certificate authentication callback function
 **/

typedef error_t (*SshCertAuthCallback)(SshConnection *connection,
   const char_t *user, const SshCertificate *cert);


/**
 * @brief Password authentication callback function
 **/

typedef SshAuthStatus (*SshPasswordAuthCallback)(SshConnection *connection,
   const char_t *user, const char_t *password, size_t passwordLen);


/**
 * @brief Password change callback function
 **/

typedef SshAuthStatus (*SshPasswordChangeCallback)(SshConnection *connection,
   const char_t *user, const char_t *oldPassword, size_t oldPasswordLen,
   const char_t *newPassword, size_t newPasswordLen);


/**
 * @brief Signature generation callback function
 **/

typedef error_t (*SshSignGenCallback)(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written);


/**
 * @brief Signature verification callback function
 **/

typedef error_t (*SshSignVerifyCallback)(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKeyBlob,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   const SshBinaryString *signatureBlob);


/**
 * @brief ECDH key pair generation callback
 **/

typedef error_t (*SshEcdhKeyPairGenCallback)(SshConnection *connection,
   const char_t *kexAlgo, EcPublicKey *publicKey);


/**
 * @brief ECDH shared secret calculation callback
 **/

typedef error_t (*SshEcdhSharedSecretCalcCallback)(SshConnection *connection,
   const char_t *kexAlgo, const EcPublicKey *publicKey, uint8_t *output,
   size_t *outputLen);


/**
 * @brief Global request callback function
 **/

typedef error_t (*SshGlobalReqCallback)(SshConnection *connection,
   const SshString *name, const uint8_t *data, size_t length, void *param);


/**
 * @brief Channel request callback function
 **/

typedef error_t (*SshChannelReqCallback)(SshChannel *channel,
   const SshString *type, const uint8_t *data, size_t length, void *param);


/**
 * @brief Channel open callback function
 **/

typedef error_t (*SshChannelOpenCallback)(SshConnection *connection,
   const SshString *type, uint32_t senderChannel, uint32_t initialWindowSize,
   uint32_t maxPacketSize, const uint8_t *data, size_t length, void *param);


/**
 * @brief Connection open callback function
 **/

typedef error_t (*SshConnectionOpenCallback)(SshConnection *connection,
   void *param);


/**
 * @brief Connection close callback function
 **/

typedef void (*SshConnectionCloseCallback)(SshConnection *connection,
   void *param);


/**
 * @brief Encryption engine
 **/

typedef struct
{
   CipherMode cipherMode;                    ///<Cipher mode of operation
   const CipherAlgo *cipherAlgo;             ///<Cipher algorithm
   CipherContext cipherContext;              ///<Cipher context
   const HashAlgo *hashAlgo;                 ///<Hash algorithm for MAC operations
   HmacContext *hmacContext;                 ///<HMAC context
   size_t macSize;                           ///<Size of the MAC tag, in bytes
   bool_t etm;                               ///<Encrypt-then-MAC
   uint8_t iv[SSH_MAX_CIPHER_BLOCK_SIZE];    ///<Initialization vector
   uint8_t encKey[SSH_MAX_ENC_KEY_SIZE];     ///<Encryption key
   size_t encKeyLen;                         ///<Length of the encryption key, in bytes
   uint8_t macKey[SSH_MAX_HASH_DIGEST_SIZE]; ///<Integrity key
   uint8_t seqNum[4];                        ///<Sequence number
#if (SSH_GCM_CIPHER_SUPPORT == ENABLED || SSH_RFC5647_SUPPORT == ENABLED)
   GcmContext gcmContext;                    ///<GCM context
#endif
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   uint8_t aad[4];                           ///<Additional authenticated data
#endif
} SshEncryptionEngine;


/**
 * @brief SSH channel buffer
 **/

typedef struct
{
   char_t data[SSH_CHANNEL_BUFFER_SIZE]; ///<Data buffer
   size_t length;
   size_t threshold;
   size_t writePos;
   size_t readPos;
} SshChannelBuffer;


/**
 * @brief SSH channel
 **/

struct _SshChannel
{
   SshChannelState state;        ///<Channel state
   SshRequestState requestState; ///<Channel request state
   SshContext *context;          ///<SSH context
   SshConnection *connection;    ///<SSH connection
   OsEvent event;
   uint_t eventMask;
   uint_t eventFlags;
   OsEvent *userEvent;
   systime_t timeout;            ///<Timeout value
   uint32_t localChannelNum;     ///<Local channel number
   uint32_t remoteChannelNum;    ///<Remote channel number
   uint32_t maxPacketSize;       ///<Maximum packet size
   SshChannelBuffer txBuffer;    ///<TX buffer
   SshChannelBuffer rxBuffer;    ///<RX buffer
   size_t txWindowSize;          ///<TX flow-control window
   size_t rxWindowSize;          ///<RX flow-control window
   size_t rxWindowSizeInc;       ///<Window size increment
   bool_t channelSuccessSent;    ///<An SSH_MSG_CHANNEL_SUCCESS message has been sent
   bool_t eofRequest;            ///<Channel EOF request
   bool_t eofSent;               ///<An SSH_MSG_CHANNEL_EOF message has been sent
   bool_t eofReceived;           ///<An SSH_MSG_CHANNEL_EOF message has been received
   bool_t closeRequest;          ///<Channel close request
   bool_t closeSent;             ///<An SSH_MSG_CHANNEL_CLOSE message has been sent
   bool_t closeReceived;         ///<An SSH_MSG_CHANNEL_CLOSE message has been received
};


/**
 * @brief SSH connection
 **/

struct _SshConnection
{
   SshConnectionState state;                    ///<Connection state
   SshRequestState requestState;                ///<Global request state
   SshContext *context;                         ///<SSH context
   Socket *socket;                              ///<Underlying socket
   systime_t timestamp;                         ///<Time stamp to manage connection timeout

   char_t clientId[SSH_MAX_ID_LEN + 1];         ///<Client's identification string
   char_t serverId[SSH_MAX_ID_LEN + 1];         ///<Server's identification string
   uint8_t cookie[SSH_COOKIE_SIZE];             ///<Random value generated by the sender
   char_t user[SSH_MAX_USERNAME_LEN + 1];       ///<User name

#if (SSH_SERVER_SUPPORT == ENABLED && SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
   char_t passwordChangePrompt[SSH_MAX_PASSWORD_CHANGE_PROMPT_LEN + 1]; ///<Password change prompt string
#endif

   const char_t *kexAlgo;                       ///<Selected key exchange algorithm name
   const char_t *serverHostKeyAlgo;             ///<Selected server's host key algorithm name
   const char_t *clientEncAlgo;                 ///<Selected client's encryption algorithm name
   const char_t *serverEncAlgo;                 ///<Selected server's encryption algorithm name
   const char_t *clientMacAlgo;                 ///<Selected client's MAC algorithm name
   const char_t *serverMacAlgo;                 ///<Selected server's MAC algorithm name
   const char_t *clientCompressAlgo;            ///<Selected client's encryption algorithm name
   const char_t *serverCompressAlgo;            ///<Selected server's encryption algorithm name
   int_t hostKeyIndex;                          ///<Index of the selected host key
#if (SSH_RSA_KEX_SUPPORT == ENABLED)
   int_t rsaKeyIndex;                           ///<Index of the transient RSA key to use
   uint8_t *serverHostKey;                      ///<Server's host key
   size_t serverHostKeyLen;                     ///<Length of the server's host key, in bytes
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED)
   int_t dhGexGroupIndex;                       ///<Index of the selected Diffie-Hellman group
#endif

   uint8_t sessionId[SSH_MAX_HASH_DIGEST_SIZE]; ///<Session identifier
   size_t sessionIdLen;                         ///<Length of the session identifier, in bytes
   uint8_t h[SSH_MAX_HASH_DIGEST_SIZE];         ///<Exchange hash H
   size_t hLen;                                 ///<Length of the exchange hash, in bytes
   uint8_t k[SSH_MAX_SHARED_SECRET_LEN];        ///<Shared secret K
   size_t kLen;                                 ///<Length of the shared secret, in bytes

   const HashAlgo *hashAlgo;                    ///<Exchange hash algorithm
   HashContext hashContext;                     ///<Exchange hash context
#if (SSH_HMAC_SUPPORT == ENABLED)
   HmacContext hmacContext;                     ///<HMAC context
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED || SSH_DH_GEX_KEX_SUPPORT == ENABLED)
   DhContext dhContext;                         ///<Diffie-Hellman context
#endif
#if (SSH_ECDH_KEX_SUPPORT == ENABLED || SSH_HBR_KEX_SUPPORT == ENABLED)
   EcdhContext ecdhContext;                     ///<ECDH context
#endif

   SshEncryptionEngine encryptionEngine;        ///<Encryption engine
   SshEncryptionEngine decryptionEngine;        ///<Decryption engine

   bool_t kexInitSent;                          ///<An SSH_MSG_KEXINIT message has been sent
   bool_t kexInitReceived;                      ///<An SSH_MSG_KEXINIT message has been received
   bool_t newKeysSent;                          ///<An SSH_MSG_NEWKEYS message has been sent
   bool_t newKeysReceived;                      ///<An SSH_MSG_NEWKEYS message has been received
   bool_t disconnectRequest;                    ///<Request for disconnection
   bool_t disconnectSent;                       ///<An SSH_MSG_DISCONNECT message has been sent
   bool_t disconnectReceived;                   ///<An SSH_MSG_DISCONNECT message has been received
   bool_t wrongGuess;                           ///<A wrong guessed key exchange packet follows
   uint_t authAttempts;                         ///<Number of authentication attempts
   bool_t publicKeyOk;                          ///<The provided host key is acceptable
   uint32_t localChannelNum;                    ///<Current channel number

#if (SSH_EXT_INFO_SUPPORT == ENABLED)
   bool_t extInfoReceived;                      ///<"ext-info-c" or "ext-info-s" indicator has been received
#endif

   uint8_t buffer[SSH_BUFFER_SIZE];             ///<Internal buffer
   size_t txBufferLen;                          ///<Number of bytes that are pending to be sent
   size_t txBufferPos;                          ///<Current position in TX buffer
   size_t rxBufferLen;                          ///<Number of bytes available for reading
   size_t rxBufferPos;                          ///<Current position in RX buffer
};


/**
 * @brief SSH context
 **/

struct _SshContext
{
   SshOperationMode mode;                                        ///<Mode of operation (client or server)
   uint_t numConnections;                                        ///<Maximum number of SSH connections
   SshConnection *connections;                                   ///<SSH connections
   uint_t numChannels;                                           ///<Maximum number of SSH channels
   SshChannel *channels;                                         ///<SSH channels
   const PrngAlgo *prngAlgo;                                     ///<Pseudo-random number generator to be used
   void *prngContext;                                            ///<Pseudo-random number generator context
   SshHostKey hostKeys[SSH_MAX_HOST_KEYS];                       ///<List of host keys

#if (SSH_CLIENT_SUPPORT == ENABLED)
   char_t username[SSH_MAX_USERNAME_LEN + 1];                    ///<User name
   char_t password[SSH_MAX_PASSWORD_LEN + 1];                    ///<Password
#endif

#if (SSH_SERVER_SUPPORT == ENABLED && SSH_RSA_KEX_SUPPORT == ENABLED)
   SshRsaKey rsaKeys[SSH_MAX_RSA_KEYS];                         ///<Transient RSA keys (for RSA key exchange)
#endif
#if (SSH_SERVER_SUPPORT == ENABLED && SSH_DH_GEX_KEX_SUPPORT == ENABLED)
   SshDhGexGroup dhGexGroups[SSH_MAX_DH_GEX_GROUPS];            ///<Diffie-Hellman groups
#endif

   SshHostKeyVerifyCallback hostKeyVerifyCallback;               ///<Host key verification callback
#if (SSH_CERT_SUPPORT == ENABLED)
   SshCertVerifyCallback certVerifyCallback;                     ///<Certificate verification callback
   SshCaPublicKeyVerifyCallback caPublicKeyVerifyCallback;       ///<CA public key verification callback
#endif
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
   SshPublicKeyAuthCallback publicKeyAuthCallback;               ///<Public key authentication callback
#endif
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)
   SshCertAuthCallback certAuthCallback;                         ///<Certificate authentication callback
#endif
#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
   SshPasswordAuthCallback passwordAuthCallback;                 ///<Password authentication callback
   SshPasswordChangeCallback passwordChangeCallback;             ///<Password change callback
#endif
#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
   SshSignGenCallback signGenCallback;                           ///<Signature generation callback
   SshSignVerifyCallback signVerifyCallback;                     ///<Signature verification callback
#endif
#if (SSH_ECDH_CALLBACK_SUPPORT == ENABLED)
   SshEcdhKeyPairGenCallback ecdhKeyPairGenCallback;             ///<ECDH key pair generation callback
   SshEcdhSharedSecretCalcCallback ecdhSharedSecretCalcCallback; ///<ECDH shared secret calculation callback
#endif
   SshGlobalReqCallback globalReqCallback[SSH_MAX_GLOBAL_REQ_CALLBACKS];             ///<Global request callbacks
   void *globalReqParam[SSH_MAX_GLOBAL_REQ_CALLBACKS];                               ///<Opaque pointer passed to the global request callback
   SshChannelReqCallback channelReqCallback[SSH_MAX_CHANNEL_REQ_CALLBACKS];          ///<Channel request callbacks
   void *channelReqParam[SSH_MAX_CHANNEL_REQ_CALLBACKS];                             ///<Opaque pointer passed to the channel request callback
   SshChannelOpenCallback channelOpenCallback[SSH_MAX_CHANNEL_OPEN_CALLBACKS];       ///<Channel open callbacks
   void *channelOpenParam[SSH_MAX_CHANNEL_OPEN_CALLBACKS];                           ///<Opaque pointer passed to the channel open callback
   SshConnectionOpenCallback connectionOpenCallback[SSH_MAX_CONN_OPEN_CALLBACKS];    ///<Connection open callback function
   void *connectionOpenParam[SSH_MAX_CONN_OPEN_CALLBACKS];                           ///<Opaque pointer passed to the connection open callback
   SshConnectionCloseCallback connectionCloseCallback[SSH_MAX_CONN_CLOSE_CALLBACKS]; ///<Connection close callback function
   void *connectionCloseParam[SSH_MAX_CONN_CLOSE_CALLBACKS];                         ///<Opaque pointer passed to the connection close callback

   OsMutex mutex;                                                ///<Mutex preventing simultaneous access to the context
   OsEvent event;                                                ///<Event object used to poll the sockets
   SocketEventDesc eventDesc[SSH_MAX_CONNECTIONS + 1];           ///<The events the application is interested in
};


/**
 * @brief Structure describing channel events
 **/

typedef struct
{
   SshChannel *channel; ///<Handle to a channel to monitor
   uint_t eventMask;    ///<Requested events
   uint_t eventFlags;   ///<Returned events
} SshChannelEventDesc;


//SSH related functions
error_t sshInit(SshContext *context, SshConnection *connections,
   uint_t numConnections, SshChannel *channels, uint_t numChannels);

error_t sshSetOperationMode(SshContext *context, SshOperationMode mode);

error_t sshSetPrng(SshContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t sshSetUsername(SshContext *context, const char_t *username);
error_t sshSetPassword(SshContext *context, const char_t *password);

error_t sshRegisterHostKeyVerifyCallback(SshContext *context,
   SshHostKeyVerifyCallback callback);

error_t sshRegisterCertVerifyCallback(SshContext *context,
   SshCertVerifyCallback callback);

error_t sshRegisterCaPublicKeyVerifyCallback(SshContext *context,
   SshCaPublicKeyVerifyCallback callback);

error_t sshRegisterPublicKeyAuthCallback(SshContext *context,
   SshPublicKeyAuthCallback callback);

error_t sshRegisterCertAuthCallback(SshContext *context,
   SshCertAuthCallback callback);

error_t sshRegisterPasswordAuthCallback(SshContext *context,
   SshPasswordAuthCallback callback);

error_t sshRegisterPasswordChangeCallback(SshContext *context,
   SshPasswordChangeCallback callback);

error_t sshRegisterSignGenCallback(SshContext *context,
   SshSignGenCallback callback);

error_t sshRegisterSignVerifyCallback(SshContext *context,
   SshSignVerifyCallback callback);

error_t sshRegisterEcdhKeyPairGenCallback(SshContext *context,
   SshEcdhKeyPairGenCallback callback);

error_t sshRegisterEcdhSharedSecretCalcCallback(SshContext *context,
   SshEcdhSharedSecretCalcCallback callback);

error_t sshRegisterGlobalRequestCallback(SshContext *context,
   SshGlobalReqCallback callback, void *param);

error_t sshUnregisterGlobalRequestCallback(SshContext *context,
   SshGlobalReqCallback callback);

error_t sshRegisterChannelRequestCallback(SshContext *context,
   SshChannelReqCallback callback, void *param);

error_t sshUnregisterChannelRequestCallback(SshContext *context,
   SshChannelReqCallback callback);

error_t sshRegisterChannelOpenCallback(SshContext *context,
   SshChannelOpenCallback callback, void *param);

error_t sshUnregisterChannelOpenCallback(SshContext *context,
   SshChannelOpenCallback callback);

error_t sshRegisterConnectionOpenCallback(SshContext *context,
   SshConnectionOpenCallback callback, void *param);

error_t sshUnregisterConnectionOpenCallback(SshContext *context,
   SshConnectionOpenCallback callback);

error_t sshRegisterConnectionCloseCallback(SshContext *context,
   SshConnectionCloseCallback callback, void *param);

error_t sshUnregisterConnectionCloseCallback(SshContext *context,
   SshConnectionCloseCallback callback);

error_t sshLoadRsaKey(SshContext *context, uint_t index,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen);

error_t sshUnloadRsaKey(SshContext *context, uint_t index);

error_t sshLoadDhGexGroup(SshContext *context, uint_t index,
   const char_t *dhParams, size_t dhParamsLen);

error_t sshUnloadDhGexGroup(SshContext *context, uint_t index);

error_t sshLoadHostKey(SshContext *context, uint_t index,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen);

error_t sshUnloadHostKey(SshContext *context, uint_t index);

error_t sshLoadCertificate(SshContext *context, uint_t index,
   const char_t *cert, size_t certLen, const char_t *privateKey,
   size_t privateKeyLen);

error_t sshUnloadCertificate(SshContext *context, uint_t index);

error_t sshSetPasswordChangePrompt(SshConnection *connection,
   const char_t *prompt);

SshChannel *sshCreateChannel(SshConnection *connection);

error_t sshSetChannelTimeout(SshChannel *channel, systime_t timeout);

error_t sshWriteChannel(SshChannel *channel, const void *data, size_t length,
   size_t *written, uint_t flags);

error_t sshReadChannel(SshChannel *channel, void *data, size_t size,
   size_t *received, uint_t flags);

error_t sshPollChannels(SshChannelEventDesc *eventDesc, uint_t size,
   OsEvent *extEvent, systime_t timeout);

error_t sshCloseChannel(SshChannel *channel);
void sshDeleteChannel(SshChannel *channel);

void sshDeinit(SshContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
