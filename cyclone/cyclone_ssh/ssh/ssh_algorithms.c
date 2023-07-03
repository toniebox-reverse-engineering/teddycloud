/**
 * @file ssh_algorithms.c
 * @brief SSH algorithm negotiation
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_algorithms.h"
#include "ssh/ssh_kex_rsa.h"
#include "ssh/ssh_kex_dh_gex.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief List of supported key exchange algorithms
 **/

static const char_t *const sshSupportedKexAlgos[] =
{
#if (SSH_HBR_KEX_SUPPORT == ENABLED && SSH_SNTRUP761_SUPPORT == ENABLED && \
   SSH_CURVE25519_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   "sntrup761x25519-sha512@openssh.com",
#endif
#if (SSH_ECDH_KEX_SUPPORT == ENABLED && SSH_CURVE25519_SUPPORT == ENABLED && \
   SSH_SHA256_SUPPORT == ENABLED)
   "curve25519-sha256",
   "curve25519-sha256@libssh.org",
#endif
#if (SSH_ECDH_KEX_SUPPORT == ENABLED && SSH_CURVE448_SUPPORT == ENABLED && \
   SSH_SHA512_SUPPORT == ENABLED)
   "curve448-sha512",
#endif
#if (SSH_ECDH_KEX_SUPPORT == ENABLED && SSH_NISTP256_SUPPORT == ENABLED && \
   SSH_SHA256_SUPPORT == ENABLED)
   "ecdh-sha2-nistp256",
#endif
#if (SSH_ECDH_KEX_SUPPORT == ENABLED && SSH_NISTP384_SUPPORT == ENABLED && \
   SSH_SHA384_SUPPORT == ENABLED)
   "ecdh-sha2-nistp384",
#endif
#if (SSH_ECDH_KEX_SUPPORT == ENABLED && SSH_NISTP521_SUPPORT == ENABLED && \
   SSH_SHA512_SUPPORT == ENABLED)
   "ecdh-sha2-nistp521",
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   "diffie-hellman-group-exchange-sha256",
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED && SSH_SHA384_SUPPORT == ENABLED)
   "diffie-hellman-group-exchange-sha384@ssh.com",
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   "diffie-hellman-group-exchange-sha512@ssh.com",
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED && \
   SSH_MAX_DH_MODULUS_SIZE >= 2048 && SSH_MIN_DH_MODULUS_SIZE <= 2048)
   "diffie-hellman-group14-sha256",
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED && \
   SSH_MAX_DH_MODULUS_SIZE >= 3072 && SSH_MIN_DH_MODULUS_SIZE <= 3072)
   "diffie-hellman-group15-sha512",
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED && \
   SSH_MAX_DH_MODULUS_SIZE >= 4096 && SSH_MIN_DH_MODULUS_SIZE <= 4096)
   "diffie-hellman-group16-sha512",
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED && \
   SSH_MAX_DH_MODULUS_SIZE >= 6144 && SSH_MIN_DH_MODULUS_SIZE <= 6144)
   "diffie-hellman-group17-sha512",
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED && \
   SSH_MAX_DH_MODULUS_SIZE >= 8192 && SSH_MIN_DH_MODULUS_SIZE <= 8192)
   "diffie-hellman-group18-sha512",
#endif
#if (SSH_RSA_KEX_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED && \
   SSH_MAX_RSA_MODULUS_SIZE >= 2048)
   "rsa2048-sha256",
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED && SSH_SHA224_SUPPORT == ENABLED)
   "diffie-hellman-group-exchange-sha224@ssh.com",
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED)
   "diffie-hellman-group-exchange-sha1",
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED && \
   SSH_MAX_DH_MODULUS_SIZE >= 2048 && SSH_MIN_DH_MODULUS_SIZE <= 2048)
   "diffie-hellman-group14-sha1",
#endif
#if (SSH_DH_KEX_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED && \
   SSH_MAX_DH_MODULUS_SIZE >= 1024 && SSH_MIN_DH_MODULUS_SIZE <= 1024)
   "diffie-hellman-group1-sha1",
#endif
#if (SSH_RSA_KEX_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED && \
   SSH_MAX_RSA_MODULUS_SIZE >= 1024)
   "rsa1024-sha1",
#endif
};


/**
 * @brief List of supported host key algorithms
 **/

static const SshHostKeyAlgo sshSupportedHostKeyAlgos[] =
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)
   {
      "ssh-ed25519-cert-v01@openssh.com",
      "ssh-ed25519-cert-v01@openssh.com",
      "ssh-ed25519"
   },
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   {
      "ssh-ed25519",
      "ssh-ed25519",
      "ssh-ed25519"
   },
#endif
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   {
      "ssh-ed448",
      "ssh-ed448",
      "ssh-ed448"
   },
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP256_SUPPORT == ENABLED && \
   SSH_SHA256_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)
   {
      "ecdsa-sha2-nistp256-cert-v01@openssh.com",
      "ecdsa-sha2-nistp256-cert-v01@openssh.com",
      "ecdsa-sha2-nistp256"
   },
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP256_SUPPORT == ENABLED && \
   SSH_SHA256_SUPPORT == ENABLED)
   {
      "ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp256"
   },
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP384_SUPPORT == ENABLED && \
   SSH_SHA384_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)
   {
      "ecdsa-sha2-nistp384-cert-v01@openssh.com",
      "ecdsa-sha2-nistp384-cert-v01@openssh.com",
      "ecdsa-sha2-nistp384"
   },
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP384_SUPPORT == ENABLED && \
   SSH_SHA384_SUPPORT == ENABLED)
   {
      "ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp384"
   },
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP521_SUPPORT == ENABLED && \
   SSH_SHA512_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)
   {
      "ecdsa-sha2-nistp521-cert-v01@openssh.com",
      "ecdsa-sha2-nistp521-cert-v01@openssh.com",
      "ecdsa-sha2-nistp521"
   },
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP521_SUPPORT == ENABLED && \
   SSH_SHA512_SUPPORT == ENABLED)
   {
      "ecdsa-sha2-nistp521",
      "ecdsa-sha2-nistp521",
      "ecdsa-sha2-nistp521"
   },
#endif
#if (SSH_RSA_SIGN_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED && \
   SSH_CERT_SUPPORT == ENABLED)
   {
      "rsa-sha2-256-cert-v01@openssh.com",
      "ssh-rsa-cert-v01@openssh.com",
      "rsa-sha2-256"
   },
#endif
#if (SSH_RSA_SIGN_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   {
      "rsa-sha2-256",
      "ssh-rsa",
      "rsa-sha2-256"
   },
#endif
#if (SSH_RSA_SIGN_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED && \
   SSH_CERT_SUPPORT == ENABLED)
   {
      "rsa-sha2-512-cert-v01@openssh.com",
      "ssh-rsa-cert-v01@openssh.com",
      "rsa-sha2-512"
   },
#endif
#if (SSH_RSA_SIGN_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   {
      "rsa-sha2-512",
      "ssh-rsa",
      "rsa-sha2-512"
   },
#endif
#if (SSH_RSA_SIGN_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED && \
   SSH_CERT_SUPPORT == ENABLED)
   {
      "ssh-rsa-cert-v01@openssh.com",
      "ssh-rsa-cert-v01@openssh.com",
      "ssh-rsa"
   },
#endif
#if (SSH_RSA_SIGN_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED)
   {
      "ssh-rsa",
      "ssh-rsa",
      "ssh-rsa"
   },
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED && \
   SSH_CERT_SUPPORT == ENABLED)
   {
      "ssh-dss-cert-v01@openssh.com",
      "ssh-dss-cert-v01@openssh.com",
      "ssh-dss"
   },
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED)
   {
      "ssh-dss",
      "ssh-dss",
      "ssh-dss"
   },
#endif
};


/**
 * @brief List of supported encryption algorithms
 **/

static const char_t *const sshSupportedEncAlgos[] =
{
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   "chacha20-poly1305@openssh.com",
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_GCM_CIPHER_SUPPORT == ENABLED)
   "aes128-gcm@openssh.com",
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_GCM_CIPHER_SUPPORT == ENABLED)
   "aes256-gcm@openssh.com",
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   "AEAD_AES_128_GCM",
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   "AEAD_AES_256_GCM",
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   "AEAD_CAMELLIA_128_GCM",
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   "AEAD_CAMELLIA_256_GCM",
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "aes128-ctr",
#endif
#if (SSH_AES_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "aes192-ctr",
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "aes256-ctr",
#endif
#if (SSH_TWOFISH_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "twofish128-ctr",
#endif
#if (SSH_TWOFISH_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "twofish192-ctr",
#endif
#if (SSH_TWOFISH_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "twofish256-ctr",
#endif
#if (SSH_SERPENT_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "serpent128-ctr",
#endif
#if (SSH_SERPENT_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "serpent192-ctr",
#endif
#if (SSH_SERPENT_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "serpent256-ctr",
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "camellia128-ctr",
#endif
#if (SSH_CAMELLIA_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "camellia192-ctr",
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "camellia256-ctr",
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "aes128-cbc",
#endif
#if (SSH_AES_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "aes192-cbc",
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "aes256-cbc",
#endif
#if (SSH_TWOFISH_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "twofish128-cbc",
#endif
#if (SSH_TWOFISH_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "twofish192-cbc",
#endif
#if (SSH_TWOFISH_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "twofish256-cbc",
   "twofish-cbc",
#endif
#if (SSH_SERPENT_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "serpent128-cbc",
#endif
#if (SSH_SERPENT_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "serpent192-cbc",
#endif
#if (SSH_SERPENT_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "serpent256-cbc",
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "camellia128-cbc",
#endif
#if (SSH_CAMELLIA_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "camellia192-cbc",
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "camellia256-cbc",
#endif
#if (SSH_SEED_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "seed-cbc@ssh.com",
#endif
#if (SSH_3DES_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "3des-ctr",
#endif
#if (SSH_3DES_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "3des-cbc",
#endif
#if (SSH_BLOWFISH_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "blowfish-ctr",
#endif
#if (SSH_BLOWFISH_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "blowfish-cbc",
#endif
#if (SSH_IDEA_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "idea-ctr",
#endif
#if (SSH_IDEA_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "idea-cbc",
#endif
#if (SSH_CAST128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "cast128-ctr",
#endif
#if (SSH_CAST128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "cast128-cbc",
#endif
#if (SSH_RC4_256_SUPPORT == ENABLED && SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   "arcfour256",
#endif
#if (SSH_RC4_128_SUPPORT == ENABLED && SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   "arcfour128",
#endif
};


/**
 * @brief List of supported MAC algorithms
 **/

static const char_t *const sshSupportedMacAlgos[] =
{
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   "hmac-sha2-256-etm@openssh.com",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   "hmac-sha2-256",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   "hmac-sha2-512-etm@openssh.com",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   "hmac-sha2-512",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   "hmac-sha1-etm@openssh.com",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA1_SUPPORT == ENABLED)
   "hmac-sha1",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_RIPEMD160_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   "hmac-ripemd160-etm@openssh.com",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_RIPEMD160_SUPPORT == ENABLED)
   "hmac-ripemd160",
   "hmac-ripemd160@openssh.com",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_MD5_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   "hmac-md5-etm@openssh.com",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_MD5_SUPPORT == ENABLED)
   "hmac-md5",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA1_96_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   "hmac-sha1-96-etm@openssh.com",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_SHA1_96_SUPPORT == ENABLED)
   "hmac-sha1-96",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_MD5_96_SUPPORT == ENABLED && \
   SSH_ETM_SUPPORT == ENABLED)
   "hmac-md5-96-etm@openssh.com",
#endif
#if (SSH_HMAC_SUPPORT == ENABLED && SSH_MD5_96_SUPPORT == ENABLED)
   "hmac-md5-96",
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   "AEAD_AES_128_GCM",
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   "AEAD_AES_256_GCM",
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   "AEAD_CAMELLIA_128_GCM",
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_RFC5647_SUPPORT == ENABLED)
   "AEAD_CAMELLIA_256_GCM",
#endif
   ""
};


/**
 * @brief List of supported compression algorithms
 **/

static const char_t *const sshSupportedCompressionAlgos[] =
{
   "none"
};


/**
 * @brief Format the list of key exchange algorithms
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatKexAlgoList(SshConnection *connection, uint8_t *p,
   size_t *written)
{
   uint_t i;
   size_t n;
   bool_t acceptable;

   //The algorithm name-list is represented as a uint32 containing its length
   //followed by a comma-separated list of zero or more names
   n = sizeof(uint32_t);

   //Loop through the list of key exchange algorithms
   for(i = 0; i < arraysize(sshSupportedKexAlgos); i++)
   {
      //Initialize flag
      acceptable = FALSE;

#if (SSH_RSA_KEX_SUPPORT == ENABLED)
      //RSA key exchange algorithm?
      if(connection->context->mode == SSH_OPERATION_MODE_SERVER &&
         sshIsRsaKexAlgo(sshSupportedKexAlgos[i]))
      {
         //RSA algorithms can only be negotiated at server-side if a valid
         //transient RSA key has been loaded
         if(sshSelectTransientRsaKey(connection->context,
            sshSupportedKexAlgos[i]) >= 0)
         {
            acceptable = TRUE;
         }
      }
      else
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED)
      //DH GEX key exchange algorithm?
      if(connection->context->mode == SSH_OPERATION_MODE_SERVER &&
         sshIsDhGexKexAlgo(sshSupportedKexAlgos[i]))
      {
         //Diffie-Hellman Group Exchange algorithms can only be negotiated at
         //server-side if a valid group has been loaded
         if(sshSelectDhGexGroup(connection->context, SSH_MIN_DH_MODULUS_SIZE,
            SSH_PREFERRED_DH_MODULUS_SIZE, SSH_MAX_DH_MODULUS_SIZE) >= 0)
         {
            acceptable = TRUE;
         }
      }
      else
#endif
      //Diffie-Hellman or ECDH key exchange algorithm?
      {
         //The current key exchange algorithm is acceptable
         acceptable = TRUE;
      }

      //Acceptable key exchange algorithm?
      if(acceptable)
      {
         //Names are separated by commas
         if(n != sizeof(uint32_t))
         {
            p[n++] = ',';
         }

         //A name must have a non-zero length and it must not contain a comma
         osStrcpy((char_t *) p + n, sshSupportedKexAlgos[i]);

         //Update the length of the name list
         n += osStrlen(sshSupportedKexAlgos[i]);
      }
   }

#if (SSH_EXT_INFO_SUPPORT == ENABLED)
   //Applications implementing the extension negotiation mechanism must add an
   //indicator name to the field kex_algorithms in the SSH_MSG_KEXINIT message
   //sent by the application in the first key exchange (refer to RFC 8308,
   //section 2.1)
   if(!connection->newKeysSent)
   {
      const char_t *indicatorName;

      //Names are separated by commas
      if(n != sizeof(uint32_t))
      {
         p[n++] = ',';
      }

      //The indicator names inserted by the client and server are different
      //to ensure these names will not produce a match and therefore not
      //affect the algorithm chosen in key exchange algorithm negotiation
      if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         indicatorName = "ext-info-c";
      }
      else
      {
         indicatorName = "ext-info-s";
      }

      //The indicator name may be added at any position in the name-list
      osStrcpy((char_t *) p + n, indicatorName);

      //Update the length of the name list
      n += osStrlen(indicatorName);
   }
#endif

   //The name list is preceded by a uint32 containing its length
   STORE32BE(n - sizeof(uint32_t), p);

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format the list of host key algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatHostKeyAlgoList(SshContext *context, uint8_t *p,
   size_t *written)
{
   uint_t i;
   size_t n;
   const SshHostKeyAlgo *entry;

   //A name-list is represented as a uint32 containing its length followed
   //by a comma-separated list of zero or more names
   n = sizeof(uint32_t);

   //Loop through the supported host key algorithms
   for(i = 0; i < arraysize(sshSupportedHostKeyAlgos); i++)
   {
      //Point to the current entry
      entry = &sshSupportedHostKeyAlgos[i];

      //The client lists the algorithms that it is willing to accept. The
      //server lists the algorithms for which it has host keys (refer to
      //RFC 4253, section 7.1)
      if(context->mode == SSH_OPERATION_MODE_CLIENT ||
         sshSelectHostKey(context, entry->publicKeyAlgo) >= 0)
      {
         //Algorithm names are separated by commas
         if(n != sizeof(uint32_t))
         {
            p[n++] = ',';
         }

         //A name must have a non-zero length and it must not contain a comma
         osStrcpy((char_t *) p + n, entry->publicKeyAlgo);

         //Update the length of the name list
         n += osStrlen(entry->publicKeyAlgo);
      }
   }

   //The name list is preceded by a uint32 containing its length
   STORE32BE(n - sizeof(uint32_t), p);

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format the list of encryption algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatEncAlgoList(SshContext *context, uint8_t *p, size_t *written)
{
   //The algorithm name-list must be a comma-separated list of algorithm names.
   //Each supported algorithm must be listed in order of preference
   return sshFormatNameList(sshSupportedEncAlgos,
      arraysize(sshSupportedEncAlgos), p, written);
}


/**
 * @brief Format the list of integrity algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatMacAlgoList(SshContext *context, uint8_t *p, size_t *written)
{
   //The algorithm name-list must be a comma-separated list of algorithm names.
   //Each supported algorithm must be listed in order of preference
   return sshFormatNameList(sshSupportedMacAlgos,
      arraysize(sshSupportedMacAlgos) - 1, p, written);
}


/**
 * @brief Format the list of compression algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatCompressionAlgoList(SshContext *context, uint8_t *p,
   size_t *written)
{
   //The algorithm name-list must be a comma-separated list of algorithm names.
   //Each supported algorithm must be listed in order of preference
   return sshFormatNameList(sshSupportedCompressionAlgos,
      arraysize(sshSupportedCompressionAlgos), p, written);
}


/**
 * @brief Format the list of public key algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatPublicKeyAlgoList(SshContext *context, uint8_t *p,
   size_t *written)
{
   uint_t i;
   size_t n;
   const SshHostKeyAlgo *entry;

   //A name-list is represented as a uint32 containing its length followed
   //by a comma-separated list of zero or more names
   n = sizeof(uint32_t);

   //Enumerate all public key algorithms that are supported
   for(i = 0; i < arraysize(sshSupportedHostKeyAlgos); i++)
   {
      //Point to the current entry
      entry = &sshSupportedHostKeyAlgos[i];

      //Algorithm names are separated by commas
      if(n != sizeof(uint32_t))
      {
         p[n++] = ',';
      }

      //A name must have a non-zero length and it must not contain a comma
      osStrcpy((char_t *) p + n, entry->publicKeyAlgo);

      //Update the length of the name list
      n += osStrlen(entry->publicKeyAlgo);
   }

   //The name list is preceded by a uint32 containing its length
   STORE32BE(n - sizeof(uint32_t), p);

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Generic algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @param[in] supportedAlgoList List of algorithms supported by the entity
 * @param[in] supportedAlgoListLen Number of items in the name list
 * @return Name of the selected algorithm, if any
 **/

const char_t *sshSelectAlgo(SshContext *context, const SshNameList *peerAlgoList,
   const char_t *const *supportedAlgoList, uint_t supportedAlgoListLen)
{
   uint_t i;
   uint_t j;
   SshString name;
   const char_t *selectedAlgo;

   //Name of the chosen algorithm
   selectedAlgo = NULL;

   //Check whether SSH operates as a client or a server
   if(context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Loop through the list of algorithms supported by the SSH client
      for(i = 0; i < supportedAlgoListLen && selectedAlgo == NULL; i++)
      {
         //Loop through the list of algorithms offered by the SSH server
         for(j = 0; selectedAlgo == NULL; j++)
         {
            //Algorithm names are separated by commas
            if(sshGetName(peerAlgoList, j, &name))
            {
               //Compare algorithm names
               if(sshCompareString(&name, supportedAlgoList[i]))
               {
                  //The chosen algorithm must be the first algorithm on the
                  //client's name list that is also on the server's name list
                  selectedAlgo = supportedAlgoList[i];
               }
            }
            else
            {
               //The end of the list was reached
               break;
            }
         }
      }
   }
   else
   {
      //Loop through the list of algorithms offered by the SSH client
      for(j = 0; selectedAlgo == NULL; j++)
      {
         //Algorithm names are separated by commas
         if(sshGetName(peerAlgoList, j, &name))
         {
            //Loop through the list of algorithms supported by the SSH server
            for(i = 0; i < supportedAlgoListLen && selectedAlgo == NULL; i++)
            {
               //Compare algorithm names
               if(sshCompareString(&name, supportedAlgoList[i]))
               {
                  //The chosen algorithm must be the first algorithm on the
                  //client's name list that is also on the server's name list
                  selectedAlgo = supportedAlgoList[i];
               }
            }
         }
         else
         {
            //The end of the list was reached
            break;
         }
      }
   }

   //Return the name of the chosen algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Key exchange algorithm negotiation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Name of the selected algorithm, if any
 **/

const char_t *sshSelectKexAlgo(SshConnection *connection,
   const SshNameList *peerAlgoList)
{
   uint_t i;
   uint_t j;
   SshString name;
   const char_t *selectedAlgo;

   //Name of the chosen host key algorithm
   selectedAlgo = NULL;

   //Check whether SSH operates as a client or a server
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Loop through the list of algorithms supported by the SSH client
      for(i = 0; i < arraysize(sshSupportedKexAlgos) &&
         selectedAlgo == NULL; i++)
      {
         //Loop through the list of algorithms offered by the SSH server
         for(j = 0; selectedAlgo == NULL; j++)
         {
            //Algorithm names are separated by commas
            if(sshGetName(peerAlgoList, j, &name))
            {
               //Compare algorithm names
               if(sshCompareString(&name, sshSupportedKexAlgos[i]))
               {
                  //The chosen algorithm must be the first algorithm on the
                  //client's name list that is also on the server's name list
                  selectedAlgo = sshSupportedKexAlgos[i];
               }
            }
            else
            {
               //The end of the list was reached
               break;
            }
         }
      }
   }
   else
   {
      //Loop through the list of algorithms offered by the SSH client
      for(j = 0; selectedAlgo == NULL; j++)
      {
         //Algorithm names are separated by commas
         if(sshGetName(peerAlgoList, j, &name))
         {
            //Loop through the list of algorithms supported by the SSH server
            for(i = 0; i < arraysize(sshSupportedKexAlgos) &&
               selectedAlgo == NULL; i++)
            {
               //Compare algorithm names
               if(sshCompareString(&name, sshSupportedKexAlgos[i]))
               {
#if (SSH_RSA_KEX_SUPPORT == ENABLED)
                  //RSA key exchange algorithm?
                  if(sshIsRsaKexAlgo(sshSupportedKexAlgos[i]))
                  {
                     //RSA algorithms can only be negotiated at server-side if
                     //a valid transient RSA key has been loaded
                     if(sshSelectTransientRsaKey(connection->context,
                        sshSupportedKexAlgos[i]) >= 0)
                     {
                        selectedAlgo = sshSupportedKexAlgos[i];
                     }
                  }
                  else
#endif
#if (SSH_DH_GEX_KEX_SUPPORT == ENABLED)
                  //DH GEX key exchange algorithm?
                  if(sshIsDhGexKexAlgo(sshSupportedKexAlgos[i]))
                  {
                     //Diffie-Hellman Group Exchange algorithms can only be
                     //negotiated at server-side if a valid group has been loaded
                     if(sshSelectDhGexGroup(connection->context,
                        SSH_MIN_DH_MODULUS_SIZE, SSH_PREFERRED_DH_MODULUS_SIZE,
                        SSH_MAX_DH_MODULUS_SIZE) >= 0)
                     {
                        selectedAlgo = sshSupportedKexAlgos[i];
                     }
                  }
                  else
#endif
                  //Diffie-Hellman or ECDH key exchange algorithm?
                  {
                     //Select current host key algorithm
                     selectedAlgo = sshSupportedKexAlgos[i];
                  }
               }
            }
         }
         else
         {
            //The end of the list was reached
            break;
         }
      }
   }

#if (SSH_EXT_INFO_SUPPORT == ENABLED)
   //Applications implementing the extension negotiation mechanism must add an
   //indicator name to the field kex_algorithms in the SSH_MSG_KEXINIT message
   //sent by the application in the first key exchange (refer to RFC 8308,
   //section 2.1)
   if(!connection->newKeysSent)
   {
      const char_t *indicatorName;

      //The indicator names inserted by the client and server are different
      //to ensure these names will not produce a match and therefore not
      //affect the algorithm chosen in key exchange algorithm negotiation
      if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         indicatorName = "ext-info-s";
      }
      else
      {
         indicatorName = "ext-info-c";
      }

      //The indicator name may be added at any position in the name-list
      if(sshFindName(peerAlgoList, indicatorName) >= 0)
      {
         connection->extInfoReceived = TRUE;
      }
      else
      {
         connection->extInfoReceived = FALSE;
      }
   }
#endif

   //Return the name of the chosen host key algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Host key algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Name of the selected algorithm, if any
 **/

const char_t *sshSelectHostKeyAlgo(SshContext *context,
   const SshNameList *peerAlgoList)
{
   uint_t i;
   uint_t j;
   SshString name;
   const char_t *selectedAlgo;
   const SshHostKeyAlgo *entry;

   //Name of the chosen host key algorithm
   selectedAlgo = NULL;

   //Check whether SSH operates as a client or a server
   if(context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Loop through the list of algorithms supported by the SSH client
      for(i = 0; i < arraysize(sshSupportedHostKeyAlgos) &&
         selectedAlgo == NULL; i++)
      {
         //Point to the current entry
         entry = &sshSupportedHostKeyAlgos[i];

         //Loop through the list of algorithms offered by the SSH server
         for(j = 0; selectedAlgo == NULL; j++)
         {
            //Algorithm names are separated by commas
            if(sshGetName(peerAlgoList, j, &name))
            {
               //Compare algorithm names
               if(sshCompareString(&name, entry->publicKeyAlgo))
               {
                  //The chosen algorithm must be the first algorithm on the
                  //client's name list that is also on the server's name list
                  selectedAlgo = entry->publicKeyAlgo;
               }
            }
            else
            {
               //The end of the list was reached
               break;
            }
         }
      }
   }
   else
   {
      //Loop through the list of algorithms offered by the SSH client
      for(j = 0; selectedAlgo == NULL; j++)
      {
         //Algorithm names are separated by commas
         if(sshGetName(peerAlgoList, j, &name))
         {
            //Loop through the list of algorithms supported by the SSH server
            for(i = 0; i < arraysize(sshSupportedHostKeyAlgos) &&
               selectedAlgo == NULL; i++)
            {
               //Point to the current entry
               entry = &sshSupportedHostKeyAlgos[i];

               //Compare algorithm names
               if(sshCompareString(&name, entry->publicKeyAlgo))
               {
                  //The chosen algorithm must be the first algorithm on the
                  //client's name list that is also on the server's name list
                  if(sshSelectHostKey(context, entry->publicKeyAlgo) >= 0)
                  {
                     //Select current host key algorithm
                     selectedAlgo = entry->publicKeyAlgo;
                  }
               }
            }
         }
         else
         {
            //The end of the list was reached
            break;
         }
      }
   }

   //Return the name of the chosen host key algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Encryption algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Name of the selected algorithm, if any
 **/

const char_t *sshSelectEncAlgo(SshContext *context,
   const SshNameList *peerAlgoList)
{
   //The chosen encryption algorithm to each direction must be the first
   //algorithm on the client's name-list that is also on the server's name-list
   return sshSelectAlgo(context, peerAlgoList, sshSupportedEncAlgos,
      arraysize(sshSupportedEncAlgos));
}


/**
 * @brief Integrity algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] encAlgo Selected encryption algorithm
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Name of the selected algorithm, if any
 **/

const char_t *sshSelectMacAlgo(SshContext *context, const char_t *encAlgo,
   const SshNameList *peerAlgoList)
{
   const char_t *selectedAlgo;

#if (SSH_GCM_CIPHER_SUPPORT == ENABLED || SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   //AES-GCM or ChaCha20Poly1305 encryption algorithm?
   if(sshCompareAlgo(encAlgo, "aes128-gcm@openssh.com") ||
      sshCompareAlgo(encAlgo, "aes256-gcm@openssh.com") ||
      sshCompareAlgo(encAlgo, "chacha20-poly1305@openssh.com"))
   {
      //AEAD algorithms offer both encryption and authentication
      selectedAlgo = sshSupportedMacAlgos[arraysize(sshSupportedMacAlgos) - 1];
   }
   else
#endif
#if (SSH_RFC5647_SUPPORT == ENABLED)
   //AES-GCM or Camellia-GCM encryption algorithm?
   if(sshCompareAlgo(encAlgo, "AEAD_AES_128_GCM") ||
      sshCompareAlgo(encAlgo, "AEAD_AES_256_GCM") ||
      sshCompareAlgo(encAlgo, "AEAD_CAMELLIA_128_GCM") ||
      sshCompareAlgo(encAlgo, "AEAD_CAMELLIA_256_GCM"))
   {
      //If AES-GCM is selected as the encryption algorithm, it must also be
      //selected as the MAC algorithm (refer to RFC 5647, section 5.1)
      selectedAlgo = encAlgo;
   }
   else
#endif
   //Non-AEAD encryption algorithm?
   {
      //The chosen MAC algorithm to each direction must be the first algorithm
      //on the client's name-list that is also on the server's name-list
      selectedAlgo = sshSelectAlgo(context, peerAlgoList, sshSupportedMacAlgos,
         arraysize(sshSupportedMacAlgos) - 1);
   }

   //Return the name of the chosen algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Compression algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Name of the selected algorithm, if any
 **/

const char_t *sshSelectCompressionAlgo(SshContext *context,
   const SshNameList *peerAlgoList)
{
   //The chosen compression algorithm to each direction must be the first
   //algorithm on the client's name-list that is also on the server's name-list
   return sshSelectAlgo(context, peerAlgoList, sshSupportedCompressionAlgos,
      arraysize(sshSupportedCompressionAlgos));
}


/**
 * @brief Public key algorithm selection
 * @param[in] context Pointer to the SSH context
 * @param[in] keyFormatId Key format identifier
 * @param[in] peerAlgoList List of public key algorithms supported by the
 *   peer (optional parameter)
 * @return Name of the selected algorithm, if any
 **/

const char_t *sshSelectPublicKeyAlgo(SshContext *context,
   const char_t *keyFormatId, const SshNameList *peerAlgoList)
{
   uint_t i;
   uint_t j;
   SshString name;
   const char_t *selectedAlgo;
   const SshHostKeyAlgo *entry;

   //Name of the chosen public key algorithm
   selectedAlgo = NULL;

   //Loop through the list of supported algorithms
   for(i = 0; i < arraysize(sshSupportedHostKeyAlgos) &&
      selectedAlgo == NULL; i++)
   {
      //Point to the current entry
      entry = &sshSupportedHostKeyAlgos[i];

      //Check key format identifier
      if(sshCompareAlgo(entry->keyFormatId, keyFormatId))
      {
         //The parameter is optional
         if(peerAlgoList != NULL)
         {
            //Loop through the list of algorithms supported by the peer
            for(j = 0; selectedAlgo == NULL; j++)
            {
               //Algorithm names are separated by commas
               if(sshGetName(peerAlgoList, j, &name))
               {
                  //Compare algorithm names
                  if(sshCompareString(&name, entry->publicKeyAlgo))
                  {
                     //Select current public key algorithm
                     selectedAlgo = entry->publicKeyAlgo;
                  }
               }
               else
               {
                  //The end of the list was reached
                  break;
               }
            }
         }
         else
         {
            //Select current public key algorithm
            selectedAlgo = entry->publicKeyAlgo;
         }
      }
   }

   //Return the name of the chosen public key algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Get the key format identifier used by a given public key algorithm
 * @param[in] publicKeyAlgo Public key algorithm
 * @return Key format identifier
 **/

const char_t *sshGetKeyFormatId(const SshString *publicKeyAlgo)
{
   uint_t i;
   const char_t *keyFormatId;
   const SshHostKeyAlgo *entry;

   //Initialize key format identifier
   keyFormatId = NULL;

   //Loop through the list of supported algorithms
   for(i = 0; i < arraysize(sshSupportedHostKeyAlgos) &&
      keyFormatId == NULL; i++)
   {
      //Point to the current entry
      entry = &sshSupportedHostKeyAlgos[i];

      //Matching entry?
      if(sshCompareString(publicKeyAlgo, entry->publicKeyAlgo))
      {
         keyFormatId = entry->keyFormatId;
      }
   }

   //Return the matching key format identifier
   return keyFormatId;
}


/**
 * @brief Get the signature format identifier used by a given public key algorithm
 * @param[in] publicKeyAlgo Public key algorithm
 * @return Signature format identifier
 **/

const char_t *sshGetSignFormatId(const SshString *publicKeyAlgo)
{
   uint_t i;
   const char_t *signFormatId;
   const SshHostKeyAlgo *entry;

   //Initialize signature format identifier
   signFormatId = NULL;

   //Loop through the list of supported algorithms
   for(i = 0; i < arraysize(sshSupportedHostKeyAlgos) &&
      signFormatId == NULL; i++)
   {
      //Point to the current entry
      entry = &sshSupportedHostKeyAlgos[i];

      //Matching entry?
      if(sshCompareString(publicKeyAlgo, entry->publicKeyAlgo))
      {
         signFormatId = entry->signFormatId;
      }
   }

   //Return the matching signature format identifier
   return signFormatId;
}


/**
 * @brief Check whether the other party's guess is correct
 * @param[in] context Pointer to the SSH context
 * @param[in] kexAlgoList List of key exchange algorithms advertised by the
 *   other party
 * @param[in] hostKeyAlgoList List of host key algorithms advertised by the
 *   other party
 * @return TRUE if the guess is correct else FALSE
 **/

bool_t sshIsGuessCorrect(SshContext *context, const SshNameList *kexAlgoList,
   const SshNameList *hostKeyAlgoList)
{
   bool_t correct;
   SshString preferredKexAlgo;
   SshString preferredHostKeyAlgo;

   //The first key exchange algorithm of the list is the preferred algorithm
   correct = sshGetName(kexAlgoList, 0, &preferredKexAlgo);

   //Each name-list must contain at least one algorithm name
   if(correct)
   {
      //The first host key algorithm of the list is the preferred algorithm
      correct = sshGetName(hostKeyAlgoList, 0, &preferredHostKeyAlgo);
   }

   //Each name-list must contain at least one algorithm name
   if(correct)
   {
      //The guess is considered wrong if the key exchange algorithm or the
      //host key algorithm is guessed wrong (server and client have different
      //preferred algorithm)
      if(!sshCompareString(&preferredKexAlgo, sshSupportedKexAlgos[0]) ||
         !sshCompareString(&preferredHostKeyAlgo, sshSupportedHostKeyAlgos[0].publicKeyAlgo))
      {
         correct = FALSE;
      }
   }

   //Return TRUE if the guess is correct
   return correct;
}


/**
 * @brief Test if the specified algorithm is an RSA key exchange algorithm
 * @param[in] kexAlgo Key exchange algorithm name
 * @return TRUE if RSA key exchange algorithm, else FALSE
 **/

bool_t sshIsRsaKexAlgo(const char_t *kexAlgo)
{
   //RSA key exchange algorithm?
   if(sshCompareAlgo(kexAlgo, "rsa1024-sha1") ||
      sshCompareAlgo(kexAlgo, "rsa2048-sha256"))
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if the specified algorithm is a Diffie-Hellman key exchange algorithm
 * @param[in] kexAlgo Key exchange algorithm name
 * @return TRUE if Diffie-Hellman key exchange algorithm, else FALSE
 **/

bool_t sshIsDhKexAlgo(const char_t *kexAlgo)
{
   //Diffie-Hellman key exchange algorithm?
   if(sshCompareAlgo(kexAlgo, "diffie-hellman-group1-sha1") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group14-sha1") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group14-sha256") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group15-sha512") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group16-sha512") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group17-sha512") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group18-sha512"))
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if the specified algorithm is a DH GEX key exchange algorithm
 * @param[in] kexAlgo Key exchange algorithm name
 * @return TRUE if DH GEX key exchange algorithm, else FALSE
 **/

bool_t sshIsDhGexKexAlgo(const char_t *kexAlgo)
{
   //DH GEX key exchange algorithm?
   if(sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha1") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha256") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha224@ssh.com") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha384@ssh.com") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha512@ssh.com"))
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if the specified algorithm is an ECDH key exchange algorithm
 * @param[in] kexAlgo Key exchange algorithm name
 * @return TRUE if ECDH key exchange algorithm, else FALSE
 **/

bool_t sshIsEcdhKexAlgo(const char_t *kexAlgo)
{
   //ECDH key exchange algorithm?
   if(sshCompareAlgo(kexAlgo, "ecdh-sha2-nistp256") ||
      sshCompareAlgo(kexAlgo, "ecdh-sha2-nistp384") ||
      sshCompareAlgo(kexAlgo, "ecdh-sha2-nistp521") ||
      sshCompareAlgo(kexAlgo, "curve25519-sha256") ||
      sshCompareAlgo(kexAlgo, "curve25519-sha256@libssh.org") ||
      sshCompareAlgo(kexAlgo, "curve448-sha512"))
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if the specified algorithm is a PQ-hybrid key exchange algorithm
 * @param[in] kexAlgo Key exchange algorithm name
 * @return TRUE if PQ-hybrid key exchange algorithm, else FALSE
 **/

bool_t sshIsHbrKexAlgo(const char_t *kexAlgo)
{
   //Post-quantum hybrid key exchange algorithm?
   if(sshCompareAlgo(kexAlgo, "sntrup761x25519-sha512@openssh.com"))
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if the specified public key algorithm is using certificates
 * @param[in] publicKeyAlgo Public key algorithm name
 * @return TRUE if the public key algorithm is using certificates, else FALSE
 **/

bool_t sshIsCertPublicKeyAlgo(const SshString *publicKeyAlgo)
{
   //Check public key algorithm name
   if(sshCompareString(publicKeyAlgo, "ssh-rsa-cert-v01@openssh.com") ||
      sshCompareString(publicKeyAlgo, "rsa-sha2-256-cert-v01@openssh.com") ||
      sshCompareString(publicKeyAlgo, "rsa-sha2-512-cert-v01@openssh.com") ||
      sshCompareString(publicKeyAlgo, "ssh-dss-cert-v01@openssh.com") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp256-cert-v01@openssh.com") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp384-cert-v01@openssh.com") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp521-cert-v01@openssh.com") ||
      sshCompareString(publicKeyAlgo, "ssh-ed25519-cert-v01@openssh.com"))
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}

#endif
