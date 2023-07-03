/**
 * @file ssh_key_format.c
 * @brief SSH key formatting
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
#include "ssh/ssh_key_parse.h"
#include "ssh/ssh_key_format.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Format an RSA public host key
 * @param[in] publicKey Pointer to the RSA public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatRsaPublicKey(const RsaPublicKey *publicKey,
   uint8_t *p, size_t *written)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the public host key structure
   *written = 0;

   //Format public key format identifier
   error = sshFormatString("ssh-rsa", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format RSA public exponent
   error = sshFormatMpint(&publicKey->e, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format RSA modulus
   error = sshFormatMpint(&publicKey->n, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written += n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format a DSA public host key
 * @param[in] publicKey Pointer to the DSA public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatDsaPublicKey(const DsaPublicKey *publicKey,
   uint8_t *p, size_t *written)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the public host key structure
   *written = 0;

   //Format public key format identifier
   error = sshFormatString("ssh-dss", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format DSA prime modulus
   error = sshFormatMpint(&publicKey->params.p, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format DSA group order
   error = sshFormatMpint(&publicKey->params.q, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format DSA group generator
   error = sshFormatMpint(&publicKey->params.g, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format DSA public key value
   error = sshFormatMpint(&publicKey->y, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written += n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format an ECDSA public host key
 * @param[in] params EC domain parameters
 * @param[in] publicKey Pointer to the ECDSA public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatEcdsaPublicKey(const EcDomainParameters *params,
   const EcPublicKey *publicKey, uint8_t *p, size_t *written)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const char_t *keyFormatId;
   const char_t *curveName;

   //Total length of the public host key structure
   *written = 0;

   //Check elliptic curve
   if(!osStrcmp(params->name, "secp256r1"))
   {
      //Select NIST P-256 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp256";
      curveName = "nistp256";
   }
   else if(!osStrcmp(params->name, "secp384r1"))
   {
      //Select NIST P-384 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp384";
      curveName = "nistp384";
   }
   else if(!osStrcmp(params->name, "secp521r1"))
   {
      //Select NIST P-521 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp521";
      curveName = "nistp521";
   }
   else
   {
      //Unknown host key algorithm
      return ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Format public key format identifier
   error = sshFormatString(keyFormatId, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format the elliptic curve domain parameter identifier
   error = sshFormatString(curveName, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format EC public key
   error = ecExport(params, &publicKey->q, p + 4, &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format an Ed25519 public host key
 * @param[in] publicKey Pointer to the Ed25519 public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatEd25519PublicKey(const EddsaPublicKey *publicKey,
   uint8_t *p, size_t *written)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the public host key structure
   *written = 0;

   //Format public key format identifier
   error = sshFormatString("ssh-ed25519", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The public key shall consist of 32 octets
   n = ED25519_PUBLIC_KEY_LEN;

   //Format Ed25519 public key
   error = mpiExport(&publicKey->q, p + 4, n, MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format an Ed448 public host key
 * @param[in] publicKey Pointer to the Ed448 public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatEd448PublicKey(const EddsaPublicKey *publicKey,
   uint8_t *p, size_t *written)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the public host key structure
   *written = 0;

   //Format public key format identifier
   error = sshFormatString("ssh-ed448", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The public key shall consist of 57 octets
   n = ED448_PUBLIC_KEY_LEN;

   //Format Ed448 public key
   error = mpiExport(&publicKey->q, p + 4, n, MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format private key header (OpenSSH format)
 * @param[out] p Buffer where to store the private key header
 * @param[out] written Length of the resulting private key header
 * @return Error code
 **/

error_t sshFormatOpenSshPrivateKeyHeader(uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Total length of the private key header
   *written = 0;

   //Format magic identifier
   osMemmove(p, "openssh-key-v1", SSH_AUTH_MAGIC_SIZE);

   //Point to the next field
   p += SSH_AUTH_MAGIC_SIZE;
   *written += SSH_AUTH_MAGIC_SIZE;

   //Format 'ciphername' field (for unencrypted keys the cipher "none" is used)
   error = sshFormatString("none", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format 'kdfname' field (for unencrypted keys the KDF "none" is used)
   error = sshFormatString("none", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format 'kdfoptions' field
   error = sshFormatString("", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format 'number of keys' field
   STORE32BE(1, p);

   //Total number of bytes that have been written
   *written += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RSA private key blob (OpenSSH format)
 * @param[in] privateKey Pointer to the RSA private key
 * @param[out] p Buffer where to store the private key blob
 * @param[out] written Length of the resulting private key blob
 * @return Error code
 **/

error_t sshFormatOpenSshRsaPrivateKey(const RsaPrivateKey *privateKey,
   uint8_t *p, size_t *written)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;

   //Total length of the private key blob
   length = 0;

   //Format 'checkint' fields
   STORE32BE(0x12345678, p);
   STORE32BE(0x12345678, p + sizeof(uint32_t));

   //Point to the next field
   p += 2 * sizeof(uint32_t);
   length += 2 * sizeof(uint32_t);

   //Format key format identifier
   error = sshFormatString("ssh-rsa", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format RSA modulus
   error = sshFormatMpint(&privateKey->n, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format RSA public exponent
   error = sshFormatMpint(&privateKey->e, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format RSA private exponent
   error = sshFormatMpint(&privateKey->d, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format RSA CRT coefficient
   error = sshFormatMpint(&privateKey->qinv, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Parse RSA first factor
   error = sshFormatMpint(&privateKey->p, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Parse RSA second factor
   error = sshFormatMpint(&privateKey->q, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The private key is followed by a comment
   error = sshFormatString("", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The padding size is determined by the 'ciphername' field
   for(n = 0; (length % 8) != 0; n++, length++)
   {
      p[n] = n + 1;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format DSA private key blob (OpenSSH format)
 * @param[in] privateKey Pointer to the DSA private key
 * @param[in] publicKey Pointer to the DSA public key
 * @param[out] p Buffer where to store the private key blob
 * @param[out] written Length of the resulting private key blob
 * @return Error code
 **/

error_t sshFormatOpenSshDsaPrivateKey(const DsaPrivateKey *privateKey,
   const DsaPublicKey *publicKey, uint8_t *p, size_t *written)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;

   //Total length of the private key blob
   length = 0;

   //Format 'checkint' fields
   STORE32BE(0x12345678, p);
   STORE32BE(0x12345678, p + sizeof(uint32_t));

   //Point to the next field
   p += 2 * sizeof(uint32_t);
   length += 2 * sizeof(uint32_t);

   //Format key format identifier
   error = sshFormatString("ssh-dss", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format DSA prime modulus
   error = sshFormatMpint(&privateKey->params.p, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format DSA group order
   error = sshFormatMpint(&privateKey->params.q, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format DSA group generator
   error = sshFormatMpint(&privateKey->params.g, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format DSA public key value
   error = sshFormatMpint(&publicKey->y, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format DSA private key value
   error = sshFormatMpint(&privateKey->x, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The private key is followed by a comment
   error = sshFormatString("", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The padding size is determined by the 'ciphername' field
   for(n = 0; (length % 8) != 0; n++, length++)
   {
      p[n] = n + 1;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format ECDSA private key blob (OpenSSH format)
 * @param[in] params EC domain parameters
 * @param[in] privateKey Pointer to the ECDSA private key
 * @param[in] publicKey Pointer to the ECDSA public key
 * @param[out] p Buffer where to store the private key blob
 * @param[out] written Length of the resulting private key blob
 * @return Error code
 **/

error_t sshFormatOpenSshEcdsaPrivateKey(const EcDomainParameters *params,
   const EcPrivateKey *privateKey, const EcPublicKey *publicKey,
   uint8_t *p, size_t *written)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   const char_t *keyFormatId;
   const char_t *curveName;

   //Total length of the private key blob
   length = 0;

   //Format 'checkint' fields
   STORE32BE(0x12345678, p);
   STORE32BE(0x12345678, p + sizeof(uint32_t));

   //Point to the next field
   p += 2 * sizeof(uint32_t);
   length += 2 * sizeof(uint32_t);

   //Check elliptic curve
   if(!osStrcmp(params->name, "secp256r1"))
   {
      //Select NIST P-256 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp256";
      curveName = "nistp256";
   }
   else if(!osStrcmp(params->name, "secp384r1"))
   {
      //Select NIST P-384 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp384";
      curveName = "nistp384";
   }
   else if(!osStrcmp(params->name, "secp521r1"))
   {
      //Select NIST P-521 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp521";
      curveName = "nistp521";
   }
   else
   {
      //Unknown host key algorithm
      return ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Format public key format identifier
   error = sshFormatString(keyFormatId, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format the elliptic curve domain parameter identifier
   error = sshFormatString(curveName, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //Format EC public key
   error = ecExport(params, &publicKey->q, p + 4, &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Point to the next field
   p += sizeof(uint32_t) + n;
   length += sizeof(uint32_t) + n;

   //Format EC private key
   error = sshFormatMpint(&privateKey->d, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The private key is followed by a comment
   error = sshFormatString("", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The padding size is determined by the 'ciphername' field
   for(n = 0; (length % 8) != 0; n++, length++)
   {
      p[n] = n + 1;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format Ed25519 private key blob (OpenSSH format)
 * @param[in] privateKey Pointer to the Ed25519 private key
 * @param[in] publicKey Pointer to the Ed25519 public key
 * @param[out] p Buffer where to store the private key blob
 * @param[out] written Length of the resulting private key blob
 * @return Error code
 **/

error_t sshFormatOpenSshEd25519PrivateKey(const EddsaPrivateKey *privateKey,
   const EddsaPublicKey *publicKey, uint8_t *p, size_t *written)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;

   //Total length of the private key blob
   length = 0;

   //Format 'checkint' fields
   STORE32BE(0x12345678, p);
   STORE32BE(0x12345678, p + sizeof(uint32_t));

   //Point to the next field
   p += 2 * sizeof(uint32_t);
   length += 2 * sizeof(uint32_t);

   //Format key format identifier
   error = sshFormatString("ssh-ed25519", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The public key shall consist of 32 octets
   n = ED25519_PUBLIC_KEY_LEN;

   //Format Ed25519 public key
   error = mpiExport(&publicKey->q, p + 4, n, MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Point to the next field
   p += sizeof(uint32_t) + n;
   length += sizeof(uint32_t) + n;

   //The private key shall consist of 64 octets
   n = ED25519_PRIVATE_KEY_LEN + ED25519_PUBLIC_KEY_LEN;

   //Format Ed25519 private key
   error = mpiExport(&privateKey->d, p + 4, ED25519_PRIVATE_KEY_LEN,
      MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Format Ed25519 public key
   error = mpiExport(&publicKey->q, p + 4 + ED25519_PRIVATE_KEY_LEN,
      ED25519_PUBLIC_KEY_LEN, MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Point to the next field
   p += sizeof(uint32_t) + n;
   length += sizeof(uint32_t) + n;

   //The private key is followed by a comment
   error = sshFormatString("", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The padding size is determined by the 'ciphername' field
   for(n = 0; (length % 8) != 0; n++, length++)
   {
      p[n] = n + 1;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format Ed448 private key blob (OpenSSH format)
 * @param[in] privateKey Pointer to the Ed448 private key
 * @param[in] publicKey Pointer to the Ed448 public key
 * @param[out] p Buffer where to store the private key blob
 * @param[out] written Length of the resulting private key blob
 * @return Error code
 **/

error_t sshFormatOpenSshEd448PrivateKey(const EddsaPrivateKey *privateKey,
   const EddsaPublicKey *publicKey, uint8_t *p, size_t *written)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;

   //Total length of the private key blob
   length = 0;

   //Format 'checkint' fields
   STORE32BE(0x12345678, p);
   STORE32BE(0x12345678, p + sizeof(uint32_t));

   //Point to the next field
   p += 2 * sizeof(uint32_t);
   length += 2 * sizeof(uint32_t);

   //Format key format identifier
   error = sshFormatString("ssh-ed448", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The public key shall consist of 57 octets
   n = ED448_PUBLIC_KEY_LEN;

   //Format Ed448 public key
   error = mpiExport(&publicKey->q, p + 4, n, MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Point to the next field
   p += sizeof(uint32_t) + n;
   length += sizeof(uint32_t) + n;

   //The private key shall consist of 114 octets
   n = ED448_PRIVATE_KEY_LEN + ED448_PUBLIC_KEY_LEN;

   //Format Ed448 private key
   error = mpiExport(&privateKey->d, p + 4, ED448_PRIVATE_KEY_LEN,
      MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Format Ed448 public key
   error = mpiExport(&publicKey->q, p + 4 + ED448_PRIVATE_KEY_LEN,
      ED448_PUBLIC_KEY_LEN, MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Point to the next field
   p += sizeof(uint32_t) + n;
   length += sizeof(uint32_t) + n;

   //The private key is followed by a comment
   error = sshFormatString("", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   length += n;

   //The padding size is determined by the 'ciphername' field
   for(n = 0; (length % 8) != 0; n++, length++)
   {
      p[n] = n + 1;
   }

   //Total number of bytes that have been written
   *written = length;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
