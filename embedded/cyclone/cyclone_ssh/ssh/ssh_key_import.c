/**
 * @file ssh_key_import.c
 * @brief SSH key file import functions
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
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_key_parse.h"
#include "ssh/ssh_misc.h"
#include "encoding/base64.h"
#include "pkix/pem_import.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief List of supported key types
 **/

static const SshKeyType sshKeyTypes[] =
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   {"ssh-rsa", X509_KEY_TYPE_RSA, NULL},
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   {"ssh-dss", X509_KEY_TYPE_DSA, NULL},
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP256_SUPPORT == ENABLED)
   {"ecdsa-sha2-nistp256", X509_KEY_TYPE_EC, "secp256r1"},
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP384_SUPPORT == ENABLED)
   {"ecdsa-sha2-nistp384", X509_KEY_TYPE_EC, "secp384r1"},
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED && SSH_NISTP521_SUPPORT == ENABLED)
   {"ecdsa-sha2-nistp521", X509_KEY_TYPE_EC, "secp521r1"},
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   {"ssh-ed25519", X509_KEY_TYPE_ED25519, NULL},
#endif
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   {"ssh-ed448", X509_KEY_TYPE_ED448, NULL},
#endif
};


/**
 * @brief Decode an SSH public key file containing an RSA public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] publicKey RSA public key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportRsaPublicKey(const char_t *input, size_t length,
   RsaPublicKey *publicKey)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshRsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the public key file (SSH2 or OpenSSH format)
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse RSA host key structure
            error = sshParseRsaHostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import RSA public key
            error = sshImportRsaHostKey(&hostKey, publicKey);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decode the content of the public key file (PEM format)
      error = pemImportRsaPublicKey(input, length, publicKey);
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      rsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH public key file containing a DSA public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] publicKey DSA public key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportDsaPublicKey(const char_t *input, size_t length,
   DsaPublicKey *publicKey)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshDsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the public key file (SSH2 or OpenSSH format)
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse DSA host key structure
            error = sshParseDsaHostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import DSA public key
            error = sshImportDsaHostKey(&hostKey, publicKey);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decode the content of the public key file (PEM format)
      error = pemImportDsaPublicKey(input, length, publicKey);
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      dsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH public key file containing an ECDSA public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] params EC domain parameters resulting from the parsing process
 * @param[out] publicKey ECDSA public key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportEcdsaPublicKey(const char_t *input, size_t length,
   EcDomainParameters *params, EcPublicKey *publicKey)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshEcdsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the public key file (SSH2 or OpenSSH format)
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse ECDSA host key structure
            error = sshParseEcdsaHostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import ECDSA public key
            error = sshImportEcdsaHostKey(&hostKey, params, publicKey);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Import EC domain parameters
      error = pemImportEcParameters(input, length, params);

      //Check status code
      if(!error)
      {
         //Decode the content of the public key file (PEM format)
         error = pemImportEcPublicKey(input, length, publicKey);
      }
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFreeDomainParameters(params);
      ecFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH public key file containing an Ed25519 public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] publicKey Ed25519 public key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportEd25519PublicKey(const char_t *input, size_t length,
   EddsaPublicKey *publicKey)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshEddsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the public key file (SSH2 or OpenSSH format)
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse Ed25519 host key structure
            error = sshParseEd25519HostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import Ed25519 public key
            error = sshImportEd25519HostKey(&hostKey, publicKey);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decode the content of the public key file (PEM format)
      error = pemImportEddsaPublicKey(input, length, publicKey);
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH public key file containing an Ed448 public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] publicKey Ed448 public key resulting from the parsing process
 * @return Error code
 **/
error_t sshImportEd448PublicKey(const char_t *input, size_t length,
   EddsaPublicKey *publicKey)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshEddsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the public key file (SSH2 or OpenSSH format)
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse Ed448 host key structure
            error = sshParseEd448HostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import Ed448 public key
            error = sshImportEd448HostKey(&hostKey, publicKey);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decode the content of the public key file (PEM format)
      error = pemImportEddsaPublicKey(input, length, publicKey);
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH private key file containing an RSA private key
 * @param[in] input Pointer to the SSH private key file
 * @param[in] length Length of the SSH private key file
 * @param[out] privateKey RSA private key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportRsaPrivateKey(const char_t *input, size_t length,
   RsaPrivateKey *privateKey)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   Mpi t;
   SshPrivateKeyHeader privateKeyHeader;
   SshRsaPrivateKey privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the private key structure
   error = sshDecodeOpenSshPrivateKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the private key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Initialize multiple precision integer
         mpiInit(&t);

         //Decode the content of the private key file (OpenSSH format)
         error = sshDecodeOpenSshPrivateKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse private key header
            error = sshParseOpenSshPrivateKeyHeader(buffer, n, &privateKeyHeader);
         }

         //Check status code
         if(!error)
         {
            //Parse RSA private key blob
            error = sshParseOpenSshRsaPrivateKey(privateKeyHeader.encrypted.value,
               privateKeyHeader.encrypted.length, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import RSA modulus
            error = mpiImport(&privateKey->n, privateKeyInfo.n.value,
               privateKeyInfo.n.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Import RSA public exponent
            error = mpiImport(&privateKey->e, privateKeyInfo.e.value,
               privateKeyInfo.e.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Import RSA private exponent
            error = mpiImport(&privateKey->d, privateKeyInfo.d.value,
               privateKeyInfo.d.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Import RSA first factor
            error = mpiImport(&privateKey->p, privateKeyInfo.p.value,
               privateKeyInfo.p.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Import RSA second factor
            error = mpiImport(&privateKey->q, privateKeyInfo.q.value,
               privateKeyInfo.q.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Import RSA CRT coefficient
            error = mpiImport(&privateKey->qinv, privateKeyInfo.qinv.value,
               privateKeyInfo.qinv.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Compute t = p - 1
            error = mpiSubInt(&t, &privateKey->p, 1);
         }

         //Check status code
         if(!error)
         {
            //Compute first factor's CRT exponent
            error = mpiMod(&privateKey->dp, &privateKey->d, &t);
         }

         //Check status code
         if(!error)
         {
            //Compute t = q - 1
            error = mpiSubInt(&t, &privateKey->q, 1);
         }

         //Check status code
         if(!error)
         {
            //Compute second factor's CRT exponent
            error = mpiMod(&privateKey->dq, &privateKey->d, &t);
         }

         //Release multiple precision integers
         mpiFree(&t);
         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decode the content of the private key file (PEM format)
      error = pemImportRsaPrivateKey(input, length, privateKey);
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      rsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH private key file containing a DSA private key
 * @param[in] input Pointer to the SSH private key file
 * @param[in] length Length of the SSH private key file
 * @param[out] privateKey DSA private key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportDsaPrivateKey(const char_t *input, size_t length,
   DsaPrivateKey *privateKey)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshPrivateKeyHeader privateKeyHeader;
   SshDsaPrivateKey privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the private key structure
   error = sshDecodeOpenSshPrivateKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the private key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the private key file (OpenSSH format)
         error = sshDecodeOpenSshPrivateKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse private key header
            error = sshParseOpenSshPrivateKeyHeader(buffer, n, &privateKeyHeader);
         }

         //Check status code
         if(!error)
         {
            //Parse DSA private key blob
            error = sshParseOpenSshDsaPrivateKey(privateKeyHeader.encrypted.value,
               privateKeyHeader.encrypted.length, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import DSA prime modulus
            error = mpiImport(&privateKey->params.p, privateKeyInfo.p.value,
               privateKeyInfo.p.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Import DSA group order
            error = mpiImport(&privateKey->params.q, privateKeyInfo.q.value,
               privateKeyInfo.q.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Import DSA group generator
            error = mpiImport(&privateKey->params.g, privateKeyInfo.g.value,
               privateKeyInfo.g.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Check status code
         if(!error)
         {
            //Import DSA private key value
            error = mpiImport(&privateKey->x, privateKeyInfo.x.value,
               privateKeyInfo.x.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decode the content of the private key file (PEM format)
      error = pemImportDsaPrivateKey(input, length, privateKey);
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      dsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH private key file containing an ECDSA private key
 * @param[in] input Pointer to the SSH private key file
 * @param[in] length Length of the SSH private key file
 * @param[out] privateKey ECDSA private key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportEcdsaPrivateKey(const char_t *input, size_t length,
   EcPrivateKey *privateKey)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshPrivateKeyHeader privateKeyHeader;
   SshEcdsaPrivateKey privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the private key structure
   error = sshDecodeOpenSshPrivateKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the private key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the private key file (OpenSSH format)
         error = sshDecodeOpenSshPrivateKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse private key header
            error = sshParseOpenSshPrivateKeyHeader(buffer, n, &privateKeyHeader);
         }

         //Check status code
         if(!error)
         {
            //Parse ECDSA private key blob
            error = sshParseOpenSshEcdsaPrivateKey(privateKeyHeader.encrypted.value,
               privateKeyHeader.encrypted.length, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import EC private key
            error = mpiImport(&privateKey->d, privateKeyInfo.d.value,
               privateKeyInfo.d.length, MPI_FORMAT_BIG_ENDIAN);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decode the content of the private key file (PEM format)
      error = pemImportEcPrivateKey(input, length, privateKey);
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH private key file containing an Ed25519 private key
 * @param[in] input Pointer to the SSH private key file
 * @param[in] length Length of the SSH private key file
 * @param[out] privateKey Ed25519 private key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportEd25519PrivateKey(const char_t *input, size_t length,
   EddsaPrivateKey *privateKey)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshPrivateKeyHeader privateKeyHeader;
   SshEddsaPrivateKey privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the private key structure
   error = sshDecodeOpenSshPrivateKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the private key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the private key file (OpenSSH format)
         error = sshDecodeOpenSshPrivateKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse private key header
            error = sshParseOpenSshPrivateKeyHeader(buffer, n, &privateKeyHeader);
         }

         //Check status code
         if(!error)
         {
            //Parse Ed25519 private key blob
            error = sshParseOpenSshEd25519PrivateKey(privateKeyHeader.encrypted.value,
               privateKeyHeader.encrypted.length, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import Ed25519 private key
            error = mpiImport(&privateKey->d, privateKeyInfo.d.value,
               ED25519_PRIVATE_KEY_LEN, MPI_FORMAT_LITTLE_ENDIAN);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decode the content of the private key file (PEM format)
      error = pemImportEddsaPrivateKey(input, length, privateKey);
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH private key file containing an Ed448 private key
 * @param[in] input Pointer to the SSH private key file
 * @param[in] length Length of the SSH private key file
 * @param[out] privateKey Ed448 private key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportEd448PrivateKey(const char_t *input, size_t length,
   EddsaPrivateKey *privateKey)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshPrivateKeyHeader privateKeyHeader;
   SshEddsaPrivateKey privateKeyInfo;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(privateKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the private key structure
   error = sshDecodeOpenSshPrivateKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the private key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the private key file (OpenSSH format)
         error = sshDecodeOpenSshPrivateKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse private key header
            error = sshParseOpenSshPrivateKeyHeader(buffer, n, &privateKeyHeader);
         }

         //Check status code
         if(!error)
         {
            //Parse Ed448 private key blob
            error = sshParseOpenSshEd448PrivateKey(privateKeyHeader.encrypted.value,
               privateKeyHeader.encrypted.length, &privateKeyInfo);
         }

         //Check status code
         if(!error)
         {
            //Import Ed448 private key
            error = mpiImport(&privateKey->d, privateKeyInfo.d.value,
               ED448_PRIVATE_KEY_LEN, MPI_FORMAT_LITTLE_ENDIAN);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decode the content of the private key file (PEM format)
      error = pemImportEddsaPrivateKey(input, length, privateKey);
   }

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePrivateKey(privateKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import an RSA host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] publicKey Pointer to the RSA public key
 * @return Error code
 **/

error_t sshImportRsaHostKey(const SshRsaHostKey *hostKey,
   RsaPublicKey *publicKey)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   uint_t k;

   //Import RSA public exponent
   error = mpiImport(&publicKey->e, hostKey->e.value, hostKey->e.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import RSA modulus
   error = mpiImport(&publicKey->n, hostKey->n.value, hostKey->n.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the modulus, in bits
   k = mpiGetBitLength(&publicKey->n);

   //Applications should enforce minimum and maximum key sizes
   if(k < SSH_MIN_RSA_MODULUS_SIZE || k > SSH_MAX_RSA_MODULUS_SIZE)
      return ERROR_INVALID_KEY_LENGTH;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import a DSA host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] publicKey Pointer to the DSA public key
 * @return Error code
 **/

error_t sshImportDsaHostKey(const SshDsaHostKey *hostKey,
   DsaPublicKey *publicKey)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t k;

   //Import DSA prime modulus
   error = mpiImport(&publicKey->params.p, hostKey->p.value, hostKey->p.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import DSA group order
   error = mpiImport(&publicKey->params.q, hostKey->q.value, hostKey->q.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import DSA group generator
   error = mpiImport(&publicKey->params.g, hostKey->g.value, hostKey->g.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import DSA public key value
   error = mpiImport(&publicKey->y, hostKey->y.value, hostKey->y.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the modulus, in bits
   k = mpiGetBitLength(&publicKey->params.p);

   //Applications should enforce minimum and maximum key sizes
   if(k < SSH_MIN_DSA_MODULUS_SIZE || k > SSH_MAX_DSA_MODULUS_SIZE)
      return ERROR_INVALID_KEY_LENGTH;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import a ECDSA host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] params EC domain parameters
 * @param[out] publicKey Pointer to the ECDSA public key
 * @return Error code
 **/

error_t sshImportEcdsaHostKey(const SshEcdsaHostKey *hostKey,
   EcDomainParameters *params, EcPublicKey *publicKey)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   const EcCurveInfo *curveInfo;

   //Retrieve the elliptic curve that matches the specified key format
   //identifier
   curveInfo = sshGetCurveInfo(&hostKey->keyFormatId, &hostKey->curveName);

   //Make sure the key format identifier is acceptable
   if(curveInfo != NULL)
   {
      //Load EC domain parameters
      error = ecLoadDomainParameters(params, curveInfo);
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Check status code
   if(!error)
   {
      //Import EC public key
      error = ecImport(params, &publicKey->q, hostKey->q.value,
         hostKey->q.length);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import an Ed25519 host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] publicKey Pointer to the Ed25519 public key
 * @return Error code
 **/

error_t sshImportEd25519HostKey(const SshEddsaHostKey *hostKey,
   EddsaPublicKey *publicKey)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Import Ed25519 public key
   error = mpiImport(&publicKey->q, hostKey->q.value, hostKey->q.length,
      MPI_FORMAT_LITTLE_ENDIAN);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import an Ed448 host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] publicKey Pointer to the Ed448 public key
 * @return Error code
 **/

error_t sshImportEd448HostKey(const SshEddsaHostKey *hostKey,
   EddsaPublicKey *publicKey)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Import Ed448 public key
   error = mpiImport(&publicKey->q, hostKey->q.value, hostKey->q.length,
      MPI_FORMAT_LITTLE_ENDIAN);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Get SSH public key type
 * @param[in] input SSH public key file
 * @param[in] length Length of the SSH public key file
 * @return SSH public key type
 **/

const char_t *sshGetPublicKeyType(const char_t *input, size_t length)
{
   error_t error;
   uint_t i;
   size_t n;
   const char_t *keyType;

   //Initialize key type
   keyType = NULL;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      uint8_t *buffer;
      SshString keyFormatId;

      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the public key file (SSH2 or OpenSSH format)
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status
         if(!error)
         {
            //Decode key format identifier
            error = sshParseString(buffer, n, &keyFormatId);
         }

         //Check status
         if(!error)
         {
            //Loop through the list of supported key types
            for(i = 0; i < arraysize(sshKeyTypes); i++)
            {
               //Matching identifier?
               if(sshCompareString(&keyFormatId, sshKeyTypes[i].identifier))
               {
                  keyType = sshKeyTypes[i].identifier;
                  break;
               }
            }
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
   }
   else
   {
      X509KeyType type;
      EcDomainParameters params;

      //Initialize EC domain parameters
      ecInitDomainParameters(&params);

      //Retrieve the type of the public key (PEM format)
      error = pemGetPublicKeyType(input, length, &type);

      //Check status
      if(!error)
      {
         //EC public key?
         if(type == X509_KEY_TYPE_EC)
         {
            //Import EC domain parameters
            error = pemImportEcParameters(input, length, &params);
         }
      }

      //Check status
      if(!error)
      {
         //Loop through the list of supported key types
         for(i = 0; i < arraysize(sshKeyTypes); i++)
         {
            //Matching key type?
            if(sshKeyTypes[i].type == type)
            {
               //EC public key?
               if(type == X509_KEY_TYPE_EC)
               {
                  //Check curve name
                  if(!osStrcmp(sshKeyTypes[i].curveName, params.name))
                  {
                     keyType = sshKeyTypes[i].identifier;
                     break;
                  }
               }
               else
               {
                  keyType = sshKeyTypes[i].identifier;
                  break;
               }
            }
         }
      }

      //Release EC domain parameters
      ecFreeDomainParameters(&params);
   }

   //Return key type
   return keyType;
}


/**
 * @brief Decode SSH public key file (SSH2 or OpenSSH format)
 * @param[in] input SSH public key file to decode
 * @param[in] inputLen Length of the SSH public key file to decode
 * @param[out] output Pointer to the decoded data (optional parameter)
 * @param[out] outputLen Length of the decoded data
 **/

error_t sshDecodePublicKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;

   //Decode SSH public key file (SSH2 format)
   error = sshDecodeSsh2PublicKeyFile(input, inputLen, output, outputLen);

   //Check status code
   if(error)
   {
      //Decode SSH public key file (OpenSSH format)
      error = sshDecodeOpenSshPublicKeyFile(input, inputLen, output, outputLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Decode SSH public key file (SSH2 format)
 * @param[in] input SSH public key file to decode
 * @param[in] inputLen Length of the SSH public key file to decode
 * @param[out] output Pointer to the decoded data (optional parameter)
 * @param[out] outputLen Length of the decoded data
 **/

error_t sshDecodeSsh2PublicKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;
   int_t i;
   int_t n;
   bool_t separatorChar;
   bool_t backslashChar;
   bool_t continuationLine;
   const char_t *p;

   //The first line of a conforming key file must be a begin marker (refer to
   //RFC 4716, section 3.2)
   i = sshSearchMarker(input, inputLen, "---- BEGIN SSH2 PUBLIC KEY ----", 31);
   //Begin marker not found?
   if(i < 0)
      return ERROR_INVALID_SYNTAX;

   //Advance the pointer over the marker
   i += 31;

   //The last line of a conforming key file must be an end marker (refer to
   //RFC 4716, section 3.2)
   n = sshSearchMarker(input + i, inputLen - i, "---- END SSH2 PUBLIC KEY ----", 29);
   //End marker not found?
   if(n < 0)
      return ERROR_INVALID_SYNTAX;

   //Point to the key file header
   p = input + i;
   i = 0;

   //Initialize flags
   separatorChar = FALSE;
   backslashChar = FALSE;
   continuationLine = FALSE;

   //The key file header section consists of multiple lines
   while(i < n)
   {
      //End of line detected?
      if(p[i] == '\n' || (i + 1) == n)
      {
         //A line that is not a continuation line and that has no ':' in it
         //is the first line of the Base64-encoded body (refer to RFC 4716,
         //section 3.3)
         if(!continuationLine && !separatorChar)
         {
            break;
         }

         //A line is continued if the last character in the line is a '\'
         continuationLine = backslashChar;

         //Reset flags
         separatorChar = FALSE;
         backslashChar = FALSE;

         //Point to the next line
         p += i + 1;
         n -= i + 1;
         i = 0;
      }
      else
      {
         //Check current character
         if(p[i] == ':')
         {
            //A ':' character is used to separate header name and value
            separatorChar = TRUE;
            backslashChar = FALSE;
         }
         else if(p[i] == '\\')
         {
            //A backslash is used at the end of a continued line
            backslashChar = TRUE;
         }
         else if(p[i] == '\r')
         {
            //Discard current character
         }
         else
         {
            //The current line is not a continued line
            backslashChar = FALSE;
         }

         //Next character
         i++;
      }
   }

   //The body of the SSH public key file is Base64-encoded
   error = base64Decode(p, n, output, outputLen);
   //Failed to decode the file?
   if(error)
      return error;

   //Sanity check
   if(*outputLen == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Decode SSH public key file (OpenSSH format)
 * @param[in] input SSH public key file to decode
 * @param[in] inputLen Length of the SSH public key file to decode
 * @param[out] output Pointer to the decoded data (optional parameter)
 * @param[out] outputLen Length of the decoded data
 **/

error_t sshDecodeOpenSshPublicKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;
   size_t i;
   size_t j;
   size_t n;
   const char_t *keyType;

   //Initialize key type
   keyType = NULL;

   //Loop through the list of identifiers
   for(i = 0; i < arraysize(sshKeyTypes); i++)
   {
      //Get the length of the identifier
      n = osStrlen(sshKeyTypes[i].identifier);

      //Matching identifier?
      if(inputLen > n && !osMemcmp(input, sshKeyTypes[i].identifier, n))
      {
         keyType = sshKeyTypes[i].identifier;
         break;
      }
   }

   //Unrecognized key type?
   if(keyType == NULL)
      return ERROR_INVALID_SYNTAX;

   //Get the length of the identifier string
   i = osStrlen(keyType);

   //The identifier must be followed by a whitespace character
   if(input[i] != ' ' && input[i] != '\t')
      return ERROR_INVALID_SYNTAX;

   //Skip whitespace characters
   while(i < inputLen && (input[i] == ' ' || input[i] == '\t'))
   {
      i++;
   }

   //Point to the public key
   j = i;

   //The public key may be followed by a whitespace character and a comment
   while(j < inputLen && (input[j] != ' ' && input[j] != '\t'))
   {
      j++;
   }

   //The public key is Base64-encoded
   error = base64Decode(input + i, j - i, output, outputLen);
   //Failed to decode the file?
   if(error)
      return error;

   //Sanity check
   if(*outputLen == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Decode SSH private key file (OpenSSH format)
 * @param[in] input SSH public key file to decode
 * @param[in] inputLen Length of the SSH private key file to decode
 * @param[out] output Pointer to the decoded data (optional parameter)
 * @param[out] outputLen Length of the decoded data
 **/

error_t sshDecodeOpenSshPrivateKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;
   int_t i;
   int_t n;

   //The first line of the private key file must be a begin marker
   i = sshSearchMarker(input, inputLen, "-----BEGIN OPENSSH PRIVATE KEY-----", 35);
   //Begin marker not found?
   if(i < 0)
      return ERROR_INVALID_SYNTAX;

   //Advance the pointer over the marker
   i += 35;

   //The last line of the private key file must be an end marker
   n = sshSearchMarker(input + i, inputLen - i, "-----END OPENSSH PRIVATE KEY-----", 33);
   //End marker not found?
   if(n < 0)
      return ERROR_INVALID_SYNTAX;

   //The body of the SSH private key file is Base64-encoded
   error = base64Decode(input + i, n, output, outputLen);
   //Failed to decode the file?
   if(error)
      return error;

   //Sanity check
   if(*outputLen == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Search a string for a given marker
 * @param[in] s String to search
 * @param[in] sLen Length of the string to search
 * @param[in] marker String containing the marker to search for
 * @param[in] markerLen Length of the marker
 * @return The index of the first occurrence of the marker in the string,
 *   or -1 if the marker does not appear in the string
 **/

int_t sshSearchMarker(const char_t *s, size_t sLen, const char_t *marker,
   size_t markerLen)
{
   size_t i;
   size_t j;

   //Loop through input string
   for(i = 0; (i + markerLen) <= sLen; i++)
   {
      //Compare current substring with the given marker
      for(j = 0; j < markerLen; j++)
      {
         if(s[i + j] != marker[j])
            break;
      }

      //Check whether the marker has been found
      if(j == markerLen)
         return i;
   }

   //The marker does not appear in the string
   return -1;
}

#endif
