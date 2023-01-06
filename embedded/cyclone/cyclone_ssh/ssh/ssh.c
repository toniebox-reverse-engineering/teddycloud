/**
 * @file ssh.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_algorithms.h"
#include "ssh/ssh_channel.h"
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_cert_import.h"
#include "ssh/ssh_misc.h"
#include "pkix/pem_import.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief SSH context initialization
 * @param[in] context Pointer to the SSH context
 * @param[in] connections SSH connections
 * @param[in] numConnections Maximum number of SSH connections
 * @param[in] channels SSH channels
 * @param[in] numChannels Maximum number of SSH channels
 * @return Error code
 **/

error_t sshInit(SshContext *context, SshConnection *connections,
   uint_t numConnections, SshChannel *channels, uint_t numChannels)
{
   uint_t i;
   error_t error;
   SshConnection *connection;
   SshChannel *channel;

   //Check parameters
   if(context == NULL || connections == NULL || numConnections == 0 ||
      channels == NULL || numChannels == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Initialize status code
   error = NO_ERROR;

   //Clear SSH context
   osMemset(context, 0, sizeof(SshContext));

   //Attach SSH connections
   context->numConnections = numConnections;
   context->connections = connections;

   //Attach SSH channels
   context->numChannels = numChannels;
   context->channels = channels;

   //Start of exception handling block
   do
   {
      //Create a mutex to prevent simultaneous access to the SSH context
      if(!osCreateMutex(&context->mutex))
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //Create an event object to manage connection events
      if(!osCreateEvent(&context->event))
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //Loop through SSH connections
      for(i = 0; i < context->numConnections; i++)
      {
         //Point to the structure describing the current connection
         connection = &context->connections[i];

         //Clear associated structure
         osMemset(connection, 0, sizeof(SshConnection));
         //Attach SSH context
         connection->context = context;
         //Index of the selected host key
         connection->hostKeyIndex = -1;
         //Set default state
         connection->state = SSH_CONN_STATE_CLOSED;
      }

      //Loop through SSH channels
      for(i = 0; i < context->numChannels; i++)
      {
         //Point to the structure describing the current channel
         channel = &context->channels[i];

         //Clear associated structure
         osMemset(channel, 0, sizeof(SshChannel));
         //Attach SSH context
         channel->context = context;
         //Set default state
         channel->state = SSH_CHANNEL_STATE_UNUSED;

         //Create an event object to manage channel events
         if(!osCreateEvent(&channel->event))
         {
            //Report an error
            error = ERROR_OUT_OF_RESOURCES;
            break;
         }
      }

      //End of exception handling block
   } while(0);

   //Check status code
   if(error)
   {
      //Clean up side effects
      sshDeinit(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Set operation mode (client or server)
 * @param[in] context Pointer to the SSH context
 * @param[in] mode Specifies whether this entity is considered a client or a
 *   server
 * @return Error code
 **/

error_t sshSetOperationMode(SshContext *context, SshOperationMode mode)
{
   //Invalid SSH context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(mode != SSH_OPERATION_MODE_CLIENT && mode != SSH_OPERATION_MODE_SERVER)
      return ERROR_INVALID_PARAMETER;

   //Check whether SSH operates as a client or a server
   context->mode = mode;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the pseudo-random number generator to be used
 * @param[in] context Pointer to the SSH context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t sshSetPrng(SshContext *context, const PrngAlgo *prngAlgo,
   void *prngContext)
{
   //Invalid SSH context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL)
      return ERROR_INVALID_PARAMETER;

   //PRNG algorithm that will be used to generate random numbers
   context->prngAlgo = prngAlgo;
   //PRNG context
   context->prngContext = prngContext;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the user name to be used for authentication
 * @param[in] context Pointer to the SSH context
 * @param[in] username NULL-terminated string containing the user name
 * @return Error code
 **/

error_t sshSetUsername(SshContext *context, const char_t *username)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || username == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the user name is acceptable
   if(osStrlen(username) > SSH_MAX_USERNAME_LEN)
      return ERROR_INVALID_LENGTH;

   //Save user name
   osStrcpy(context->username, username);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set the password to be used for authentication
 * @param[in] context Pointer to the SSH context
 * @param[in] password NULL-terminated string containing the password
 * @return Error code
 **/

error_t sshSetPassword(SshContext *context, const char_t *password)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || password == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the password is acceptable
   if(osStrlen(password) > SSH_MAX_PASSWORD_LEN)
      return ERROR_INVALID_LENGTH;

   //Save password
   osStrcpy(context->password, password);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register host key verification callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Host key verification callback function
 * @return Error code
 **/

error_t sshRegisterHostKeyVerifyCallback(SshContext *context,
   SshHostKeyVerifyCallback callback)
{
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->hostKeyVerifyCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register certificate verification callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Certificate verification callback function
 * @return Error code
 **/

error_t sshRegisterCertVerifyCallback(SshContext *context,
   SshCertVerifyCallback callback)
{
#if (SSH_CERT_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->certVerifyCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register CA public key verification callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback CA public key verification callback function
 * @return Error code
 **/

error_t sshRegisterCaPublicKeyVerifyCallback(SshContext *context,
   SshCaPublicKeyVerifyCallback callback)
{
#if (SSH_CERT_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->caPublicKeyVerifyCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register public key authentication callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Public key authentication callback function
 * @return Error code
 **/

error_t sshRegisterPublicKeyAuthCallback(SshContext *context,
   SshPublicKeyAuthCallback callback)
{
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->publicKeyAuthCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register certificate authentication callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Certificate authentication callback function
 * @return Error code
 **/

error_t sshRegisterCertAuthCallback(SshContext *context,
   SshCertAuthCallback callback)
{
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->certAuthCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register password authentication callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Password authentication callback function
 * @return Error code
 **/

error_t sshRegisterPasswordAuthCallback(SshContext *context,
   SshPasswordAuthCallback callback)
{
#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->passwordAuthCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register password change callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Password change callback function
 * @return Error code
 **/

error_t sshRegisterPasswordChangeCallback(SshContext *context,
   SshPasswordChangeCallback callback)
{
#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->passwordChangeCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register signature generation callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Signature generation callback function
 * @return Error code
 **/

error_t sshRegisterSignGenCallback(SshContext *context,
   SshSignGenCallback callback)
{
#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->signGenCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register signature verification callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Signature verification callback function
 * @return Error code
 **/

error_t sshRegisterSignVerifyCallback(SshContext *context,
   SshSignVerifyCallback callback)
{
#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->signVerifyCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register ECDH key pair generation callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback ECDH key pair generation callback function
 * @return Error code
 **/

error_t sshRegisterEcdhKeyPairGenCallback(SshContext *context,
   SshEcdhKeyPairGenCallback callback)
{
#if (SSH_ECDH_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->ecdhKeyPairGenCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register ECDH shared secret calculation callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback ECDH shared secret calculation callback function
 * @return Error code
 **/

error_t sshRegisterEcdhSharedSecretCalcCallback(SshContext *context,
   SshEcdhSharedSecretCalcCallback callback)
{
#if (SSH_ECDH_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Save callback function
   context->ecdhSharedSecretCalcCallback = callback;
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register global request callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Global request callback function
 * @param[in] param An opaque pointer passed to the callback function
 * @return Error code
 **/

error_t sshRegisterGlobalRequestCallback(SshContext *context,
   SshGlobalReqCallback callback, void *param)
{
   error_t error;
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Initialize status code
   error = ERROR_OUT_OF_RESOURCES;

   //Multiple callbacks may be registered
   for(i = 0; i < SSH_MAX_GLOBAL_REQ_CALLBACKS && error; i++)
   {
      //Unused entry?
      if(context->globalReqCallback[i] == NULL)
      {
         //Save callback function
         context->globalReqCallback[i] = callback;
         //This opaque pointer will be directly passed to the callback function
         context->globalReqParam[i] = param;

         //We are done
         error = NO_ERROR;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Unregister global request callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Previously registered callback function
 * @return Error code
 **/

error_t sshUnregisterGlobalRequestCallback(SshContext *context,
   SshGlobalReqCallback callback)
{
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through registered callback functions
   for(i = 0; i < SSH_MAX_GLOBAL_REQ_CALLBACKS; i++)
   {
      //Matching entry?
      if(context->globalReqCallback[i] == callback)
      {
         //Unregister callback function
         context->globalReqCallback[i] = NULL;
         context->globalReqParam[i] = NULL;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register channel request callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Channel request callback function
 * @param[in] param An opaque pointer passed to the callback function
 * @return Error code
 **/

error_t sshRegisterChannelRequestCallback(SshContext *context,
   SshChannelReqCallback callback, void *param)
{
   error_t error;
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Initialize status code
   error = ERROR_OUT_OF_RESOURCES;

   //Multiple callbacks may be registered
   for(i = 0; i < SSH_MAX_CHANNEL_REQ_CALLBACKS && error; i++)
   {
      //Unused entry?
      if(context->channelReqCallback[i] == NULL)
      {
         //Save callback function
         context->channelReqCallback[i] = callback;
         //This opaque pointer will be directly passed to the callback function
         context->channelReqParam[i] = param;

         //We are done
         error = NO_ERROR;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Unregister channel request callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Previously registered callback function
 * @return Error code
 **/

error_t sshUnregisterChannelRequestCallback(SshContext *context,
   SshChannelReqCallback callback)
{
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through registered callback functions
   for(i = 0; i < SSH_MAX_CHANNEL_REQ_CALLBACKS; i++)
   {
      //Matching entry?
      if(context->channelReqCallback[i] == callback)
      {
         //Unregister callback function
         context->channelReqCallback[i] = NULL;
         context->channelReqParam[i] = NULL;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register channel open callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Channel open callback function
 * @param[in] param An opaque pointer passed to the callback function
 * @return Error code
 **/

error_t sshRegisterChannelOpenCallback(SshContext *context,
   SshChannelOpenCallback callback, void *param)
{
   error_t error;
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Initialize status code
   error = ERROR_OUT_OF_RESOURCES;

   //Multiple callbacks may be registered
   for(i = 0; i < SSH_MAX_CHANNEL_OPEN_CALLBACKS && error; i++)
   {
      //Unused entry?
      if(context->channelOpenCallback[i] == NULL)
      {
         //Save callback function
         context->channelOpenCallback[i] = callback;
         //This opaque pointer will be directly passed to the callback function
         context->channelOpenParam[i] = param;

         //We are done
         error = NO_ERROR;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Unregister channel open callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Previously registered callback function
 * @return Error code
 **/

error_t sshUnregisterChannelOpenCallback(SshContext *context,
   SshChannelOpenCallback callback)
{
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through registered callback functions
   for(i = 0; i < SSH_MAX_CHANNEL_OPEN_CALLBACKS; i++)
   {
      //Matching entry?
      if(context->channelOpenCallback[i] == callback)
      {
         //Unregister callback function
         context->channelOpenCallback[i] = NULL;
         context->channelOpenParam[i] = NULL;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register connection open callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Connection open callback function
 * @param[in] param An opaque pointer passed to the callback function
 * @return Error code
 **/

error_t sshRegisterConnectionOpenCallback(SshContext *context,
   SshConnectionOpenCallback callback, void *param)
{
   error_t error;
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Initialize status code
   error = ERROR_OUT_OF_RESOURCES;

   //Multiple callbacks may be registered
   for(i = 0; i < SSH_MAX_CONN_OPEN_CALLBACKS && error; i++)
   {
      //Unused entry?
      if(context->connectionOpenCallback[i] == NULL)
      {
         //Save callback function
         context->connectionOpenCallback[i] = callback;
         //This opaque pointer will be directly passed to the callback function
         context->connectionOpenParam[i] = param;

         //We are done
         error = NO_ERROR;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Unregister connection open callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Previously registered callback function
 * @return Error code
 **/

error_t sshUnregisterConnectionOpenCallback(SshContext *context,
   SshConnectionOpenCallback callback)
{
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through registered callback functions
   for(i = 0; i < SSH_MAX_CONN_OPEN_CALLBACKS; i++)
   {
      //Matching entry?
      if(context->connectionOpenCallback[i] == callback)
      {
         //Unregister callback function
         context->connectionOpenCallback[i] = NULL;
         context->connectionOpenParam[i] = NULL;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register connection close callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Connection close callback function
 * @param[in] param An opaque pointer passed to the callback function
 * @return Error code
 **/

error_t sshRegisterConnectionCloseCallback(SshContext *context,
   SshConnectionCloseCallback callback, void *param)
{
   error_t error;
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Initialize status code
   error = ERROR_OUT_OF_RESOURCES;

   //Multiple callbacks may be registered
   for(i = 0; i < SSH_MAX_CONN_CLOSE_CALLBACKS && error; i++)
   {
      //Unused entry?
      if(context->connectionCloseCallback[i] == NULL)
      {
         //Save callback function
         context->connectionCloseCallback[i] = callback;
         //This opaque pointer will be directly passed to the callback function
         context->connectionCloseParam[i] = param;

         //We are done
         error = NO_ERROR;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Unregister connection close callback function
 * @param[in] context Pointer to the SSH context
 * @param[in] callback Previously registered callback function
 * @return Error code
 **/

error_t sshUnregisterConnectionCloseCallback(SshContext *context,
   SshConnectionCloseCallback callback)
{
   uint_t i;

   //Check parameters
   if(context == NULL || callback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through registered callback functions
   for(i = 0; i < SSH_MAX_CONN_CLOSE_CALLBACKS; i++)
   {
      //Matching entry?
      if(context->connectionCloseCallback[i] == callback)
      {
         //Unregister callback function
         context->connectionCloseCallback[i] = NULL;
         context->connectionCloseParam[i] = NULL;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Load transient RSA key (for RSA key exchange)
 * @param[in] context Pointer to the SSH context
 * @param[in] index Zero-based index identifying a slot
 * @param[in] publicKey RSA public key (PEM, SSH2 or OpenSSH format). This
 *   parameter is taken as reference
 * @param[in] publicKeyLen Length of the RSA public key
 * @param[in] privateKey RSA private key (PEM or OpenSSH format). This
 *   parameter is taken as reference
 * @param[in] privateKeyLen Length of the RSA private key
 * @return Error code
 **/

error_t sshLoadRsaKey(SshContext *context, uint_t index,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen)
{
#if (SSH_SERVER_SUPPORT == ENABLED && SSH_RSA_KEX_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   RsaPublicKey rsaPublicKey;
   RsaPrivateKey rsaPrivateKey;

   //Make sure the SSH context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check index
   if(index >= SSH_MAX_RSA_KEYS)
      return ERROR_INVALID_PARAMETER;

   //Check public key
   if(publicKey == NULL || publicKeyLen == 0)
      return ERROR_INVALID_PARAMETER;

   //Check private key
   if(privateKey == NULL || publicKeyLen == 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize RSA public and private keys
   rsaInitPublicKey(&rsaPublicKey);
   rsaInitPrivateKey(&rsaPrivateKey);

   //Check whether the RSA public key is valid
   error = sshImportRsaPublicKey(publicKey, publicKeyLen, &rsaPublicKey);

   //Check status code
   if(!error)
   {
      //Check whether the RSA private key is valid
      error = sshImportRsaPrivateKey(privateKey, privateKeyLen,
         &rsaPrivateKey);
   }

   //Check status code
   if(!error)
   {
      //Get the length of the modulus, in bits
      k = mpiGetBitLength(&rsaPublicKey.n);

      //Make sure the prime modulus is acceptable
      if(k < SSH_MIN_RSA_MODULUS_SIZE || k > SSH_MAX_RSA_MODULUS_SIZE)
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Release previously allocated memory
   rsaFreePublicKey(&rsaPublicKey);
   rsaFreePrivateKey(&rsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Acquire exclusive access to the SSH context
      osAcquireMutex(&context->mutex);

      //Save the length of the modulus, in bits
      context->rsaKeys[index].modulusSize = k;

      //Save public key (PEM, SSH2 or OpenSSH format)
      context->rsaKeys[index].publicKey = publicKey;
      context->rsaKeys[index].publicKeyLen = publicKeyLen;

      //Save private key (PEM or OpenSSH format)
      context->rsaKeys[index].privateKey = privateKey;
      context->rsaKeys[index].privateKeyLen = privateKeyLen;

      //Release exclusive access to the SSH context
      osReleaseMutex(&context->mutex);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Unload transient RSA key (for RSA key exchange)
 * @param[in] context Pointer to the SSH context
 * @param[in] index Zero-based index identifying a slot
 * @return Error code
 **/

error_t sshUnloadRsaKey(SshContext *context, uint_t index)
{
#if (SSH_SERVER_SUPPORT == ENABLED && SSH_RSA_KEX_SUPPORT == ENABLED)
   //Make sure the SSH context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check index
   if(index >= SSH_MAX_RSA_KEYS)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Unload the specified transient RSA key
   osMemset(&context->rsaKeys[index], 0, sizeof(SshRsaKey));
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Load Diffie-Hellman group
 * @param[in] context Pointer to the SSH context
 * @param[in] index Zero-based index identifying a slot
 * @param[in] dhParams Diffie-Hellman parameters (PEM format). This parameter
 *   is taken as reference
 * @param[in] dhParamsLen Length of the Diffie-Hellman parameters
 * @return Error code
 **/

error_t sshLoadDhGexGroup(SshContext *context, uint_t index,
   const char_t *dhParams, size_t dhParamsLen)
{
#if (SSH_SERVER_SUPPORT == ENABLED && SSH_DH_GEX_KEX_SUPPORT == ENABLED)
   error_t error;
   uint_t k;
   DhParameters params;

   //Make sure the SSH context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The implementation limits the number of Diffie-Hellman groups that can
   //be loaded
   if(index >= SSH_MAX_DH_GEX_GROUPS)
      return ERROR_INVALID_PARAMETER;

   //Check Diffie-Hellman parameters
   if(dhParams == NULL || dhParamsLen == 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize Diffie-Hellman parameters
   dhInitParameters(&params);

   //Decode the PEM structure that holds Diffie-Hellman parameters
   error = pemImportDhParameters(dhParams, dhParamsLen, &params);

   //Check status code
   if(!error)
   {
      //Get the length of the prime modulus, in bits
      k = mpiGetBitLength(&params.p);

      //Make sure the prime modulus is acceptable
      if(k < SSH_MIN_DH_MODULUS_SIZE || k > SSH_MAX_DH_MODULUS_SIZE)
      {
         //Report an error
         error = ERROR_INVALID_LENGTH;
      }
   }

   //Release previously allocated memory
   dhFreeParameters(&params);

   //Check status code
   if(!error)
   {
      //Acquire exclusive access to the SSH context
      osAcquireMutex(&context->mutex);

      //Save the length of the prime modulus, in bits
      context->dhGexGroups[index].dhModulusSize = k;

      //Save Diffie-Hellman parameters (PEM format)
      context->dhGexGroups[index].dhParams = dhParams;
      context->dhGexGroups[index].dhParamsLen = dhParamsLen;

      //Release exclusive access to the SSH context
      osReleaseMutex(&context->mutex);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Unload Diffie-Hellman group
 * @param[in] context Pointer to the SSH context
 * @param[in] index Zero-based index identifying a slot
 * @return Error code
 **/

error_t sshUnloadDhGexGroup(SshContext *context, uint_t index)
{
#if (SSH_SERVER_SUPPORT == ENABLED && SSH_DH_GEX_KEX_SUPPORT == ENABLED)
   //Make sure the SSH context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check index
   if(index >= SSH_MAX_DH_GEX_GROUPS)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);
   //Unload the specified Diffie-Hellman group
   osMemset(&context->dhGexGroups[index], 0, sizeof(SshDhGexGroup));
   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Load entity's host key
 * @param[in] context Pointer to the SSH context
 * @param[in] index Zero-based index identifying a slot
 * @param[in] publicKey Public key (PEM, SSH2 or OpenSSH format). This parameter
 *   is taken as reference
 * @param[in] publicKeyLen Length of the public key
 * @param[in] privateKey Private key (PEM or OpenSSH format). This parameter is
 *   taken as reference
 * @param[in] privateKeyLen Length of the private key
 * @return Error code
 **/

error_t sshLoadHostKey(SshContext *context, uint_t index,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen)
{
   error_t error;
   SshHostKey *hostKey;
   const char_t *keyType;

   //Make sure the SSH context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The implementation limits the number of host keys that can be loaded
   if(index >= SSH_MAX_HOST_KEYS)
      return ERROR_INVALID_PARAMETER;

   //Check public key
   if(publicKey == NULL || publicKeyLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The private key is optional
   if(privateKey == NULL && privateKeyLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Retrieve public key type
   keyType = sshGetPublicKeyType(publicKey, publicKeyLen);

#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   //RSA host key?
   if(sshCompareAlgo(keyType, "ssh-rsa"))
   {
      RsaPublicKey rsaPublicKey;
      RsaPrivateKey rsaPrivateKey;

      //Initialize RSA public and private keys
      rsaInitPublicKey(&rsaPublicKey);
      rsaInitPrivateKey(&rsaPrivateKey);

      //Check whether the RSA public key is valid
      error = sshImportRsaPublicKey(publicKey, publicKeyLen, &rsaPublicKey);

      //Check status code
      if(!error)
      {
         //The private key can be omitted if a public-key hardware accelerator
         //is used to generate signatures
         if(privateKey != NULL)
         {
            //Check whether the RSA private key is valid
            error = sshImportRsaPrivateKey(privateKey, privateKeyLen,
               &rsaPrivateKey);
         }
      }

      //Release previously allocated memory
      rsaFreePublicKey(&rsaPublicKey);
      rsaFreePrivateKey(&rsaPrivateKey);
   }
   else
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   //DSA host key?
   if(sshCompareAlgo(keyType, "ssh-dss"))
   {
      DsaPublicKey dsaPublicKey;
      DsaPrivateKey dsaPrivateKey;

      //Initialize DSA public and private keys
      dsaInitPublicKey(&dsaPublicKey);
      dsaInitPrivateKey(&dsaPrivateKey);

      //Check whether the DSA public key is valid
      error = sshImportDsaPublicKey(publicKey, publicKeyLen, &dsaPublicKey);

      //Check status code
      if(!error)
      {
         //The private key can be omitted if a public-key hardware accelerator
         //is used to generate signatures
         if(privateKey != NULL)
         {
            //Check whether the DSA private key is valid
            error = sshImportDsaPrivateKey(privateKey, privateKeyLen,
               &dsaPrivateKey);
         }
      }

      //Release previously allocated memory
      dsaFreePublicKey(&dsaPublicKey);
      dsaFreePrivateKey(&dsaPrivateKey);
   }
   else
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA host key?
   if(sshCompareAlgo(keyType, "ecdsa-sha2-nistp256") ||
      sshCompareAlgo(keyType, "ecdsa-sha2-nistp384") ||
      sshCompareAlgo(keyType, "ecdsa-sha2-nistp521"))
   {
      EcDomainParameters ecParams;
      EcPublicKey ecPublicKey;
      EcPrivateKey ecPrivateKey;

      //Initialize ECDSA public and private keys
      ecInitDomainParameters(&ecParams);
      ecInitPublicKey(&ecPublicKey);
      ecInitPrivateKey(&ecPrivateKey);

      //Check whether the ECDSA public key is valid
      error = sshImportEcdsaPublicKey(publicKey, publicKeyLen, &ecParams,
         &ecPublicKey);

      //Check status code
      if(!error)
      {
         //The private key can be omitted if a public-key hardware accelerator
         //is used to generate signatures
         if(privateKey != NULL)
         {
            //Check whether the ECDSA private key is valid
            error = sshImportEcdsaPrivateKey(privateKey, privateKeyLen,
               &ecPrivateKey);
         }
      }

      //Release previously allocated memory
      ecFreeDomainParameters(&ecParams);
      ecFreePublicKey(&ecPublicKey);
      ecFreePrivateKey(&ecPrivateKey);
   }
   else
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   //Ed25519 host key?
   if(sshCompareAlgo(keyType, "ssh-ed25519"))
   {
      EddsaPublicKey eddsaPublicKey;
      EddsaPrivateKey eddsaPrivateKey;

      //Initialize EdDSA public and private keys
      eddsaInitPublicKey(&eddsaPublicKey);
      eddsaInitPrivateKey(&eddsaPrivateKey);

      //Check whether the EdDSA public key is valid
      error = sshImportEd25519PublicKey(publicKey, publicKeyLen,
         &eddsaPublicKey);

      //Check status code
      if(!error)
      {
         //The private key can be omitted if a public-key hardware accelerator
         //is used to generate signatures
         if(privateKey != NULL)
         {
            //Check whether the EdDSA private key is valid
            error = sshImportEd25519PrivateKey(privateKey, privateKeyLen,
               &eddsaPrivateKey);
         }
      }

      //Release previously allocated memory
      eddsaFreePublicKey(&eddsaPublicKey);
      eddsaFreePrivateKey(&eddsaPrivateKey);
   }
   else
#endif
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   //Ed448 host key?
   if(sshCompareAlgo(keyType, "ssh-ed448"))
   {
      EddsaPublicKey eddsaPublicKey;
      EddsaPrivateKey eddsaPrivateKey;

      //Initialize EdDSA public and private keys
      eddsaInitPublicKey(&eddsaPublicKey);
      eddsaInitPrivateKey(&eddsaPrivateKey);

      //Check whether the EdDSA public key is valid
      error = sshImportEd448PublicKey(publicKey, publicKeyLen,
         &eddsaPublicKey);

      //Check status code
      if(!error)
      {
         //The private key can be omitted if a public-key hardware accelerator
         //is used to generate signatures
         if(privateKey != NULL)
         {
            //Check whether the EdDSA private key is valid
            error = sshImportEd448PrivateKey(privateKey, privateKeyLen,
               &eddsaPrivateKey);
         }
      }

      //Release previously allocated memory
      eddsaFreePublicKey(&eddsaPublicKey);
      eddsaFreePrivateKey(&eddsaPrivateKey);
   }
   else
#endif
   //Invalid host key?
   {
      //Report an error
      error = ERROR_INVALID_KEY;
   }

   //Check status code
   if(!error)
   {
      //Acquire exclusive access to the SSH context
      osAcquireMutex(&context->mutex);

      //Point to the specified slot
      hostKey = &context->hostKeys[index];

      //Set key format identifier
      hostKey->keyFormatId = keyType;

      //Save public key (PEM, SSH2 or OpenSSH format)
      hostKey->publicKey = publicKey;
      hostKey->publicKeyLen = publicKeyLen;

      //Save private key (PEM or OpenSSH format)
      hostKey->privateKey = privateKey;
      hostKey->privateKeyLen = privateKeyLen;

#if (SSH_CLIENT_SUPPORT == ENABLED)
      //Select the default public key algorithm to use during user
      //authentication
      hostKey->publicKeyAlgo = sshSelectPublicKeyAlgo(context,
         hostKey->keyFormatId, NULL);
#endif

      //Release exclusive access to the SSH context
      osReleaseMutex(&context->mutex);
   }

   //Return status code
   return error;
}


/**
 * @brief Unload entity's host key
 * @param[in] context Pointer to the SSH context
 * @param[in] index Zero-based index identifying a slot
 * @return Error code
 **/

error_t sshUnloadHostKey(SshContext *context, uint_t index)
{
   uint_t i;
   SshConnection *connection;

   //Make sure the SSH context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check index
   if(index >= SSH_MAX_HOST_KEYS)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through SSH connections
   for(i = 0; i < context->numConnections; i++)
   {
      //Point to the structure describing the current connection
      connection = &context->connections[i];

      //Key exchange in progress?
      if(connection->state > SSH_CONN_STATE_CLOSED &&
         connection->state < SSH_CONN_STATE_OPEN)
      {
         //Check whether the key pair is currently in use
         if(connection->hostKeyIndex == index)
         {
            //Terminate the connection immediately
            connection->disconnectRequest = TRUE;
            //Notify the SSH core of the event
            sshNotifyEvent(context);
         }
      }
   }

   //Unload the specified key pair
   osMemset(&context->hostKeys[index], 0, sizeof(SshHostKey));

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Load entity's certificate
 * @param[in] context Pointer to the SSH context
 * @param[in] index Zero-based index identifying a slot
 * @param[in] cert Certificate (OpenSSH format). This parameter is taken
 *   as reference
 * @param[in] certLen Length of the certificate
 * @param[in] privateKey Private key (PEM or OpenSSH format). This parameter
 *   is taken as reference
 * @param[in] privateKeyLen Length of the private key
 * @return Error code
 **/

error_t sshLoadCertificate(SshContext *context, uint_t index,
   const char_t *cert, size_t certLen, const char_t *privateKey,
   size_t privateKeyLen)
{
#if (SSH_CERT_SUPPORT == ENABLED)
   error_t error;
   SshHostKey *hostKey;
   const char_t *certType;

   //Make sure the SSH context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The implementation limits the number of certificates that can be loaded
   if(index >= SSH_MAX_HOST_KEYS)
      return ERROR_INVALID_PARAMETER;

   //Check certificate
   if(cert == NULL || certLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The private key is optional
   if(privateKey == NULL && privateKeyLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Retrieve certificate type
   certType = sshGetCertType(cert, certLen);

#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   //RSA certificate?
   if(sshCompareAlgo(certType, "ssh-rsa-cert-v01@openssh.com"))
   {
      RsaPrivateKey rsaPrivateKey;

      //Initialize RSA private key
      rsaInitPrivateKey(&rsaPrivateKey);

      //The private key can be omitted if a public-key hardware accelerator
      //is used to generate signatures
      if(privateKey != NULL)
      {
         //Check whether the RSA private key is valid
         error = sshImportRsaPrivateKey(privateKey, privateKeyLen,
            &rsaPrivateKey);
      }

      //Release previously allocated memory
      rsaFreePrivateKey(&rsaPrivateKey);
   }
   else
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   //DSA certificate?
   if(sshCompareAlgo(certType, "ssh-dss-cert-v01@openssh.com"))
   {
      DsaPrivateKey dsaPrivateKey;

      //Initialize DSA private key
      dsaInitPrivateKey(&dsaPrivateKey);

      //The private key can be omitted if a public-key hardware accelerator
      //is used to generate signatures
      if(privateKey != NULL)
      {
         //Check whether the DSA private key is valid
         error = sshImportDsaPrivateKey(privateKey, privateKeyLen,
            &dsaPrivateKey);
      }

      //Release previously allocated memory
      dsaFreePrivateKey(&dsaPrivateKey);
   }
   else
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   //ECDSA certificate?
   if(sshCompareAlgo(certType, "ecdsa-sha2-nistp256-cert-v01@openssh.com") ||
      sshCompareAlgo(certType, "ecdsa-sha2-nistp384-cert-v01@openssh.com") ||
      sshCompareAlgo(certType, "ecdsa-sha2-nistp521-cert-v01@openssh.com"))
   {
      EcPrivateKey ecPrivateKey;

      //Initialize EC private key
      ecInitPrivateKey(&ecPrivateKey);

      //The private key can be omitted if a public-key hardware accelerator
      //is used to generate signatures
      if(privateKey != NULL)
      {
         //Check whether the EC private key is valid
         error = sshImportEcdsaPrivateKey(privateKey, privateKeyLen,
            &ecPrivateKey);
      }

      //Release previously allocated memory
      ecFreePrivateKey(&ecPrivateKey);
   }
   else
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   //Ed25519 certificate?
   if(sshCompareAlgo(certType, "ssh-ed25519-cert-v01@openssh.com"))
   {
      EddsaPrivateKey ed25519PrivateKey;

      //Initialize Ed25519 private key
      eddsaInitPrivateKey(&ed25519PrivateKey);

      //The private key can be omitted if a public-key hardware accelerator
      //is used to generate signatures
      if(privateKey != NULL)
      {
         //Check whether the EdDSA private key is valid
         error = sshImportEd25519PrivateKey(privateKey, privateKeyLen,
            &ed25519PrivateKey);
      }

      //Release previously allocated memory
      eddsaFreePrivateKey(&ed25519PrivateKey);
   }
   else
#endif
   //Invalid certificate?
   {
      //Report an error
      error = ERROR_BAD_CERTIFICATE;
   }

   //Check status code
   if(!error)
   {
      //Acquire exclusive access to the SSH context
      osAcquireMutex(&context->mutex);

      //Point to the specified slot
      hostKey = &context->hostKeys[index];

      //Set key format identifier
      hostKey->keyFormatId = certType;

      //Save certificate (OpenSSH format)
      hostKey->publicKey = cert;
      hostKey->publicKeyLen = certLen;

      //Save private key (PEM or OpenSSH format)
      hostKey->privateKey = privateKey;
      hostKey->privateKeyLen = privateKeyLen;

#if (SSH_CLIENT_SUPPORT == ENABLED)
      //Select the default public key algorithm to use during user
      //authentication
      hostKey->publicKeyAlgo = sshSelectPublicKeyAlgo(context,
         hostKey->keyFormatId, NULL);
#endif

      //Release exclusive access to the SSH context
      osReleaseMutex(&context->mutex);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Unload entity's certificate
 * @param[in] context Pointer to the SSH context
 * @param[in] index Zero-based index identifying a slot
 * @return Error code
 **/

error_t sshUnloadCertificate(SshContext *context, uint_t index)
{
#if (SSH_CERT_SUPPORT == ENABLED)
   uint_t i;
   SshConnection *connection;

   //Make sure the SSH context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check index
   if(index >= SSH_MAX_HOST_KEYS)
      return ERROR_INVALID_PARAMETER;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through SSH connections
   for(i = 0; i < context->numConnections; i++)
   {
      //Point to the structure describing the current connection
      connection = &context->connections[i];

      //Key exchange in progress?
      if(connection->state > SSH_CONN_STATE_CLOSED &&
         connection->state < SSH_CONN_STATE_OPEN)
      {
         //Check whether the certificate is currently in use
         if(connection->hostKeyIndex == index)
         {
            //Terminate the connection immediately
            connection->disconnectRequest = TRUE;
            //Notify the SSH core of the event
            sshNotifyEvent(context);
         }
      }
   }

   //Unload the specified certificate
   osMemset(&context->hostKeys[index], 0, sizeof(SshHostKey));

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set password change prompt message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] prompt  NULL-terminated string containing the prompt message
 * @return Error code
 **/

error_t sshSetPasswordChangePrompt(SshConnection *connection,
   const char_t *prompt)
{
#if (SSH_SERVER_SUPPORT == ENABLED && SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
   //Check parameters
   if(connection == NULL || prompt == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the prompt string is acceptable
   if(osStrlen(prompt) > SSH_MAX_PASSWORD_CHANGE_PROMPT_LEN)
      return ERROR_INVALID_LENGTH;

   //Save prompt string
   osStrcpy(connection->passwordChangePrompt, prompt);

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Create a new SSH channel
 * @param[in] connection Pointer to the SSH connection
 * @return Handle referencing the newly created SSH channel
 **/

SshChannel *sshCreateChannel(SshConnection *connection)
{
   uint_t i;
   SshContext *context;
   SshChannel *channel;
   OsEvent event;

   //Initialize handle
   channel = NULL;

   //Point to the SSH context
   context = connection->context;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through SSH channels
   for(i = 0; i < context->numChannels; i++)
   {
      //Unused SSH channel?
      if(context->channels[i].state == SSH_CHANNEL_STATE_UNUSED)
      {
         //Point to the current SSH channel
         channel = &context->channels[i];

         //Save event object instance
         osMemcpy(&event, &channel->event, sizeof(OsEvent));
         //Clear associated structure
         osMemset(channel, 0, sizeof(SshChannel));
         //Reuse event objects and avoid recreating them whenever possible
         osMemcpy(&channel->event, &event, sizeof(OsEvent));

         //Initialize channel's parameters
         channel->context = context;
         channel->connection = connection;
         channel->timeout = INFINITE_DELAY;
         channel->rxWindowSize = SSH_CHANNEL_BUFFER_SIZE;

         //When the implementation wish to open a new channel, it allocates a
         //local number for the channel (refer to RFC 4254, section 5.1)
         channel->localChannelNum = sshAllocateLocalChannelNum(connection);

         //The SSH channel has been successfully allocated
         channel->state = SSH_CHANNEL_STATE_RESERVED;

         //We are done
         break;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Return a handle to the newly created SSH channel
   return channel;
}


/**
 * @brief Set timeout for read/write operations
 * @param[in] channel SSH channel handle
 * @param[in] timeout Maximum time to wait
 * @return Error code
 **/

error_t sshSetChannelTimeout(SshChannel *channel, systime_t timeout)
{
   //Make sure the SSH channel handle is valid
   if(channel == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   channel->timeout = timeout;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Write data to the specified channel
 * @param[in] channel SSH channel handle
 * @param[in] data Pointer to the buffer containing the data to be transmitted
 * @param[in] length Number of data bytes to send
 * @param[out] written Actual number of bytes written (optional parameter)
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t sshWriteChannel(SshChannel *channel, const void *data, size_t length,
   size_t *written, uint_t flags)
{
   error_t error;
   size_t n;
   size_t totalLength;
   uint_t event;
   SshChannelBuffer *txBuffer;

   //Make sure the SSH channel handle is valid
   if(channel == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;
   //Point to the transmission buffer
   txBuffer = &channel->txBuffer;
   //Actual number of bytes written
   totalLength = 0;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&channel->context->mutex);

   //Send as much data as possible
   while(totalLength < length && !error)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->eofRequest &&
         !channel->eofSent && !channel->closeRequest && !channel->closeSent)
      {
         //Check whether the send buffer is available for writing
         if(txBuffer->length < SSH_CHANNEL_BUFFER_SIZE)
         {
            //Limit the number of bytes to write at a time
            n = SSH_CHANNEL_BUFFER_SIZE - txBuffer->length;
            n = MIN(n, length - totalLength);

            //Prevent memory writes from crossing buffer boundaries
            if((txBuffer->writePos + n) > SSH_CHANNEL_BUFFER_SIZE)
            {
               n = SSH_CHANNEL_BUFFER_SIZE - txBuffer->writePos;
            }

            //Copy data
            osMemcpy(txBuffer->data + txBuffer->writePos, data, n);

            //Advance the data pointer
            data = (uint8_t *) data + n;
            //Advance write position
            txBuffer->writePos += n;

            //Wrap around if necessary
            if(txBuffer->writePos >= SSH_CHANNEL_BUFFER_SIZE)
            {
               txBuffer->writePos -= SSH_CHANNEL_BUFFER_SIZE;
            }

            //Update buffer length
            txBuffer->length += n;
            //Update byte counter
            totalLength += n;
         }
         else
         {
            //Notify the SSH context that data is pending in the send buffer
            sshNotifyEvent(channel->context);

            //Wait until there is more room in the send buffer
            event = sshWaitForChannelEvents(channel, SSH_CHANNEL_EVENT_TX_READY,
               channel->timeout);

            //Channel not available for writing?
            if(event != SSH_CHANNEL_EVENT_TX_READY)
            {
               //Report a timeout error
               error = ERROR_TIMEOUT;
            }
         }
      }
      else
      {
         //The channel is not writable
         error = ERROR_WRITE_FAILED;
      }
   }

   //Check whether all the data has been written
   if(totalLength == length)
   {
      //When a party will no longer send more data to a channel, it should
      //send an SSH_MSG_CHANNEL_EOF message (refer to RFC 4254, section 5.3)
      if((flags & SSH_FLAG_EOF) != 0)
      {
         channel->eofRequest = TRUE;
      }
   }

   //Notify the SSH core that data is pending in the send buffer
   sshNotifyEvent(channel->context);

   //Release exclusive access to the SSH context
   osReleaseMutex(&channel->context->mutex);

   //The parameter is optional
   if(written != NULL)
   {
      //Total number of data that have been written
      *written = totalLength;
   }

   //Return status code
   return error;
}


/**
 * @brief Receive data from the specified channel
 * @param[in] channel SSH channel handle
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be received
 * @param[out] received Number of bytes that have been received
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t sshReadChannel(SshChannel *channel, void *data, size_t size,
   size_t *received, uint_t flags)
{
   error_t error;
   size_t n;
   uint_t event;
   SshChannelBuffer *rxBuffer;

   //Check parameters
   if(channel == NULL || data == NULL || received == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;
   //Point to the receive buffer
   rxBuffer = &channel->rxBuffer;
   //No data has been read yet
   *received = 0;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&channel->context->mutex);

   //Read as much data as possible
   while(*received < size && !error)
   {
      //Any data pending in the receive buffer?
      if(rxBuffer->length > 0)
      {
         //Check channel state
         if(channel->state == SSH_CHANNEL_STATE_OPEN)
         {
            //Compute the number of bytes available for reading
            n = MIN(rxBuffer->length, size - *received);

            //Limit the number of bytes to copy at a time
            if((rxBuffer->readPos + n) > SSH_CHANNEL_BUFFER_SIZE)
            {
               n = SSH_CHANNEL_BUFFER_SIZE - rxBuffer->readPos;
            }

            //Check flags
            if((flags & SSH_FLAG_BREAK_CHAR) != 0)
            {
               char_t c;
               size_t i;

               //Retrieve the break character code
               c = LSB(flags);

               //Search for the specified break character
               for(i = 0; i < n; i++)
               {
                  if(rxBuffer->data[rxBuffer->readPos + i] == c)
                  {
                     break;
                  }
               }

               //Adjust the number of data to read
               n = MIN(n, i + 1);
            }

            //Copy data to user buffer
            osMemcpy(data, rxBuffer->data + rxBuffer->readPos, n);

            //Advance read position
            rxBuffer->readPos += n;

            //Wrap around if necessary
            if(rxBuffer->readPos >= SSH_CHANNEL_BUFFER_SIZE)
            {
               rxBuffer->readPos = 0;
            }

            //Update buffer length
            rxBuffer->length -= n;
            //Total number of bytes that have been received
            *received += n;

            //Update flow-control window
            sshUpdateChannelWindow(channel, n);

            //The SSH_FLAG_BREAK_CHAR flag causes the function to stop reading
            //data as soon as the specified break character is encountered
            if((flags & SSH_FLAG_BREAK_CHAR) != 0)
            {
               //Check whether a break character has been found
               if(n > 0 && ((uint8_t *) data)[n - 1] == LSB(flags))
               {
                  break;
               }
            }

            //The SSH_FLAG_WAIT_ALL flag causes the function to return only
            //when the requested number of bytes have been read
            if((flags & SSH_FLAG_WAIT_ALL) == 0)
            {
               break;
            }

            //Advance data pointer
            data = (uint8_t *) data + n;
         }
         else
         {
            //The channel is not readable
            error = ERROR_READ_FAILED;
         }
      }
      else
      {
         //Check channel state
         if(channel->state == SSH_CHANNEL_STATE_OPEN)
         {
            //Check whether an SSH_MSG_CHANNEL_EOF or SSH_MSG_CHANNEL_CLOSE
            //message has been received
            if(channel->closeReceived || channel->eofReceived ||
               channel->connection->disconnectReceived)
            {
               //The peer will no longer send data to the channel
               error = ERROR_END_OF_STREAM;
            }
            else
            {
               //Wait for data to be available for reading
               event = sshWaitForChannelEvents(channel,
                  SSH_CHANNEL_EVENT_RX_READY, channel->timeout);

               //Channel not available for reading?
               if(event != SSH_CHANNEL_EVENT_RX_READY)
               {
                  //Report a timeout error
                  error = ERROR_TIMEOUT;
               }
            }
         }
         else if(channel->state == SSH_CHANNEL_STATE_CLOSED)
         {
            //The peer will no longer send data to the channel
            if(channel->closeReceived || channel->eofReceived ||
               channel->connection->disconnectReceived)
            {
               error = ERROR_END_OF_STREAM;
            }
            else if(channel->connection->disconnectSent)
            {
               error = ERROR_CONNECTION_CLOSING;
            }
            else
            {
               error = ERROR_READ_FAILED;
            }
         }
         else
         {
            //The channel is not readable
            error = ERROR_READ_FAILED;
         }
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&channel->context->mutex);

   //Check status code
   if(error == ERROR_END_OF_STREAM)
   {
      //Check flags
      if((flags & SSH_FLAG_BREAK_CHAR) != 0 || (flags & SSH_FLAG_WAIT_ALL) == 0)
      {
         //The user must be satisfied with data already on hand
         if(*received > 0)
         {
            error = NO_ERROR;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Wait for one of a set of channels to become ready to perform I/O
 *
 * This function determines the status of one or more channels, waiting if
 *   necessary, to perform synchronous I/O
 *
 * @param[in,out] eventDesc Set of entries specifying the events the user is interested in
 * @param[in] size Number of entries in the descriptor set
 * @param[in] extEvent External event that can abort the wait if necessary (optional)
 * @param[in] timeout Maximum time to wait before returning
 * @return Error code
 **/

error_t sshPollChannels(SshChannelEventDesc *eventDesc, uint_t size,
   OsEvent *extEvent, systime_t timeout)
{
   uint_t i;
   bool_t status;
   OsEvent *event;
   OsEvent eventObject;

   //Check parameters
   if(eventDesc == NULL || size == 0)
      return ERROR_INVALID_PARAMETER;

   //Try to use the supplied event object to receive notifications
   if(!extEvent)
   {
      //Create an event object only if necessary
      if(!osCreateEvent(&eventObject))
      {
         //Report an error
         return ERROR_OUT_OF_RESOURCES;
      }

      //Reference to the newly created event
      event = &eventObject;
   }
   else
   {
      //Reference to the external event
      event = extEvent;
   }

   //Loop through descriptors
   for(i = 0; i < size; i++)
   {
      //Valid channel handle?
      if(eventDesc[i].channel != NULL)
      {
         //Clear event flags
         eventDesc[i].eventFlags = 0;

         //Subscribe to the requested events
         sshRegisterUserEvents(eventDesc[i].channel, event,
            eventDesc[i].eventMask);
      }
   }

   //Block the current task until an event occurs
   status = osWaitForEvent(event, timeout);

   //Loop through descriptors
   for(i = 0; i < size; i++)
   {
      //Valid channel handle?
      if(eventDesc[i].channel != NULL)
      {
         //Any channel event in the signaled state?
         if(status)
         {
            //Retrieve event flags for the current channel
            eventDesc[i].eventFlags = sshGetUserEvents(eventDesc[i].channel);
            //Clear unnecessary flags
            eventDesc[i].eventFlags &= eventDesc[i].eventMask;
         }

         //Unsubscribe previously registered events
         sshUnregisterUserEvents(eventDesc[i].channel);
      }
   }

   //Reset event object
   osResetEvent(event);

   //Release previously allocated resources
   if(!extEvent)
   {
      osDeleteEvent(&eventObject);
   }

   //Return status code
   return status ? NO_ERROR : ERROR_TIMEOUT;
}


/**
 * @brief Close channel
 * @param[in] channel SSH channel handle
 * @return Error code
 **/

error_t sshCloseChannel(SshChannel *channel)
{
   error_t error;
   uint_t event;

   //Make sure the SSH channel handle is valid
   if(channel == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&channel->context->mutex);

   //Check channel state
   if(channel->state == SSH_CHANNEL_STATE_OPEN)
   {
      //When either party wishes to terminate the channel, it sends
      //SSH_MSG_CHANNEL_CLOSE
      if(!channel->closeRequest)
      {
         //Request closure of the channel
         channel->closeRequest = TRUE;
         //Notify the SSH context that the channel should be closed
         sshNotifyEvent(channel->context);
      }

      //Client mode operation?
      if(channel->context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         //Wait for the channel to close
         event = sshWaitForChannelEvents(channel, SSH_CHANNEL_EVENT_CLOSED,
            channel->timeout);

         //Check whether the channel is properly closed
         if(event != SSH_CHANNEL_EVENT_CLOSED)
         {
            //Report a timeout error
            error = ERROR_TIMEOUT;
         }
      }
   }
   else if(channel->state == SSH_CHANNEL_STATE_CLOSED)
   {
      //The channel is considered closed for a party when it has both sent
      //and received SSH_MSG_CHANNEL_CLOSE
      if(channel->context->mode == SSH_OPERATION_MODE_SERVER)
      {
         channel->state = SSH_CHANNEL_STATE_UNUSED;
      }
   }
   else
   {
      //Invalid channel state
      error = ERROR_WRONG_STATE;
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&channel->context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Release channel
 * @param[in] channel SSH channel handle
 **/

void sshDeleteChannel(SshChannel *channel)
{
   //Make sure the SSH channel handle is valid
   if(channel != NULL)
   {
      //Acquire exclusive access to the SSH context
      osAcquireMutex(&channel->context->mutex);
      //Release SSH channel
      channel->state = SSH_CHANNEL_STATE_UNUSED;
      //Release exclusive access to the SSH context
      osReleaseMutex(&channel->context->mutex);
   }
}


/**
 * @brief Release SSH context
 * @param[in] context Pointer to the SSH context
 **/

void sshDeinit(SshContext *context)
{
   uint_t i;
   SshConnection *connection;
   SshChannel *channel;

   //Free previously allocated memory
   osDeleteMutex(&context->mutex);
   osDeleteEvent(&context->event);

   //Loop through SSH connections
   for(i = 0; i < context->numConnections; i++)
   {
      //Point to the structure describing the current connection
      connection = &context->connections[i];

      //Clear associated structure
      osMemset(connection, 0, sizeof(SshConnection));
   }

   //Loop through SSH channels
   for(i = 0; i < context->numChannels; i++)
   {
      //Point to the structure describing the current channel
      channel = &context->channels[i];

      //Release event object
      osDeleteEvent(&channel->event);
      //Clear associated structure
      osMemset(channel, 0, sizeof(SshChannel));
   }

   //Clear SSH context
   osMemset(context, 0, sizeof(SshContext));
}

#endif
