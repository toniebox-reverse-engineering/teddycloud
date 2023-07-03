/**
 * @file acme_client.c
 * @brief ACME client (Automatic Certificate Management Environment)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneACME Open.
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
 * @section Description
 *
 * ACME is a protocol that a CA and an applicant can use to automate the
 * process of verification and certificate issuance. The protocol also
 * provides facilities for other certificate management functions, such as
 * certificate revocation. Refer to the following RFCs for complete details:
 * - RFC 8555: Automatic Certificate Management Environment (ACME)
 * - RFC 8737: ACME TLS Application-Layer Protocol Negotiation (ALPN) Challenge Extension
 * - RFC 7515: JSON Web Signature (JWS)
 * - RFC 7517: JSON Web Key (JWK)
 * - RFC 7518: JSON Web Algorithms (JWA)
 * - RFC 7638: JSON Web Key (JWK) Thumbprint
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL ACME_TRACE_LEVEL

//Dependencies
#include "acme/acme_client.h"
#include "acme/acme_client_directory.h"
#include "acme/acme_client_nonce.h"
#include "acme/acme_client_account.h"
#include "acme/acme_client_order.h"
#include "acme/acme_client_auth.h"
#include "acme/acme_client_challenge.h"
#include "acme/acme_client_certificate.h"
#include "acme/acme_client_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Initialize ACME client context
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientInit(AcmeClientContext *context)
{
   error_t error;

   //Make sure the ACME client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear ACME client context
   osMemset(context, 0, sizeof(AcmeClientContext));

   //Initialize HTTP client context
   error = httpClientInit(&context->httpClientContext);
   //Any error to report?
   if(error)
      return error;

   //Initialize ACME client state
   context->state = ACME_CLIENT_STATE_DISCONNECTED;
   //Initialize HTTP request state
   context->requestState = ACME_REQ_STATE_INIT;
   //Default timeout
   context->timeout = ACME_CLIENT_DEFAULT_TIMEOUT;

   //Default directory URI
   osStrcpy(context->directoryUri, "/directory");

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Register TLS initialization callback function
 * @param[in] context Pointer to the ACME client context
 * @param[in] callback TLS initialization callback function
 * @return Error code
 **/

error_t acmeClientRegisterTlsInitCallback(AcmeClientContext *context,
   AcmeClientTlsInitCallback callback)
{
   //Make sure the ACME client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->tlsInitCallback = callback;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Register CSR generation callback function
 * @param[in] context Pointer to the ACME client context
 * @param[in] callback TLS initialization callback function
 * @return Error code
 **/

error_t acmeClientRegisterCsrCallback(AcmeClientContext *context,
   AcmeClientCsrCallback callback)
{
   //Make sure the ACME client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->csrCallback = callback;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the pseudo-random number generator to be used
 * @param[in] context Pointer to the ACME client context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t acmeClientSetPrng(AcmeClientContext *context, const PrngAlgo *prngAlgo,
   void *prngContext)
{
   //Check parameters
   if(context == NULL || prngAlgo == NULL || prngContext == NULL)
      return ERROR_INVALID_PARAMETER;

   //PRNG algorithm that will be used to generate random numbers
   context->prngAlgo = prngAlgo;
   //PRNG context
   context->prngContext = prngContext;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set communication timeout
 * @param[in] context Pointer to the ACME client context
 * @param[in] timeout Timeout value, in milliseconds
 * @return Error code
 **/

error_t acmeClientSetTimeout(AcmeClientContext *context, systime_t timeout)
{
   //Make sure the ACME client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the domain name of the ACME server
 * @param[in] context Pointer to the ACME client context
 * @param[in] host NULL-terminated string containing the host name
 * @return Error code
 **/

error_t acmeClientSetHost(AcmeClientContext *context, const char_t *host)
{
   //Check parameters
   if(context == NULL || host == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the host name is acceptable
   if(osStrlen(host) > ACME_CLIENT_MAX_NAME_LEN)
      return ERROR_INVALID_LENGTH;

   //Save host name
   osStrcpy(context->serverName, host);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the URI of the directory object
 * @param[in] context Pointer to the ACME client context
 * @param[in] directoryUri NULL-terminated string containing the directory URI
 * @return Error code
 **/

error_t acmeClientSetDirectoryUri(AcmeClientContext *context,
   const char_t *directoryUri)
{
   //Check parameters
   if(context == NULL || directoryUri == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the URI is acceptable
   if(osStrlen(directoryUri) > ACME_CLIENT_MAX_URI_LEN)
      return ERROR_INVALID_LENGTH;

   //Save the URI of the directory object
   osStrcpy(context->directoryUri, directoryUri);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Bind the ACME client to a particular network interface
 * @param[in] context Pointer to the ACME client context
 * @param[in] interface Network interface to be used
 * @return Error code
 **/

error_t acmeClientBindToInterface(AcmeClientContext *context,
   NetInterface *interface)
{
   //Make sure the ACME client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Explicitly associate the ACME client with the specified interface
   context->interface = interface;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Establish a connection with the specified ACME server
 * @param[in] context Pointer to the ACME client context
 * @param[in] serverIpAddr IP address of the ACME server to connect to
 * @param[in] serverPort Port number
 * @return Error code
 **/

error_t acmeClientConnect(AcmeClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the ACME client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Establish connection with the HTTP server
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_DISCONNECTED)
      {
         //Save the TCP port number to be used
         context->serverPort = serverPort;

         //Use of HTTPS is required (refer to RFC 8555, section 6.1)
         if(context->tlsInitCallback != NULL)
         {
            //Register TLS initialization callback
            error = httpClientRegisterTlsInitCallback(&context->httpClientContext,
               context->tlsInitCallback);
         }
         else
         {
            //Report an error
            error = ERROR_INVALID_PARAMETER;
         }

         //Check status code
         if(!error)
         {
            //Select HTTP protocol version
            error = httpClientSetVersion(&context->httpClientContext,
               HTTP_VERSION_1_1);
         }

         //Check status code
         if(!error)
         {
            //Set timeout value for blocking operations
            error = httpClientSetTimeout(&context->httpClientContext,
               context->timeout);
         }

         //Check status code
         if(!error)
         {
            //Bind the HTTP client to the relevant network interface
            error = httpClientBindToInterface(&context->httpClientContext,
               context->interface);
         }

         //Check status code
         if(!error)
         {
            //Establish HTTPS connection
            context->state = ACME_CLIENT_STATE_CONNECTING;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_CONNECTING)
      {
         //Establish HTTPS connection
         error = httpClientConnect(&context->httpClientContext, serverIpAddr,
            serverPort);

         //Check status code
         if(error == NO_ERROR)
         {
            //The HTTPS connection is established
            context->state = ACME_CLIENT_STATE_CONNECTED;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //Initialize HTTP request state
         context->requestState = ACME_REQ_STATE_INIT;

         //Initialize the directory object
         osMemset(&context->directory, 0, sizeof(AcmeDirectory));
         //Invalidate the nonce
         osMemset(context->nonce, 0, ACME_CLIENT_MAX_NONCE_LEN);

         //Reset error counter
         context->badNonceErrors = 0;

         //The client is connected to the ACME server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to establish connection with the ACME server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Clean up side effects
      httpClientClose(&context->httpClientContext);
      //Update ACME client state
      context->state = ACME_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Load account key pair
 * @param[in] context Pointer to the ACME client context
 * @param[in] publicKey Public key (PEM format)
 * @param[in] publicKeyLen Length of the public key
 * @param[in] privateKey Private key (PEM format)
 * @param[in] privateKeyLen Length of the private key
 * @return Error code
 **/

error_t acmeClientSetAccountKey(AcmeClientContext *context,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen)
{
   //Check parameters
   if(context == NULL || publicKey == NULL || publicKeyLen == 0 ||
      privateKey == NULL || privateKeyLen == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Release the current key pair, if any
   acmeClientUnloadKeyPair(&context->accountKey);

   //The public and private keys are encoded in PEM format
   return acmeClientLoadKeyPair(&context->accountKey, publicKey, publicKeyLen,
      privateKey, privateKeyLen);
}


/**
 * @brief Account creation
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Account information
 * @return Error code
 **/

error_t acmeClientCreateAccount(AcmeClientContext *context,
   const AcmeAccountParams *params)
{
   error_t error;

   //Check parameters
   if(context == NULL || params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //Check account information
         error = acmeClientCheckAccountParams(params);

         //Check status code
         if(!error)
         {
            //Initialize account object
            osMemset(&context->account, 0, sizeof(AcmeAccount));

            //Release the current key pair, if any
            acmeClientUnloadKeyPair(&context->accountKey);

            //The public and private keys are encoded in PEM format
            error = acmeClientLoadKeyPair(&context->accountKey,
               params->publicKey, params->publicKeyLen,
               params->privateKey, params->privateKeyLen);
         }

         //Check status code
         if(!error)
         {
            //In order to help clients configure themselves with the right URLs
            //for each ACME operation, ACME servers provide a directory object
            //(refer to RFC 8555, section 7.1.1)
            context->state = ACME_CLIENT_STATE_DIRECTORY;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_DIRECTORY)
      {
         //If the directory object is no longer valid, the client must access
         //the directory again by sending a GET request to the directory URL
         error = acmeClientSendDirectoryRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_NONCE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_NONCE)
      {
         //Before sending a POST request to the server, an ACME client needs to
         //have a fresh anti-replay nonce (refer to RFC 8555, section 7.2)
         error = acmeClientSendNewNonceRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_ACCOUNT)
      {
         //A client creates a new account by sending a POST request to the
         //server's newAccount URL (refer to RFC 8555, section 7.3)
         error = acmeClientSendNewAccountRequest(context, params, FALSE);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Unexpected HTTP response?
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = ACME_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Account information update
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Updated account information
 * @return Error code
 **/

error_t acmeClientUpdateAccount(AcmeClientContext *context,
   const AcmeAccountParams *params)
{
   error_t error;

   //Check parameters
   if(context == NULL || params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //Check account information
         error = acmeClientCheckAccountParams(params);

         //Check status code
         if(!error)
         {
            //In order to help clients configure themselves with the right URLs
            //for each ACME operation, ACME servers provide a directory object
            //(refer to RFC 8555, section 7.1.1)
            context->state = ACME_CLIENT_STATE_DIRECTORY;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_DIRECTORY)
      {
         //If the directory object is no longer valid, the client must access
         //the directory again by sending a GET request to the directory URL
         error = acmeClientSendDirectoryRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_NONCE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_NONCE)
      {
         //Before sending a POST request to the server, an ACME client needs to
         //have a fresh anti-replay nonce (refer to RFC 8555, section 7.2)
         error = acmeClientSendNewNonceRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_ACCOUNT)
      {
         //If a client wishes to find the URL for an existing account, then
         //it should do so by sending a POST request to the newAccount URL
         //with an "onlyReturnExisting" field set to "true" (refer to RFC 8555,
         //section 7.3.1)
         error = acmeClientSendNewAccountRequest(context, NULL, TRUE);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_UPDATE_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_UPDATE_ACCOUNT)
      {
         //If the client wishes to update the account information, it sends a
         //POST request with updated information to the account URL (refer to
         //RFC 8555, section 7.3.1)
         error = acmeClientSendUpdateAccountRequest(context, params);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Unexpected HTTP response?
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = ACME_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Account key rollover
 * @param[in] context Pointer to the ACME client context
 * @param[in] publicKey New public key (PEM format)
 * @param[in] publicKeyLen Length of the new public key
 * @param[in] privateKey New private key (PEM format)
 * @param[in] privateKeyLen Length of the new private key
 * @return Error code
 **/

error_t acmeClientChangeAccountKey(AcmeClientContext *context,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen)
{
   error_t error;

   //Check parameters
   if(context == NULL || publicKey == NULL || publicKeyLen == 0 ||
      privateKey == NULL || privateKeyLen == 0)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //In order to help clients configure themselves with the right URLs for
         //each ACME operation, ACME servers provide a directory object (refer
         //to RFC 8555, section 7.1.1)
         context->state = ACME_CLIENT_STATE_DIRECTORY;
      }
      else if(context->state == ACME_CLIENT_STATE_DIRECTORY)
      {
         //If the directory object is no longer valid, the client must access
         //the directory again by sending a GET request to the directory URL
         error = acmeClientSendDirectoryRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_NONCE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_NONCE)
      {
         //Before sending a POST request to the server, an ACME client needs to
         //have a fresh anti-replay nonce (refer to RFC 8555, section 7.2)
         error = acmeClientSendNewNonceRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_ACCOUNT)
      {
         //If a client wishes to find the URL for an existing account, then
         //it should do so by sending a POST request to the newAccount URL
         //with an "onlyReturnExisting" field set to "true" (refer to RFC 8555,
         //section 7.3.1)
         error = acmeClientSendNewAccountRequest(context, NULL, TRUE);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_CHANGE_KEY;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_CHANGE_KEY)
      {
         //A client can change the public key that is associated with an
         //account, by sending a POST request to the server's keyChange
         //URL (refer to RFC 8555, section 7.3.5)
         error = acmeClientSendKeyChangeRequest(context, publicKey,
            publicKeyLen, privateKey, privateKeyLen);

         //Check status code
         if(!error)
         {
            //Unload the old account key
            acmeClientUnloadKeyPair(&context->accountKey);

            //Load the new account key
            error = acmeClientLoadKeyPair(&context->accountKey, publicKey,
               publicKeyLen, privateKey, privateKeyLen);

            //Update ACME client state
            context->state = ACME_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Unexpected HTTP response?
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = ACME_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief ACME account deactivation
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientDeactivateAccount(AcmeClientContext *context)
{
   error_t error;
   AcmeAccountParams params;

   //Make sure the ACME client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //In order to help clients configure themselves with the right URLs for
         //each ACME operation, ACME servers provide a directory object (refer
         //to RFC 8555, section 7.1.1)
         context->state = ACME_CLIENT_STATE_DIRECTORY;
      }
      else if(context->state == ACME_CLIENT_STATE_DIRECTORY)
      {
         //If the directory object is no longer valid, the client must access
         //the directory again by sending a GET request to the directory URL
         error = acmeClientSendDirectoryRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_NONCE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_NONCE)
      {
         //Before sending a POST request to the server, an ACME client needs to
         //have a fresh anti-replay nonce (refer to RFC 8555, section 7.2)
         error = acmeClientSendNewNonceRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_ACCOUNT)
      {
         //If a client wishes to find the URL for an existing account, then
         //it should do so by sending a POST request to the newAccount URL
         //with an "onlyReturnExisting" field set to "true" (refer to RFC 8555,
         //section 7.3.1)
         error = acmeClientSendNewAccountRequest(context, NULL, TRUE);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_DEACTIVATE_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_DEACTIVATE_ACCOUNT)
      {
         //Initialize account parameters
         osMemset(&params, 0, sizeof(AcmeAccountParams));

         //A client can deactivate an account by posting a signed update to the
         //account URL with a status field of "deactivated" (refer to RFC 8555,
         //section 7.3.1)
         params.status = "deactivated";

         //Send the POST request to the account URL
         error = acmeClientSendUpdateAccountRequest(context, &params);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Unexpected HTTP response?
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = ACME_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Begin the certificate issuance process
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Certificate order information
 * @return Error code
 **/

error_t acmeClientCreateOrder(AcmeClientContext *context,
   const AcmeOrderParams *params)
{
   error_t error;

   //Check parameters
   if(context == NULL || params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //Check certificate order information
         error = acmeClientCheckOrderParams(params);

         //Check status code
         if(!error)
         {
            //Initialize order object
            error = acmeClientInitOrder(context, params);
         }

         //Check status code
         if(!error)
         {
            //In order to help clients configure themselves with the right URLs
            //for each ACME operation, ACME servers provide a directory object
            //(refer to RFC 8555, section 7.1.1)
            context->state = ACME_CLIENT_STATE_DIRECTORY;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_DIRECTORY)
      {
         //If the directory object is no longer valid, the client must access
         //the directory again by sending a GET request to the directory URL
         error = acmeClientSendDirectoryRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_NONCE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_NONCE)
      {
         //Before sending a POST request to the server, an ACME client needs to
         //have a fresh anti-replay nonce (refer to RFC 8555, section 7.2)
         error = acmeClientSendNewNonceRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_ACCOUNT)
      {
         //If a client wishes to find the URL for an existing account, then
         //it should do so by sending a POST request to the newAccount URL
         //with an "onlyReturnExisting" field set to "true" (refer to RFC 8555,
         //section 7.3.1)
         error = acmeClientSendNewAccountRequest(context, NULL, TRUE);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_ORDER;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_ORDER)
      {
         //The client begins the certificate issuance process by sending a
         //POST request to the server's newOrder resource (refer to RFC 8555,
         //section 7.4)
         error = acmeClientSendNewOrderRequest(context, params);

         //Check status code
         if(!error)
         {
            //Point to the first authorization
            context->index = 0;
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_AUTHORIZATION;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_AUTHORIZATION)
      {
         //Loop through the authorizations
         if(context->index < context->numAuthorizations)
         {
            AcmeAuthorization *authorization;

            //Point to the current authorization
            authorization = &context->authorizations[context->index];

            //When a client receives an order from the server in reply to a
            //newOrder request, it downloads the authorization resources by
            //sending POST-as-GET requests to the indicated URLs (refer to
            //RFC 8555, section 7.5)
            error = acmeClientSendAuthorizationRequest(context, authorization);

            //Check status code
            if(!error)
            {
               //Point the next authorization
               context->index++;
            }
         }
         else
         {
            //All the authorizations have been downloaded
            context->state = ACME_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Unexpected HTTP response?
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = ACME_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Get the key authorization that matches a given token (HTTP challenge)
 * @param[in] context Pointer to the ACME client context
 * @param[in] token NULL-terminated string that contains the token
 * @return The function returns a NULL-terminated string that contains the key
 *   authorization if the token is valid. Else, the NULL pointer is returned
 **/

const char_t *acmeClientGetHttpKeyAuthorization(AcmeClientContext *context,
   const char_t *token)
{
   const char_t *keyAuth;

   //Default value
   keyAuth = NULL;

#if (ACME_CLIENT_HTTP_CHALLENGE_SUPPORT == ENABLED)
   //Check parameters
   if(context != NULL && token != NULL)
   {
      uint_t i;

      //Loop through the challenges
      for(i = 0; i < context->numChallenges; i++)
      {
         //Check the status of the challenge
         if(context->challenges[i].status == ACME_CHALLENGE_STATUS_PENDING ||
            context->challenges[i].status == ACME_CHALLENGE_STATUS_PROCESSING)
         {
            //HTTP validation method?
            if(context->challenges[i].type == ACME_CHALLENGE_TYPE_HTTP_01)
            {
               //Compare token values
               if(!osStrcmp(context->challenges[i].token, token))
               {
                  //Point to the key authorization
                  keyAuth = context->challenges[i].keyAuth;
                  break;
               }
            }
         }
      }
   }
#endif

   //Return the ASCII representation of the key authorization
   return keyAuth;
}


/**
 * @brief Get the key authorization digest that matches a given identifier (DNS challenge)
 * @param[in] context Pointer to the ACME client context
 * @param[in] identifier NULL-terminated string that contains the domain name
 * @return The function returns a NULL-terminated string that contains the
 *   Base64url-encoded digest of the key authorization if the identifier is
 *   valid. Else, the NULL pointer is returned
 **/

const char_t *acmeClientGetDnsKeyAuthorization(AcmeClientContext *context,
   const char_t *identifier)
{
   const char_t *keyAuth;

   //Default value
   keyAuth = NULL;

#if (ACME_CLIENT_DNS_CHALLENGE_SUPPORT == ENABLED)
   //Check parameters
   if(context != NULL && identifier != NULL)
   {
      uint_t i;

      //Loop through the challenges
      for(i = 0; i < context->numChallenges; i++)
      {
         //Check the status of the challenge
         if(context->challenges[i].status == ACME_CHALLENGE_STATUS_PENDING ||
            context->challenges[i].status == ACME_CHALLENGE_STATUS_PROCESSING)
         {
            //DNS validation method?
            if(context->challenges[i].type == ACME_CHALLENGE_TYPE_DNS_01)
            {
               //Any identifier of type "dns" may have a wildcard domain name as
               //its value
               if(context->challenges[i].wildcard)
               {
                  //A wildcard domain name consists of a single asterisk character
                  //followed by a single full stop character ("*.") followed by a
                  //domain name
                  if(!osStrncmp(identifier, "*.", 2) &&
                     !osStrcmp(context->challenges[i].identifier, identifier + 2))
                  {
                     //Point to the key authorization digest
                     keyAuth = context->challenges[i].keyAuth;
                     break;
                  }
               }
               else
               {
                  //Compare identifier values
                  if(!osStrcmp(context->challenges[i].identifier, identifier))
                  {
                     //Point to the key authorization digest
                     keyAuth = context->challenges[i].keyAuth;
                     break;
                  }
               }
            }
         }
      }
   }
#endif

   //Return the Base64url representation of the key authorization digest
   return keyAuth;
}


/**
 * @brief Get the self-certificate that matches a given identifier (TLS-ALPN challenge)
 * @param[in] context Pointer to the ACME client context
 * @param[in] identifier NULL-terminated string that contains the domain name
 * @return The function returns a NULL-terminated string that contains the
 *   TLS-ALPN certificate if the identifier is valid. Else, the NULL pointer
 *   is returned
 **/

const char_t *acmeClientGetTlsAlpnCertificate(AcmeClientContext *context,
   const char_t *identifier)
{
   const char_t *cert;

   //Default value
   cert = NULL;

#if (ACME_CLIENT_TLS_ALPN_CHALLENGE_SUPPORT == ENABLED)
   //Check parameters
   if(context != NULL && identifier != NULL)
   {
      uint_t i;

      //Loop through the challenges
      for(i = 0; i < context->numChallenges; i++)
      {
         //Check the status of the challenge
         if(context->challenges[i].status == ACME_CHALLENGE_STATUS_PENDING ||
            context->challenges[i].status == ACME_CHALLENGE_STATUS_PROCESSING)
         {
            //TLS with ALPN validation method?
            if(context->challenges[i].type == ACME_CHALLENGE_TYPE_TLS_ALPN_01)
            {
               //Compare identifier values
               if(!osStrcmp(context->challenges[i].identifier, identifier))
               {
                  //Point to the self-signed certificate
                  cert = context->challenges[i].cert;
                  break;
               }
            }
         }
      }
   }
#endif

   //Return the TLS-ALPN certificate
   return cert;
}


/**
 * @brief Poll for order status
 * @param[in] context Pointer to the ACME client context
 * @param[out] orderStatus Order status
 * @return Error code
 **/

error_t acmeClientPollOrderStatus(AcmeClientContext *context,
   AcmeOrderStatus *orderStatus)
{
   error_t error;

   //Check parameters
   if(context == NULL || orderStatus == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //Check the order of the order
         if(context->order.status == ACME_ORDER_STATUS_PENDING ||
            context->order.status == ACME_ORDER_STATUS_READY ||
            context->order.status == ACME_ORDER_STATUS_PROCESSING)
         {
            //In order to help clients configure themselves with the right URLs
            //for each ACME operation, ACME servers provide a directory object
            //(refer to RFC 8555, section 7.1.1)
            context->state = ACME_CLIENT_STATE_DIRECTORY;
         }
         else if(context->order.status == ACME_ORDER_STATUS_VALID ||
            context->order.status == ACME_ORDER_STATUS_INVALID)
         {
            //Exit immediately
            break;
         }
         else
         {
            //Report an error
            error = ERROR_WRONG_STATE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_DIRECTORY)
      {
         //If the directory object is no longer valid, the client must access
         //the directory again by sending a GET request to the directory URL
         error = acmeClientSendDirectoryRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_NONCE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_NONCE)
      {
         //Before sending a POST request to the server, an ACME client needs to
         //have a fresh anti-replay nonce (refer to RFC 8555, section 7.2)
         error = acmeClientSendNewNonceRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_ACCOUNT)
      {
         //If a client wishes to find the URL for an existing account, then
         //it should do so by sending a POST request to the newAccount URL
         //with an "onlyReturnExisting" field set to "true" (refer to RFC 8555,
         //section 7.3.1)
         error = acmeClientSendNewAccountRequest(context, NULL, TRUE);

         //Check status code
         if(!error)
         {
            //Clients should check the status of the order to determine whether
            //they need to take any action (refer to RFC 8555, section 7.1.3)
            if(context->order.status == ACME_ORDER_STATUS_PENDING)
            {
               //Point to the first challenge
               context->index = 0;

               //The client indicate to the server that it is ready for the
               //challenge validation
               context->state = ACME_CLIENT_STATE_CHALLENGE_READY;
            }
            else if(context->order.status == ACME_ORDER_STATUS_READY)
            {
               //All the authorizations listed in the order object are in the
               //"valid" state
               context->state = ACME_CLIENT_STATE_FINALIZE;
            }
            else if(context->order.status == ACME_ORDER_STATUS_PROCESSING)
            {
               //The client has already submitted a request to the order's
               //"finalize" URL
               context->state = ACME_CLIENT_STATE_POLL_STATUS_2;
            }
            else
            {
               //Report an error
               error = ERROR_WRONG_STATE;
            }
         }
      }
      else if(context->state == ACME_CLIENT_STATE_CHALLENGE_READY)
      {
         //Loop through the authorizations
         if(context->index < context->numChallenges)
         {
            AcmeChallenge *challenge;

            //Point to the current challenge
            challenge = &context->challenges[context->index];

            //Check the status of the challenge
            if(challenge->status == ACME_CHALLENGE_STATUS_PENDING)
            {
               //The client indicates to the server that it is ready for the
               //challenge validation by sending an empty JSON body carried in
               //a POST request to the challenge URL (refer to RFC 8555,
               //section 7.5.1)
               error = acmeClientSendChallengeReadyRequest(context, challenge);

               //Check status code
               if(!error)
               {
                  //The challenge transitions to the "processing" state when
                  //the client responds to the challenge
                  challenge->status = ACME_CHALLENGE_STATUS_PROCESSING;
               }
            }

            //Check status code
            if(!error)
            {
               //Point the next challenge
               context->index++;
            }
         }
         else
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_POLL_STATUS_1;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_POLL_STATUS_1)
      {
         //The client should then send a POST-as-GET request to the order
         //resource to obtain its current state refer to RFC 8555, section 7.4)
         error = acmeClientSendOrderStatusRequest(context);

         //Check status code
         if(!error)
         {
            //Check the status of the order
            if(context->order.status == ACME_ORDER_STATUS_PENDING ||
               context->order.status == ACME_ORDER_STATUS_INVALID)
            {
               //Update ACME client state
               context->state = ACME_CLIENT_STATE_CONNECTED;
               break;
            }
            else if(context->order.status == ACME_ORDER_STATUS_READY)
            {
               //Once all of the authorizations listed in the order object are
               //in the "valid" state, the order transitions to the "ready" state
               context->state = ACME_CLIENT_STATE_FINALIZE;
            }
            else
            {
               //Report an error
               error = ERROR_WRONG_STATE;
               break;
            }
         }
      }
      else if(context->state == ACME_CLIENT_STATE_FINALIZE)
      {
         //Once the client believes it has fulfilled the server's requirements,
         //it should send a POST request to the order resource's finalize URL.
         //The POST body MUST include a CSR (refer to RFC 8555, section 7.4)
         error = acmeClientSendFinalizeOrderRequest(context);

         //Check status code
         if(!error)
         {
            //The order moves to the "processing" state after the client submits
            //a request to the order's finalize URL
            context->order.status = ACME_ORDER_STATUS_PROCESSING;

            //Update ACME client state
            context->state = ACME_CLIENT_STATE_POLL_STATUS_2;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_POLL_STATUS_2)
      {
         //The client should then send a POST-as-GET request to the order
         //resource to obtain its current state refer to RFC 8555, section 7.4)
         error = acmeClientSendOrderStatusRequest(context);

         //Check status code
         if(!error)
         {
            //Check the status of the order
            if(context->order.status != ACME_ORDER_STATUS_PROCESSING &&
               context->order.status != ACME_ORDER_STATUS_VALID &&
               context->order.status != ACME_ORDER_STATUS_INVALID)
            {
               //Report an error
               error = ERROR_WRONG_STATE;
            }

            //Update ACME client state
            context->state = ACME_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Always return the actual status of the order
   *orderStatus = context->order.status;

   //Unexpected HTTP response?
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = ACME_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Download the certificate
 * @param[in] context Pointer to the ACME client context
 * @param[out] buffer Pointer to the buffer where to store the certificate chain
 * @param[in] size Size of the buffer, in bytes
 * @param[out] length Actual length of the certificate chain, in bytes
 * @return Error code
 **/

error_t acmeClientDownloadCertificate(AcmeClientContext *context,
   char_t *buffer, size_t size, size_t *length)
{
   error_t error;

   //Check parameters
   if(context == NULL || buffer == NULL || length == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //Make sure the certificate has been issued by the ACME server
         if(context->order.status == ACME_ORDER_STATUS_VALID)
         {
            //In order to help clients configure themselves with the right URLs
            //for each ACME operation, ACME servers provide a directory object
            //(refer to RFC 8555, section 7.1.1)
            context->state = ACME_CLIENT_STATE_DIRECTORY;
         }
         else
         {
            //Report an error
            error = ERROR_WRONG_STATE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_DIRECTORY)
      {
         //If the directory object is no longer valid, the client must access
         //the directory again by sending a GET request to the directory URL
         error = acmeClientSendDirectoryRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_NONCE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_NONCE)
      {
         //Before sending a POST request to the server, an ACME client needs to
         //have a fresh anti-replay nonce (refer to RFC 8555, section 7.2)
         error = acmeClientSendNewNonceRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_ACCOUNT)
      {
         //If a client wishes to find the URL for an existing account, then
         //it should do so by sending a POST request to the newAccount URL
         //with an "onlyReturnExisting" field set to "true" (refer to RFC 8555,
         //section 7.3.1)
         error = acmeClientSendNewAccountRequest(context, NULL, TRUE);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_DOWNLOAD_CERT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_DOWNLOAD_CERT)
      {
         //To download the issued certificate, the client simply sends a
         //POST-as-GET request to the certificate URL (refer to RFC 8555,
         //section 7.4.2)
         error = acmeClientSendDownloadCertRequest(context, buffer, size,
            length);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Unexpected HTTP response?
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = ACME_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Certificate revocation
 * @param[in] context Pointer to the ACME client context
 * @param[in] cert Certificate to be revoked (PEM format)
 * @param[in] certLen Length of the certificate, in bytes
 * @param[in] privateKey Reserved parameter (must be NULL)
 * @param[in] privateKeyLen Reserved parameter (must be 0)
 * @param[in] reason Revocation reason code
 * @return Error code
 **/

error_t acmeClientRevokeCertificate(AcmeClientContext *context,
   const char_t *cert, size_t certLen, const char_t *privateKey,
   size_t privateKeyLen, AcmeReasonCode reason)
{
   error_t error;

   //Check parameters
   if(context == NULL || cert == NULL || certLen == 0)
      return ERROR_INVALID_PARAMETER;

   //Initialize variables
   error = NO_ERROR;

   //Execute the sequence of HTTP requests
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //In order to help clients configure themselves with the right URLs for
         //each ACME operation, ACME servers provide a directory object (refer
         //to RFC 8555, section 7.1.1)
         context->state = ACME_CLIENT_STATE_DIRECTORY;
      }
      else if(context->state == ACME_CLIENT_STATE_DIRECTORY)
      {
         //If the directory object is no longer valid, the client must access
         //the directory again by sending a GET request to the directory URL
         error = acmeClientSendDirectoryRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_NONCE;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_NONCE)
      {
         //Before sending a POST request to the server, an ACME client needs to
         //have a fresh anti-replay nonce (refer to RFC 8555, section 7.2)
         error = acmeClientSendNewNonceRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_NEW_ACCOUNT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_NEW_ACCOUNT)
      {
         //If a client wishes to find the URL for an existing account, then
         //it should do so by sending a POST request to the newAccount URL
         //with an "onlyReturnExisting" field set to "true" (refer to RFC 8555,
         //section 7.3.1)
         error = acmeClientSendNewAccountRequest(context, NULL, TRUE);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_REVOKE_CERT;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_REVOKE_CERT)
      {
         //To request that a certificate be revoked, the client sends a POST
         //request to the ACME server's revokeCert URL (refer to RFC 8555,
         //section 7.6)
         error = acmeClientSendRevokeCertRequest(context, cert, certLen, reason);

         //Check status code
         if(!error)
         {
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_CONNECTED;
            break;
         }
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Unexpected HTTP response?
   if(error == ERROR_UNEXPECTED_STATUS || error == ERROR_INVALID_RESPONSE ||
      error == ERROR_RESPONSE_TOO_LARGE)
   {
      //Revert to default state
      context->state = ACME_CLIENT_STATE_CONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Gracefully disconnect from the ACME server
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientDisconnect(AcmeClientContext *context)
{
   error_t error;

   //Make sure the ACME client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Gracefully disconnect from the ACME server
   while(!error)
   {
      //Check ACME client state
      if(context->state == ACME_CLIENT_STATE_CONNECTED)
      {
         //Gracefully shutdown HTTPS connection
         context->state = ACME_CLIENT_STATE_DISCONNECTING;
      }
      else if(context->state == ACME_CLIENT_STATE_DISCONNECTING)
      {
         //Gracefully shutdown HTTPS connection
         error = httpClientDisconnect(&context->httpClientContext);

         //Check status code
         if(error == NO_ERROR)
         {
            //Close HTTPS connection
            httpClientClose(&context->httpClientContext);
            //Update ACME client state
            context->state = ACME_CLIENT_STATE_DISCONNECTED;
         }
      }
      else if(context->state == ACME_CLIENT_STATE_DISCONNECTED)
      {
         //The client is disconnected from the ACME server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to gracefully disconnect from the ACME server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Close HTTPS connection
      httpClientClose(&context->httpClientContext);
      //Update ACME client state
      context->state = ACME_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Close the connection with the ACME server
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientClose(AcmeClientContext *context)
{
   //Make sure the ACME client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Close HTTPS connection
   httpClientClose(&context->httpClientContext);
   //Update ACME client state
   context->state = ACME_CLIENT_STATE_DISCONNECTED;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release ACME client context
 * @param[in] context Pointer to the ACME client context
 **/

void acmeClientDeinit(AcmeClientContext *context)
{
   //Make sure the ACME client context is valid
   if(context != NULL)
   {
      //Release HTTP client context
      httpClientDeinit(&context->httpClientContext);

      //Release keys
      acmeClientUnloadKeyPair(&context->accountKey);
      acmeClientUnloadKeyPair(&context->certKey);

      //Clear ACME client context
      osMemset(context, 0, sizeof(AcmeClientContext));
   }
}

#endif
