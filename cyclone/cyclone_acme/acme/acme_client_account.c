/**
 * @file acme_client_account.c
 * @brief Account object management
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL ACME_TRACE_LEVEL

//Dependencies
#include "acme/acme_client.h"
#include "acme/acme_client_account.h"
#include "acme/acme_client_jose.h"
#include "acme/acme_client_misc.h"
#include "jansson.h"
#include "jansson_private.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Check account information
 * @param[in] params Account information
 * @return Error code
 **/

error_t acmeClientCheckAccountParams(const AcmeAccountParams *params)
{
   uint_t i;

   //Sanity check
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the number of contacts
   if(params->numContacts > ACME_CLIENT_MAX_CONTACTS)
      return ERROR_INVALID_PARAMETER;

   //Make sure the list of contacts is valid
   if(params->numContacts != 0 && params->contacts == NULL)
      return ERROR_INVALID_PARAMETER;

   //Loop through the list of contacts
   for(i = 0; i < params->numContacts; i++)
   {
      //Each item must contain a valid string
      if(params->contacts[i] == NULL)
         return ERROR_INVALID_PARAMETER;
   }

   //The account parameters are valid
   return NO_ERROR;
}


/**
 * @brief Send HTTP request (newAccount URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Account information
 * @param[in] onlyReturnExisting Do not create a new account if one does not
 *   already exist
 * @return Error code
 **/

error_t acmeClientSendNewAccountRequest(AcmeClientContext *context,
   const AcmeAccountParams *params, bool_t onlyReturnExisting)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == ACME_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_DEBUG("\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("## NEW ACCOUNT ################################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Check whether the client wishes to find the URL for an existing
         //account
         if(onlyReturnExisting)
         {
            //Valid account URL?
            if(context->account.url[0] != '\0')
            {
               //The client has a account key and the corresponding account URL
               break;
            }
            else
            {
               //To recover the account URL, the client sends a POST request to
               //the newAccount URL with "onlyReturnExisting" set to "true"
               context->requestState = ACME_REQ_STATE_FORMAT_BODY;
            }
         }
         else
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_BODY;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeClientFormatNewAccountRequest(context, params,
            onlyReturnExisting);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //A client creates a new account by sending a POST request to the
         //server's newAccount URL (refer to RFC 8555, section 7.3)
         error = acmeClientFormatRequestHeader(context, "POST",
            context->directory.newAccount);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_SEND_HEADER ||
         context->requestState == ACME_REQ_STATE_SEND_BODY ||
         context->requestState == ACME_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == ACME_REQ_STATE_PARSE_HEADER ||
         context->requestState == ACME_REQ_STATE_RECEIVE_BODY ||
         context->requestState == ACME_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = acmeClientSendRequest(context);
      }
      else if(context->requestState == ACME_REQ_STATE_PARSE_BODY)
      {
         //Parse the body of the HTTP response
         error = acmeClientParseNewAccountResponse(context);

         //The HTTP transaction is complete
         context->requestState = ACME_REQ_STATE_INIT;
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format HTTP request body (newAccount URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Account information
 * @param[in] onlyReturnExisting Do not create a new account if one does not
 *   already exist
 * @return Error code
 **/

error_t acmeClientFormatNewAccountRequest(AcmeClientContext *context,
   const AcmeAccountParams *params, bool_t onlyReturnExisting)
{
   error_t error;
   int_t ret;
   uint_t i;
   size_t n;
   char_t *protected;
   char_t *payload;
   json_t *payloadObj;
   json_t *contactObj;

   //Initialize status code
   ret = 0;

   //Initialize JSON object
   payloadObj = json_object();

   //Valid account parameters?
   if(params != NULL)
   {
      //The "contact" field contains an array of URLs that the server can use
      //to contact the client for issues related to this account
      if(params->contacts != NULL && params->numContacts > 0)
      {
         //Initialize JSON object
         contactObj = json_array();

         //Loop through the list of contacts
         for(i = 0; i < params->numContacts; i++)
         {
            //Format email address
            osSprintf(context->buffer, "mailto:%s", params->contacts[i]);

            //Add the email address to the array
            ret |= json_array_append_new(contactObj,
               json_string(context->buffer));
         }

         //Add the "contact" field to the payload
         ret |= json_object_set_new(payloadObj, "contact", contactObj);
      }

      //A client can indicate its agreement with the CA's terms of service by
      //setting the "termsOfServiceAgreed" field in its account object to "true"
      if(params->termsOfServiceAgreed)
      {
         //Add the "termsOfServiceAgreed" field to the payload object
         ret |= json_object_set_new(payloadObj, "termsOfServiceAgreed",
            json_true());
      }
   }

   //If the "onlyReturnExisting" field is present with the value "true", then
   //the server must not create a new account if one does not already exist.
   //This allows a client to look up an account URL based on an account key
   if(onlyReturnExisting)
   {
      //Add the "onlyReturnExisting" field to the payload object
      ret |= json_object_set_new(payloadObj, "onlyReturnExisting",
         json_true());
   }

   //JSON object successfully created?
   if(ret == 0)
   {
      //Generate the JSON representation of the payload object
      payload = json_dumps(payloadObj, JSON_COMPACT);
   }
   else
   {
      //An error occurred during processing
      payload = NULL;
   }

   //Valid JSON representation?
   if(payload != NULL)
   {
      //Point to the buffer where to format the JWS protected header
      protected = context->buffer;

      //Format JWS protected header
      error = acmeClientFormatJwsProtectedHeader(&context->accountKey, NULL,
         context->nonce, context->directory.newAccount, protected, &n);

      //Check status code
      if(!error)
      {
         //Generate the JSON Web Signature
         error = jwsCreate(context->prngAlgo, context->prngContext, protected,
            payload, context->accountKey.alg, context->accountKey.crv,
            context->accountKey.privateKey, context->buffer, &context->bufferLen);
      }

      //Release JSON string
      jsonp_free(payload);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release JSON object
   json_decref(payloadObj);

   //Return status code
   return error;
}


/**
 * @brief Parse HTTP response (newAccount URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseNewAccountResponse(AcmeClientContext *context)
{
   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //The server must include a Replay-Nonce header field in every successful
   //response to a POST request (refer to RFC 8555, section 6.5)
   if(context->nonce[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //The server returns the account URL in the Location HTTP header field (refer
   //to RFC 8555, section 7.3)
   if(context->account.url[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Send HTTP request (account URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Account information
 * @return Error code
 **/

error_t acmeClientSendUpdateAccountRequest(AcmeClientContext *context,
   const AcmeAccountParams *params)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == ACME_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_DEBUG("\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("## UPDATE ACCOUNT #############################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeFormatUpdateAccountRequest(context, params);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //A client can update or deactivate an account by sending a POST
         //request to the account URL
         error = acmeClientFormatRequestHeader(context, "POST",
            context->account.url);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_SEND_HEADER ||
         context->requestState == ACME_REQ_STATE_SEND_BODY ||
         context->requestState == ACME_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == ACME_REQ_STATE_PARSE_HEADER ||
         context->requestState == ACME_REQ_STATE_RECEIVE_BODY ||
         context->requestState == ACME_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = acmeClientSendRequest(context);
      }
      else if(context->requestState == ACME_REQ_STATE_PARSE_BODY)
      {
         //Parse the body of the HTTP response
         error = acmeClientParseUpdateAccountResponse(context);

         //The HTTP transaction is complete
         context->requestState = ACME_REQ_STATE_INIT;
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format HTTP request body (account URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Account information
 * @return Error code
 **/

error_t acmeFormatUpdateAccountRequest(AcmeClientContext *context,
   const AcmeAccountParams *params)
{
   error_t error;
   int_t ret;
   uint_t i;
   size_t n;
   char_t *protected;
   char_t *payload;
   json_t *payloadObj;
   json_t *contactObj;

   //Initialize status code
   ret = 0;

   //Initialize JSON object
   payloadObj = json_object();

   //The "contact" field contains an array of URLs that the server can use
   //to contact the client for issues related to this account
   if(params->contacts != NULL && params->numContacts > 0)
   {
      //Initialize JSON object
      contactObj = json_array();

      //Loop through the list of contacts
      for(i = 0; i < params->numContacts; i++)
      {
         //Format email address
         osSprintf(context->buffer, "mailto:%s", params->contacts[i]);

         //Add the email address to the array
         ret |= json_array_append_new(contactObj,
            json_string(context->buffer));
      }

      //Add the "contact" field to the payload
      ret |= json_object_set_new(payloadObj, "contact", contactObj);
   }

   //A client can deactivate an account by posting a signed update to the
   //account URL with a status field of "deactivated"
   if(params->status != NULL && params->status[0] != '\0')
   {
      //Add the "status" field to the payload
      ret |= json_object_set_new(payloadObj, "status",
         json_string(params->status));
   }

   //JSON object successfully created?
   if(ret == 0)
   {
      //Generate the JSON representation of the payload object
      payload = json_dumps(payloadObj, JSON_COMPACT);
   }
   else
   {
      //An error occurred during processing
      payload = NULL;
   }

   //Valid JSON representation?
   if(payload != NULL)
   {
      //Point to the buffer where to format the JWS protected header
      protected = context->buffer;

      //Format JWS protected header
      error = acmeClientFormatJwsProtectedHeader(&context->accountKey,
         context->account.url, context->nonce, context->account.url,
         protected, &n);

      //Check status code
      if(!error)
      {
         //Generate the JSON Web Signature
         error = jwsCreate(context->prngAlgo, context->prngContext, protected,
            payload, context->accountKey.alg, context->accountKey.crv,
            context->accountKey.privateKey, context->buffer, &context->bufferLen);
      }

      //Release JSON string
      jsonp_free(payload);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release JSON object
   json_decref(payloadObj);

   //Return status code
   return error;
}


/**
 * @brief Parse HTTP response (account URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseUpdateAccountResponse(AcmeClientContext *context)
{
   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //The server must include a Replay-Nonce header field in every successful
   //response to a POST request (refer to RFC 8555, section 6.5)
   if(context->nonce[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Send HTTP request (keyChange URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] publicKey New public key (PEM format)
 * @param[in] publicKeyLen Length of the new public key
 * @param[in] privateKey New private key (PEM format)
 * @param[in] privateKeyLen Length of the new private key
 * @return Error code
 **/

error_t acmeClientSendKeyChangeRequest(AcmeClientContext *context,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen)
{
   error_t error;

   //Initialize variables
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check HTTP request state
      if(context->requestState == ACME_REQ_STATE_INIT)
      {
         //Debug message
         TRACE_DEBUG("\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("## KEY CHANGE #################################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeClientFormatKeyChangeRequest(context, publicKey,
            publicKeyLen, privateKey, privateKeyLen);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //A client can change the public key that is associated with an
         //account, by sending a POST request to the server's keyChange
         //URL (refer to RFC 8555, section 7.3.5)
         error = acmeClientFormatRequestHeader(context, "POST",
            context->directory.keyChange);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_SEND_HEADER ||
         context->requestState == ACME_REQ_STATE_SEND_BODY ||
         context->requestState == ACME_REQ_STATE_RECEIVE_HEADER ||
         context->requestState == ACME_REQ_STATE_PARSE_HEADER ||
         context->requestState == ACME_REQ_STATE_RECEIVE_BODY ||
         context->requestState == ACME_REQ_STATE_CLOSE_BODY)
      {
         //Perform HTTP request/response transaction
         error = acmeClientSendRequest(context);
      }
      else if(context->requestState == ACME_REQ_STATE_PARSE_BODY)
      {
         //Parse the body of the HTTP response
         error = acmeClientParseKeyChangeResponse(context);

         //The HTTP transaction is complete
         context->requestState = ACME_REQ_STATE_INIT;
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Format HTTP request body (keyChange URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] publicKey New public key (PEM format)
 * @param[in] publicKeyLen Length of the new public key
 * @param[in] privateKey New private key (PEM format)
 * @param[in] privateKeyLen Length of the new private key
 * @return Error code
 **/

error_t acmeClientFormatKeyChangeRequest(AcmeClientContext *context,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen)
{
   error_t error;
   int_t ret;
   size_t n;
   char_t *protected;
   char_t *payload;
   char_t *keyChange;
   json_t *keyChangeObj;
   AcmeKeyPair newAccountKey;

   //Export the old public key to JWK format
   error = acmeClientFormatJwk(&context->accountKey, context->buffer, &n,
      FALSE);
   //Any error to report?
   if(error)
      return error;

   //Load the new account key
   error = acmeClientLoadKeyPair(&newAccountKey, publicKey, publicKeyLen,
      privateKey, privateKeyLen);
   //Any error to report?
   if(error)
      return error;

   //To create this request object, the client first constructs a keyChange
   //object describing the account to be updated and its account key (refer
   //to RFC 8555, section 7.3.5)
   keyChangeObj = json_object();

   //The "account" field contains the URL for the account being modified
   ret = json_object_set_new(keyChangeObj, "account",
      json_string(context->account.url));

   //The "oldKey" field contains The JWK representation of the old key
   ret |= json_object_set_new(keyChangeObj, "oldKey",
      json_loads(context->buffer, 0, NULL));

   //JSON object successfully created?
   if(ret == 0)
   {
      //Generate the JSON representation of the payload object
      keyChange = json_dumps(keyChangeObj, JSON_COMPACT);
   }
   else
   {
      //An error occurred during processing
      keyChange = NULL;
   }

   //Valid JSON representation?
   if(keyChange != NULL)
   {
      //Point to the buffer where to format the JWS protected header
      protected = context->buffer;

      //The inner JWS must have a "jwk" header parameter containing the public
      //key of the new key pair, must have the same "url" header parameter as
      //the outer JWS and must omit the "nonce" header parameter
      error = acmeClientFormatJwsProtectedHeader(&newAccountKey, NULL, NULL,
         context->directory.keyChange, protected, &n);

      //Check status code
      if(!error)
      {
         //The inner JWS is signed with the requested new account key
         error = jwsCreate(context->prngAlgo, context->prngContext,
            protected, keyChange, newAccountKey.alg, newAccountKey.crv,
            newAccountKey.privateKey, context->buffer, &n);
      }

      //Release JSON string
      jsonp_free(keyChange);
   }
   else
   {
      //Report an error
      error = ERROR_FAILURE;
   }

   //Release JSON object
   json_decref(keyChangeObj);

   //Unload the new account key
   acmeClientUnloadKeyPair(&newAccountKey);

   //Check status code)
   if(!error)
   {
      //The inner JWS becomes the payload for the outer JWS that is the body
      //of the ACME request
      payload = jsonp_strdup(context->buffer);

      //Valid JSON representation?
      if(payload != NULL)
      {
         //Point to the buffer where to format the JWS protected header
         protected = context->buffer;

         //The outer JWS must meet the normal requirements for an ACME JWS
         //request body (refer to RFC 8555, section 7.3.5)
         error = acmeClientFormatJwsProtectedHeader(&context->accountKey,
            context->account.url, context->nonce, context->directory.keyChange,
            protected, &n);

         //Check status code
         if(!error)
         {
            //Generate the outer JWS
            error = jwsCreate(context->prngAlgo, context->prngContext,
               protected, payload, context->accountKey.alg,
               context->accountKey.crv, context->accountKey.privateKey,
               context->buffer, &context->bufferLen);
         }

         //Release JSON string
         jsonp_free(payload);
      }
      else
      {
         //Report an error
         error = ERROR_FAILURE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse HTTP response (keyChange URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseKeyChangeResponse(AcmeClientContext *context)
{
   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //The server must include a Replay-Nonce header field in every successful
   //response to a POST request (refer to RFC 8555, section 6.5)
   if(context->nonce[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //Successful processing
   return NO_ERROR;
}

#endif
