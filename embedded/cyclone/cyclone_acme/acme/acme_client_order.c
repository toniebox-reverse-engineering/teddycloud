/**
 * @file acme_client_order.c
 * @brief Order object management
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
#include "acme/acme_client_order.h"
#include "acme/acme_client_jose.h"
#include "acme/acme_client_misc.h"
#include "encoding/base64url.h"
#include "jansson.h"
#include "jansson_private.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Check certificate order information
 * @param[in] params Certificate order information
 * @return Error code
 **/

error_t acmeClientCheckOrderParams(const AcmeOrderParams *params)
{
   uint_t i;

   //Sanity check
   if(params == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the number of domains
   if(params->numDomains == 0 ||
      params->numDomains > ACME_CLIENT_MAX_DOMAINS)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Make sure the list of domains is valid
   if(params->domains == NULL)
      return ERROR_INVALID_PARAMETER;

   //Loop through the list of domains
   for(i = 0; i < params->numDomains; i++)
   {
      //Each item must contain a valid domain name
      if(params->domains[i].name == NULL)
         return ERROR_INVALID_PARAMETER;

      //Check the length of the domain name
      if(osStrlen(params->domains[i].name) > ACME_CLIENT_MAX_NAME_LEN)
         return ERROR_INVALID_PARAMETER;

#if (ACME_CLIENT_HTTP_CHALLENGE_SUPPORT == ENABLED)
      //HTTP validation method?
      if(params->domains[i].challengeType == ACME_CHALLENGE_TYPE_HTTP_01)
      {
         //The challenge type is valid
      }
      else
#endif
#if (ACME_CLIENT_DNS_CHALLENGE_SUPPORT == ENABLED)
      //DNS validation method?
      if(params->domains[i].challengeType == ACME_CHALLENGE_TYPE_DNS_01)
      {
         //The challenge type is valid
      }
      else
#endif
#if (ACME_CLIENT_TLS_ALPN_CHALLENGE_SUPPORT == ENABLED)
      //TLS with ALPN validation method?
      if(params->domains[i].challengeType == ACME_CHALLENGE_TYPE_TLS_ALPN_01)
      {
         //The challenge type is valid
      }
      else
#endif
      //Invalid challenge type?
      {
         //Report an error
         return ERROR_INVALID_PARAMETER;
      }
   }

   //The certificate public key is required
   if(params->publicKey == NULL || params->publicKeyLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The certificate private key is required
   if(params->privateKey == NULL || params->privateKeyLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The account parameters are valid
   return NO_ERROR;
}


/**
 * @brief Initialize order object
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Certificate order information
 * @return Error code
 **/

error_t acmeClientInitOrder(AcmeClientContext *context,
   const AcmeOrderParams *params)
{
   error_t error;
   uint_t i;

   //Clear order object
   osMemset(&context->order, 0, sizeof(AcmeOrder));
   context->numIdentifiers = 0;
   context->numAuthorizations = 0;
   context->numChallenges = 0;

   //Clear identifier, authorization and challenge objects
   for(i = 0; i < ACME_CLIENT_MAX_DOMAINS; i++)
   {
      osMemset(&context->identifiers[i], 0, sizeof(AcmeIdentifier));
      osMemset(&context->authorizations[i], 0, sizeof(AcmeAuthorization));
      osMemset(&context->challenges[i], 0, sizeof(AcmeChallenge));
   }

   //An order may contain multiple identifiers
   context->numIdentifiers = params->numDomains;

   //Save identifiers
   for(i = 0; i < params->numDomains; i++)
   {
      //Save identifier value
      osStrcpy(context->identifiers[i].value, params->domains[i].name);
      //Save challenge type
      context->identifiers[i].challengeType = params->domains[i].challengeType;
   }

   //Release the current key pair, if any
   acmeClientUnloadKeyPair(&context->certKey);

   //The public and private keys are encoded in PEM format
   error = acmeClientLoadKeyPair(&context->certKey, params->publicKey,
      params->publicKeyLen, params->privateKey, params->privateKeyLen);

   //Return status code
   return error;
}


/**
 * @brief Send HTTP request (newOrder URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Certificate order information
 * @return Error code
 **/

error_t acmeClientSendNewOrderRequest(AcmeClientContext *context,
   const AcmeOrderParams *params)
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
         TRACE_DEBUG("## NEW ORDER ##################################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeClientFormatNewOrderRequest(context, params);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //The client begins the certificate issuance process by sending a
         //POST request to the server's newOrder resource (refer to RFC 8555,
         //section 7.4)
         error = acmeClientFormatRequestHeader(context, "POST",
            context->directory.newOrder);

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
         error = acmeClientParseNewOrderResponse(context);

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
 * @brief Format HTTP request body (newOrder URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] params Certificate order information
 * @return Error code
 **/

error_t acmeClientFormatNewOrderRequest(AcmeClientContext *context,
   const AcmeOrderParams *params)
{
   error_t error;
   int_t ret;
   uint_t i;
   size_t n;
   char_t *protected;
   char_t *payload;
   json_t *payloadObj;
   json_t *identifierObj;
   json_t *identifiersObj;

   //Initialize status code
   ret = 0;

   //Initialize JSON objects
   payloadObj = json_object();
   identifiersObj = json_array();

   //The body of the POST contains an array of identifier objects that the
   //client wishes to submit an order for (refer to RFC 8555, section 7.4)
   for(i = 0; i < params->numDomains; i++)
   {
      //Initialize JSON object
      identifierObj = json_object();

      //Set the type of identifier
      ret |= json_object_set_new(identifierObj, "type", json_string("dns"));

      //Set the identifier itself
      ret |= json_object_set_new(identifierObj, "value",
         json_string(params->domains[i].name));

      //Add the identifier object to the array
      ret |= json_array_append_new(identifiersObj, identifierObj);
   }

   //Add the "identifiers" field to the payload
   ret |= json_object_set_new(payloadObj, "identifiers", identifiersObj);

   //The client's request may specify the value of the notBefore field in
   //the certificate
   if(params->notBefore.year > 0 && params->notBefore.month > 0 &&
      params->notBefore.day > 0)
   {
      //The date format is specified by RFC 3339
      osSprintf(context->buffer, "%04u-%02u-%02uT%02u:%02u:%02uZ",
         params->notBefore.year, params->notBefore.month,
         params->notBefore.day, params->notBefore.hours,
         params->notBefore.minutes, params->notBefore.seconds);

      //Add the "notBefore" field to the payload
      ret |= json_object_set_new(payloadObj, "notBefore",
         json_string(context->buffer));
   }

   //The client's request may specify the value of the notAfter field in
   //the certificate
   if(params->notAfter.year > 0 && params->notAfter.month > 0 &&
      params->notAfter.day > 0)
   {
      //The date format is specified by RFC 3339
      osSprintf(context->buffer, "%04u-%02u-%02uT%02u:%02u:%02uZ",
         params->notAfter.year, params->notAfter.month,
         params->notAfter.day, params->notAfter.hours,
         params->notAfter.minutes, params->notAfter.seconds);

      //Add the "notAfter" field to the payload
      ret |= json_object_set_new(payloadObj, "notAfter",
         json_string(context->buffer));
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
         context->account.url, context->nonce, context->directory.newOrder,
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
 * @brief Parse HTTP response (newOrder URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseNewOrderResponse(AcmeClientContext *context)
{
   error_t error;
   uint_t i;
   uint_t n;
   const char_t *status;
   const char_t *authorization;
   const char_t *finalize;
   const char_t *certificate;
   json_t *rootObj;
   json_t *statusObj;
   json_t *arrayObj;
   json_t *authorizationObj;
   json_t *finalizeObj;
   json_t *certificateObj;

   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //The server must include a Replay-Nonce header field in every successful
   //response to a POST request (refer to RFC 8555, section 6.5)
   if(context->nonce[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //The response header must contain a valid Location HTTP header field
   if(context->order.url[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //Invalid media type?
   if(osStrcasecmp(context->contentType, "application/json"))
      return ERROR_INVALID_RESPONSE;

   //Check whether the body of the response is truncated
   if(context->bufferLen >= ACME_CLIENT_BUFFER_SIZE)
      return ERROR_RESPONSE_TOO_LARGE;

   //Initialize status code
   error = ERROR_INVALID_RESPONSE;

   //Decode JSON string
   rootObj = json_loads(context->buffer, 0, NULL);

   //Start of exception handling block
   do
   {
      //Any parsing error?
      if(!json_is_object(rootObj))
         break;

      //Get "status" object
      statusObj = json_object_get(rootObj, "status");

      //The object must be a valid string
      if(!json_is_string(statusObj))
         break;

      //Get the value of the string
      status = json_string_value(statusObj);
      //Retrieve the status of the order
      context->order.status = acmeClientParseOrderStatus(status);

      //Get "authorizations" object
      arrayObj = json_object_get(rootObj, "authorizations");

      //The object must be a valid array
      if(!json_is_array(arrayObj))
         break;

      //Retrieve the numbers of items in the array
      n = json_array_size(arrayObj);
      //Limit the numbers of authorizations
      n = MIN(n, ACME_CLIENT_MAX_DOMAINS);

      //Loop through the list of authorizations
      for(i = 0; i < n; i++)
      {
         //Point to the current authorization
         authorizationObj = json_array_get(arrayObj, i);

         //The object must be a valid string
         if(!json_is_string(authorizationObj))
            break;

         //Retrieve the value of the string
         authorization = json_string_value(authorizationObj);

         //Check the length of the string
         if(osStrlen(authorization) > ACME_CLIENT_MAX_URL_LEN)
            break;

         //Save the authorization URL
         osStrcpy(context->authorizations[i].url, authorization);

         //Increment the number of authorizations
         context->numAuthorizations++;
      }

      //Any parsing error?
      if(i < n)
         break;

      //Get "finalize" object
      finalizeObj = json_object_get(rootObj, "finalize");

      //The object must be a valid string
      if(!json_is_string(finalizeObj))
         break;

      //Retrieve the value of the string
      finalize = json_string_value(finalizeObj);

      //Check the length of the string
      if(osStrlen(finalize) > ACME_CLIENT_MAX_URL_LEN)
         break;

      //Save the finalize URL
      osStrcpy(context->order.finalize, finalize);

      //If the status of the order is "valid", the server has issued the
      //certificate and provisioned its URL to the "certificate" field of
      //the order
      if(context->order.status == ACME_ORDER_STATUS_VALID)
      {
         //Get "certificate" object
         certificateObj = json_object_get(rootObj, "certificate");

         //The object must be a valid string
         if(!json_is_string(certificateObj))
            break;

         //Retrieve the value of the string
         certificate = json_string_value(certificateObj);

         //Check the length of the string
         if(osStrlen(certificate) > ACME_CLIENT_MAX_URL_LEN)
            break;

         //Save the certificate URL
         osStrcpy(context->order.certificate, certificate);
      }

      //Successful parsing
      error = NO_ERROR;

      //End of exception handling block
   } while(0);

   //Release JSON object
   json_decref(rootObj);

   //Return status code
   return error;
}


/**
 * @brief Send HTTP request (order URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientSendOrderStatusRequest(AcmeClientContext *context)
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
         TRACE_DEBUG("## ORDER STATUS ###############################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeClientFormatOrderStatusRequest(context);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //The client should then send a POST-as-GET request to the order
         //resource to obtain its current state refer to RFC 8555, section 7.4)
         error = acmeClientFormatRequestHeader(context, "POST",
            context->order.url);

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
         error = acmeClientParseOrderStatusResponse(context);

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
 * @brief Format HTTP request body (order URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientFormatOrderStatusRequest(AcmeClientContext *context)
{
   error_t error;
   size_t n;
   char_t *protected;
   const char_t *payload;

   //The payload field is empty for POST-as-GET requests
   payload = "";

   //Point to the buffer where to format the JWS protected header
   protected = context->buffer;

   //Format JWS protected header
   error = acmeClientFormatJwsProtectedHeader(&context->accountKey,
      context->account.url, context->nonce, context->order.url, protected, &n);

   //Check status code
   if(!error)
   {
      //Generate the JSON Web Signature
      error = jwsCreate(context->prngAlgo, context->prngContext, protected,
         payload, context->accountKey.alg, context->accountKey.crv,
         context->accountKey.privateKey, context->buffer, &context->bufferLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Parse HTTP response (order URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseOrderStatusResponse(AcmeClientContext *context)
{
   error_t error;
   const char_t *status;
   const char_t *certificate;
   json_t *rootObj;
   json_t *statusObj;
   json_t *certificateObj;

   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //The server must include a Replay-Nonce header field in every successful
   //response to a POST request (refer to RFC 8555, section 6.5)
   if(context->nonce[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //Invalid media type?
   if(osStrcasecmp(context->contentType, "application/json"))
      return ERROR_INVALID_RESPONSE;

   //Check whether the body of the response is truncated
   if(context->bufferLen >= ACME_CLIENT_BUFFER_SIZE)
      return ERROR_RESPONSE_TOO_LARGE;

   //Initialize status code
   error = ERROR_INVALID_RESPONSE;

   //Decode JSON string
   rootObj = json_loads(context->buffer, 0, NULL);

   //Start of exception handling block
   do
   {
      //Any parsing error?
      if(!json_is_object(rootObj))
         break;

      //Get "status" object
      statusObj = json_object_get(rootObj, "status");

      //The object must be a valid string
      if(!json_is_string(statusObj))
         break;

      //Get the value of the string
      status = json_string_value(statusObj);
      //Retrieve the status of the order
      context->order.status = acmeClientParseOrderStatus(status);

      //If the status of the order is "valid", the server has issued the
      //certificate and provisioned its URL to the "certificate" field of
      //the order
      if(context->order.status == ACME_ORDER_STATUS_VALID)
      {
         //Get "certificate" object
         certificateObj = json_object_get(rootObj, "certificate");

         //The object must be a valid string
         if(!json_is_string(certificateObj))
            break;

         //Retrieve the value of the string
         certificate = json_string_value(certificateObj);

         //Check the length of the string
         if(osStrlen(certificate) > ACME_CLIENT_MAX_URL_LEN)
            break;

         //Save the certificate URL
         osStrcpy(context->order.certificate, certificate);
      }

      //Successful parsing
      error = NO_ERROR;

      //End of exception handling block
   } while(0);

   //Release JSON object
   json_decref(rootObj);

   //Return status code
   return error;
}


/**
 * @brief Send HTTP request (order's finalize URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientSendFinalizeOrderRequest(AcmeClientContext *context)
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
         TRACE_DEBUG("## FINALIZE ORDER #############################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeClientFormatFinalizeOrderRequest(context);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //Once the client believes it has fulfilled the server's requirements,
         //it should send a POST request to the order resource's finalize URL.
         //The POST body MUST include a CSR (refer to RFC 8555, section 7.4)
         error = acmeClientFormatRequestHeader(context, "POST",
            context->order.finalize);

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
         error = acmeClientParseFinalizeOrderResponse(context);

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
 * @brief Format HTTP request body (order's finalize URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientFormatFinalizeOrderRequest(AcmeClientContext *context)
{
   error_t error;
   int_t ret;
   size_t n;
   char_t *protected;
   char_t *payload;
   json_t *payloadObj;

   //Any registered callback?
   if(context->csrCallback != NULL)
   {
      //Invoke user callback function
      error = context->csrCallback(context, (uint8_t *) context->buffer,
         ACME_CLIENT_BUFFER_SIZE, &n);
   }
   else
   {
      //Generate the certificate signing request
      error = acmeClientGenerateCsr(context, (uint8_t *) context->buffer, &n);
   }

   //Any error to report?
   if(error)
      return error;

   //The CSR is sent in the Base64url-encoded version of the DER format
   base64urlEncode(context->buffer, n, context->buffer, &n);

   //Initialize JSON object
   payloadObj = json_object();

   //The POST body must include a CSR (refer to RFC 8555, section 7.4)
   ret = json_object_set_new(payloadObj, "csr", json_string(context->buffer));

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
         context->account.url, context->nonce, context->order.finalize,
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
 * @brief Parse HTTP response (order's finalize URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseFinalizeOrderResponse(AcmeClientContext *context)
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
 * @brief Parse order status field
 * @param[in] label Textual representation of the status
 * @return Order status code
 **/

AcmeOrderStatus acmeClientParseOrderStatus(const char_t *label)
{
   AcmeOrderStatus status;

   //Check the status of the order (refer to RFC 8555, section 7.1.6)
   if(!osStrcmp(label, "pending"))
   {
      // Order objects are created in the "pending" state
      status = ACME_ORDER_STATUS_PENDING;
   }
   else if(!osStrcmp(label, "ready"))
   {
      //Once all of the authorizations listed in the order object are in the
      //"valid" state, the order transitions to the "ready" state
      status = ACME_ORDER_STATUS_READY;
   }
   else if(!osStrcmp(label, "processing"))
   {
      //The order moves to the "processing" state after the client submits a
      //request to the order's "finalize" URL
      status = ACME_ORDER_STATUS_PROCESSING;
   }
   else if(!osStrcmp(label, "valid"))
   {
      //Once the certificate is issued, the order enters the "valid" state
      status = ACME_ORDER_STATUS_VALID;
   }
   else if(!osStrcmp(label, "invalid"))
   {
      //The order also moves to the "invalid" state if it expires or one of
      //itS authorizations enters a final state other than "valid" ("expired",
      //"revoked", or "deactivated")
      status = ACME_ORDER_STATUS_INVALID;
   }
   else
   {
      //Unknown status
      status = ACME_ORDER_STATUS_INVALID;
   }

   //Return current status
   return status;
}

#endif
