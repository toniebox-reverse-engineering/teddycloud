/**
 * @file acme_client_auth.c
 * @brief Authorization object management
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
#include "acme/acme_client_auth.h"
#include "acme/acme_client_challenge.h"
#include "acme/acme_client_jose.h"
#include "acme/acme_client_misc.h"
#include "jansson.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Send HTTP request (authorization URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] authorization Pointer to the authorization object
 * @return Error code
 **/

error_t acmeClientSendAuthorizationRequest(AcmeClientContext *context,
   AcmeAuthorization *authorization)
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
         TRACE_DEBUG("## GET AUTHORIZATION ##########################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeFormatAuthorizationRequest(context, authorization);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //When a client receives an order from the server in reply to a
         //newOrder request, it downloads the authorization resources by
         //sending POST-as-GET requests to the indicated URLs (refer to
         //RFC 8555, section 7.5)
         error = acmeClientFormatRequestHeader(context, "POST",
            authorization->url);

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
         error = acmeClientParseAuthorizationResponse(context, authorization);

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
 * @brief Format HTTP request body (authorization URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] authorization Pointer to the authorization object
 * @return Error code
 **/

error_t acmeFormatAuthorizationRequest(AcmeClientContext *context,
   const AcmeAuthorization *authorization)
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
      context->account.url, context->nonce, authorization->url, protected, &n);

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
 * @brief Parse HTTP response (authorization URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] authorization Pointer to the authorization object
 * @return Error code
 **/

error_t acmeClientParseAuthorizationResponse(AcmeClientContext *context,
   AcmeAuthorization *authorization)
{
   error_t error;
   uint_t i;
   uint_t n;
   const char_t *status;
   const char_t *value;
   const char_t *type;
   const char_t *url;
   const char_t *token;
   json_t *rootObj;
   json_t *statusObj;
   json_t *identifierObj;
   json_t *valueObj;
   json_t *wildcardObj;
   json_t *arrayObj;
   json_t *challengeObj;
   json_t *typeObj;
   json_t *urlObj;
   json_t *tokenObj;
   AcmeChallenge *challenge;
   AcmeChallengeType challengeType;

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
      //Retrieve the status of the authorization
      authorization->status = acmeClientParseAuthorizationStatus(status);

      //Get "identifier" object
      identifierObj = json_object_get(rootObj, "identifier");

      //Invalid object?
      if(!json_is_object(identifierObj))
         break;

      //Get "value" object
      valueObj = json_object_get(identifierObj, "value");

      //The object must be a valid string
      if(!json_is_string(valueObj))
         break;

      //Get the value of the string
      value = json_string_value(valueObj);

      //Check the length of the identifier value
      if(osStrlen(value) > ACME_CLIENT_MAX_URL_LEN)
         break;

      //Get "wildcard" object
      wildcardObj = json_object_get(rootObj, "wildcard");

      //The object is optional
      if(json_is_boolean(wildcardObj))
      {
         //Get the value of the boolean
         authorization->wildcard = json_boolean_value(wildcardObj);
      }

      //Retrieve the challenge validation method
      challengeType = acmeClientGetChallengeType(context, value,
         authorization->wildcard);

      //Check the status of the authorization
      if(authorization->status == ACME_AUTH_STATUS_PENDING)
      {
         //Get "challenges" object
         arrayObj = json_object_get(rootObj, "challenges");

         //The object must be a valid array
         if(!json_is_array(arrayObj))
            break;

         //Retrieve the numbers of items in the array
         n = json_array_size(arrayObj);

         //Loop through the list of challenges
         for(i = 0; i < n; i++)
         {
            //Point to the current challenge
            challengeObj = json_array_get(arrayObj, i);

            //Invalid object?
            if(!json_is_object(challengeObj))
               break;

            //Challenge objects all contain the following basic fields
            typeObj = json_object_get(challengeObj, "type");
            urlObj = json_object_get(challengeObj, "url");
            statusObj = json_object_get(challengeObj, "status");

            //Invalid challenge object?
            if(!json_is_string(typeObj) ||
               !json_is_string(urlObj) ||
               !json_is_string(statusObj))
            {
               break;
            }

            //The strings are NULL-terminated
            type = json_string_value(typeObj);
            url = json_string_value(urlObj);
            status = json_string_value(statusObj);

            //Check challenge type
            if(acmeClientParseChallengeType(type) == challengeType)
            {
               //Additional fields are specified by the challenge type
               tokenObj = json_object_get(challengeObj, "token");

               //The object must be a valid string
               if(!json_is_string(tokenObj))
                  break;

               //Get the value of the string
               token = json_string_value(tokenObj);

               //Valid challenge object?
               if(osStrlen(url) <= ACME_CLIENT_MAX_URL_LEN &&
                  osStrlen(token) <= ACME_CLIENT_MAX_URL_LEN &&
                  osStrlen(value) <= ACME_CLIENT_MAX_NAME_LEN)
               {
                  //Point to the current challenge
                  challenge = &context->challenges[context->numChallenges];

                  //Retrieve the status of the challenge
                  challenge->status = acmeClientParseChallengeStatus(status);
                  //Save challenge URL
                  osStrcpy(challenge->url, url);
                  //Save token value
                  osStrcpy(challenge->token, token);

                  //Save domain name
                  osStrcpy(challenge->identifier, value);
                  challenge->wildcard = authorization->wildcard;

                  //Save challenge type
                  challenge->type = challengeType;

                  //Generate a key authorization from the "token" value provided
                  //in the challenge and the client's account key
                  error = acmeClientGenerateKeyAuthorization(context, challenge);

                  //Check status code
                  if(!error)
                  {
                     //DNS or TLS-ALPN validation method?
                     if(challenge->type == ACME_CHALLENGE_TYPE_DNS_01)
                     {
                        //The client computes the SHA-256 digest of the key
                        //authorization
                        error = acmeClientDigestKeyAuthorization(context,
                           challenge);
                     }
                     else if(challenge->type == ACME_CHALLENGE_TYPE_TLS_ALPN_01)
                     {
                        //The client prepares for validation by constructing a self-
                        //signed certificate
                        error = acmeClientGenerateTlsAlpnCert(context, challenge);
                     }
                     else
                     {
                        //Just for sanity
                     }
                  }

                  //Check status code
                  if(!error)
                  {
                     //Increment the number of challenges
                     context->numChallenges++;
                  }

                  //Exit immediately
                  break;
               }
            }
         }
      }
      else
      {
         //Challenge validation is not required since the authorization is not
         //in "pending" state
         error = NO_ERROR;
      }

      //End of exception handling block
   } while(0);

   //Release JSON object
   json_decref(rootObj);

   //Return status code
   return error;
}


/**
 * @brief Parse authorization status field
 * @param[in] label Textual representation of the status
 * @return Authorization status code
 **/

AcmeAuthStatus acmeClientParseAuthorizationStatus(const char_t *label)
{
   AcmeAuthStatus status;

   //Check the status of the authorization (refer to RFC 8555, section 7.1.6)
   if(!osStrcmp(label, "pending"))
   {
      //Authorization objects are created in the "pending" state
      status = ACME_AUTH_STATUS_PENDING;
   }
   else if(!osStrcmp(label, "valid"))
   {
      //If one of the challenges listed in the authorization transitions to the
      //"valid" state, then the authorization also changes to the "valid" state
      status = ACME_AUTH_STATUS_VALID;
   }
   else if(!osStrcmp(label, "invalid"))
   {
      //If the client attempts to fulfill a challenge and fails, or if there is
      //an error while the authorization is still pending, then the authorization
      //transitions to the "invalid" state
      status = ACME_AUTH_STATUS_INVALID;
   }
   else if(!osStrcmp(label, "expired"))
   {
      //A valid authorization can expire
      status = ACME_AUTH_STATUS_EXPIRED;
   }
   else if(!osStrcmp(label, "deactivated"))
   {
      //An valid authorization can be deactivated by the client
      status = ACME_AUTH_STATUS_DEACTIVATED;
   }
   else if(!osStrcmp(label, "revoked"))
   {
      //An valid authorization can be revoked by the server
      status = ACME_AUTH_STATUS_REVOKED;
   }
   else
   {
      //Unknown status
      status = ACME_AUTH_STATUS_INVALID;
   }

   //Return current status
   return status;
}

#endif
