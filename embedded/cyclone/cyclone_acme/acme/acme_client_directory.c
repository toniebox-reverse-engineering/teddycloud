/**
 * @file acme_client_directory.c
 * @brief Directory object management
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
#include "acme/acme_client_directory.h"
#include "acme/acme_client_misc.h"
#include "jansson.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Send HTTP request (directory URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientSendDirectoryRequest(AcmeClientContext *context)
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
         TRACE_DEBUG("## GET DIRECTORY ##############################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Check whether the directory object is up-to-date
         if(context->directory.newNonce[0] != '\0' &&
            context->directory.newAccount[0] != '\0' &&
            context->directory.newOrder[0] != '\0' &&
            context->directory.revokeCert[0] != '\0' &&
            context->directory.keyChange[0] != '\0')
         {
            //The directory contains the most recent information available
            break;
         }
         else
         {
            //If the directory object is no longer fresh, the client must access
            //the directory again by sending a GET request to the directory URL
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //Clients access the directory by sending a GET request to the
         //directory URL (refer to RFC 8555, section 7.1.1)
         error = acmeClientFormatRequestHeader(context, "GET",
            context->directoryUri);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_SEND_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_SEND_HEADER ||
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
         error = acmeClientParseDirectoryResponse(context);

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
 * @brief Parse HTTP response (directory URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseDirectoryResponse(AcmeClientContext *context)
{
   error_t error;
   const char_t *newNonce;
   const char_t *newAccount;
   const char_t *newOrder;
   const char_t *revokeCert;
   const char_t *keyChange;
   json_t *rootObj;
   json_t *newNonceObj;
   json_t *newAccountObj;
   json_t *newOrderObj;
   json_t *revokeCertObj;
   json_t *keyChangeObj;

   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //Invalid media type?
   if(osStrcasecmp(context->contentType, "application/json"))
      return ERROR_INVALID_RESPONSE;

   //Check whether the body of the response is truncated
   if(context->bufferLen >= ACME_CLIENT_BUFFER_SIZE)
      return ERROR_RESPONSE_TOO_LARGE;

   //Initialize status code
   error = ERROR_INVALID_RESPONSE;

   //Clear directory object
   osMemset(&context->directory, 0, sizeof(AcmeDirectory));

   //Decode JSON string
   rootObj = json_loads(context->buffer, 0, NULL);

   //Successful parsing?
   if(json_is_object(rootObj))
   {
      //In order to help clients configure themselves with the right URLs for
      //each ACME operation, ACME servers provide a directory object
      newNonceObj = json_object_get(rootObj, "newNonce");
      newAccountObj = json_object_get(rootObj, "newAccount");
      newOrderObj = json_object_get(rootObj, "newOrder");
      revokeCertObj = json_object_get(rootObj, "revokeCert");
      keyChangeObj = json_object_get(rootObj, "keyChange");

      //Valid directory object?
      if(json_is_string(newNonceObj) &&
         json_is_string(newAccountObj) &&
         json_is_string(newOrderObj) &&
         json_is_string(revokeCertObj) &&
         json_is_string(keyChangeObj))
      {
         //The strings are NULL-terminated
         newNonce = json_string_value(newNonceObj);
         newAccount = json_string_value(newAccountObj);
         newOrder = json_string_value(newOrderObj);
         revokeCert = json_string_value(revokeCertObj);
         keyChange = json_string_value(keyChangeObj);

         //Check the length of the URLs
         if(osStrlen(newNonce) <= ACME_CLIENT_MAX_URL_LEN &&
            osStrlen(newAccount) <= ACME_CLIENT_MAX_URL_LEN &&
            osStrlen(newOrder) <= ACME_CLIENT_MAX_URL_LEN &&
            osStrlen(revokeCert) <= ACME_CLIENT_MAX_URL_LEN &&
            osStrlen(keyChange) <= ACME_CLIENT_MAX_URL_LEN)
         {
            //Save the corresponding URLs
            osStrcpy(context->directory.newNonce, newNonce);
            osStrcpy(context->directory.newAccount, newAccount);
            osStrcpy(context->directory.newOrder, newOrder);
            osStrcpy(context->directory.revokeCert, revokeCert);
            osStrcpy(context->directory.keyChange, keyChange);

            //The response was successfully parsed
            error = NO_ERROR;
         }
      }
   }

   //Release JSON object
   json_decref(rootObj);

   //Return status code
   return error;
}

#endif
