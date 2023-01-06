/**
 * @file acme_client_certificate.c
 * @brief Certificate management
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
#include "acme/acme_client_certificate.h"
#include "acme/acme_client_jose.h"
#include "acme/acme_client_misc.h"
#include "pkix/pem_import.h"
#include "encoding/base64url.h"
#include "jansson.h"
#include "jansson_private.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Send HTTP request (certificate URL)
 * @param[in] context Pointer to the ACME client context
 * @param[out] buffer Pointer to the buffer where to store the certificate chain
 * @param[in] size Size of the buffer, in bytes
 * @param[out] length Actual length of the certificate chain, in bytes
 * @return Error code
 **/

error_t acmeClientSendDownloadCertRequest(AcmeClientContext *context,
   char_t *buffer, size_t size, size_t *length)
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
         TRACE_DEBUG("## DOWNLOAD CERTIFICATE #######################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeClientFormatDownloadCertRequest(context);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //To download the issued certificate, the client simply sends a
         //POST-as-GET request to the certificate URL (refer to RFC 8555,
         //section 7.4.2)
         error = acmeClientFormatRequestHeader(context, "POST",
            context->order.certificate);

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
         error = acmeClientParseDownloadCertResponse(context, buffer, size,
            length);

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
 * @brief Format HTTP request body (certificate URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientFormatDownloadCertRequest(AcmeClientContext *context)
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
      context->account.url, context->nonce, context->order.certificate,
      protected, &n);

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
 * @brief Parse HTTP response (certificate URL)
 * @param[in] context Pointer to the ACME client context
 * @param[out] buffer Pointer to the buffer where to store the certificate chain
 * @param[in] size Size of the buffer, in bytes
 * @param[out] length Actual length of the certificate chain, in bytes
 * @return Error code
 **/

error_t acmeClientParseDownloadCertResponse(AcmeClientContext *context,
   char_t *buffer, size_t size, size_t *length)
{
   error_t error;
   size_t n;

   //Initialize variables
   error = NO_ERROR;

   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //The server must include a Replay-Nonce header field in every successful
   //response to a POST request (refer to RFC 8555, section 6.5)
   if(context->nonce[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //Invalid media type?
   if(osStrcasecmp(context->contentType, "application/pem-certificate-chain"))
      return ERROR_INVALID_RESPONSE;

   //Check whether the body of the response is truncated
   if(context->bufferLen >= ACME_CLIENT_BUFFER_SIZE)
      return ERROR_RESPONSE_TOO_LARGE;

   //The body must contain a valid PEM certificate chain
   error = pemImportCertificate(context->buffer, context->bufferLen, NULL,
      &n, NULL);
   //Any error to report?
   if(error)
      return ERROR_INVALID_RESPONSE;

   //Make sure the output buffer is large enough to hold the certificate
   if(context->bufferLen > size)
      return ERROR_BUFFER_OVERFLOW;

   //Copy certificate chain
   osMemcpy(buffer, context->buffer, context->bufferLen);

   //Return the length of the certificate chain
   *length = context->bufferLen;

   //Return status code
   return error;
}


/**
 * @brief Send HTTP request (revokeCert URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] cert Certificate to be revoked (PEM format)
 * @param[in] certLen Length of the certificate, in bytes
 * @param[in] reason Revocation reason code
 * @return Error code
 **/

error_t acmeClientSendRevokeCertRequest(AcmeClientContext *context,
   const char_t *cert, size_t certLen, AcmeReasonCode reason)
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
         TRACE_DEBUG("## REVOKE CERTIFICATE #########################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeClientFormatRevokeCertRequest(context, cert, certLen, reason);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //To request that a certificate be revoked, the client sends a POST
         //request to the ACME server's revokeCert URL (refer to RFC 8555,
         //section 7.6)
         error = acmeClientFormatRequestHeader(context, "POST",
            context->directory.revokeCert);

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
         error = acmeClientParseRevokeCertResponse(context);

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
 * @brief Format HTTP request body (revokeCert URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] cert Certificate to be revoked (PEM format)
 * @param[in] certLen Length of the certificate, in bytes
 * @param[in] reason Revocation reason code
 * @return Error code
 **/

error_t acmeClientFormatRevokeCertRequest(AcmeClientContext *context,
   const char_t *cert, size_t certLen, AcmeReasonCode reason)
{
   error_t error;
   int_t ret;
   size_t n;
   char_t *protected;
   char_t *payload;
   json_t *payloadObj;

   //Convert the PEM certificate to DER format
   error = pemImportCertificate(cert, certLen, (uint8_t *) context->buffer,
      &n, NULL);
   //Any error to report?
   if(error)
      return error;

   //Encode the DER certificate using Base64url
   base64urlEncode(context->buffer, n, context->buffer, &n);

   //Initialize JSON object
   payloadObj = json_object();

   //The body of the POST contains the certificate to be revoked
   ret = json_object_set_new(payloadObj, "certificate",
      json_string(context->buffer));

   //The client may include a revocation reason code
   ret |= json_object_set_new(payloadObj, "reason",
      json_integer((json_int_t) reason));

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
         context->account.url, context->nonce, context->directory.revokeCert,
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
 * @brief Parse HTTP response (certificate URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseRevokeCertResponse(AcmeClientContext *context)
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
