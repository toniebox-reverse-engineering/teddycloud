/**
 * @file acme_client_nonce.c
 * @brief Anti-replay nonce management
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
#include "acme/acme_client_nonce.h"
#include "acme/acme_client_misc.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Send HTTP request (newNonce URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientSendNewNonceRequest(AcmeClientContext *context)
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
         TRACE_DEBUG("################################################################################\r\n");
         TRACE_DEBUG("## GET NEW NONCE ###############################################################\r\n");
         TRACE_DEBUG("################################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Check whether the nonce is fresh
         if(context->nonce[0] != '\0')
         {
            //The client has gotten a nonce from a previous request
            break;
         }
         else
         {
            //If the nonce is no longer valid, the client must get a fresh nonce
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //To get a fresh nonce, the client sends a HEAD request to the newNonce
         //resource on the server (refer to RFC 8555, section 7.2)
         error = acmeClientFormatRequestHeader(context, "HEAD",
            context->directory.newNonce);

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
         //The response to a HEAD request does not contain a body
         error = acmeClientParseNewNonceResponse(context);

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
 * @brief Parse HTTP response (newNonce URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseNewNonceResponse(AcmeClientContext *context)
{
   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //The server's response must include a Replay-Nonce header field containing
   //a fresh nonce (refer to RFC 8555, section 7.2)
   if(context->nonce[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //The response to a HEAD request does not contain a body
   return NO_ERROR;
}

#endif
