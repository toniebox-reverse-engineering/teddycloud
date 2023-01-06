/**
 * @file acme_dns_client_misc.c
 * @brief Helper functions for ACME-DNS client
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
#define TRACE_LEVEL ACME_DNS_TRACE_LEVEL

//Dependencies
#include "dns_api/acme_dns_client.h"
#include "dns_api/acme_dns_client_misc.h"
#include "jansson.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_DNS_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Format HTTP request body (register endpoint)
 * @param[in] context Pointer to the ACME-DNS client context
 * @return Error code
 **/

error_t acmeDnsClientFormatRegisterRequest(AcmeDnsClientContext *context)
{
   bool_t defaultPort;

   //Create an HTTP request
   httpClientCreateRequest(&context->httpClientContext);
   httpClientSetMethod(&context->httpClientContext, "POST");
   httpClientSetUri(&context->httpClientContext, "/register");

#if (ACME_DNS_CLIENT_TLS_SUPPORT == ENABLED)
   //"https" URI scheme?
   if(context->tlsInitCallback != NULL)
   {
      //The default port number is 443 for "https" URI scheme
      defaultPort = (context->serverPort == HTTPS_PORT) ? TRUE : FALSE;
   }
   else
#endif
   //"http" URI scheme?
   {
      //The default port number is 80 for "http" URI scheme
      defaultPort = (context->serverPort == HTTP_PORT) ? TRUE : FALSE;
   }

   //A client must send a Host header field in all HTTP/1.1 requests (refer
   //to RFC 7230, section 5.4)
   if(defaultPort)
   {
      //A host without any trailing port information implies the default port
      //for the service requested
      httpClientAddHeaderField(&context->httpClientContext, "Host",
         context->serverName);
   }
   else
   {
      //Append the port number information to the host
      httpClientFormatHeaderField(&context->httpClientContext,
         "Host", "%s:%" PRIu16, context->serverName, context->serverPort);
   }

   //Add HTTP header fields
   httpClientAddHeaderField(&context->httpClientContext, "User-Agent",
      "Mozilla/5.0");

   httpClientAddHeaderField(&context->httpClientContext, "Content-Type",
      "application/json");

   //The body of the request is empty
   httpClientSetContentLength(&context->httpClientContext, 0);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse HTTP response (register endpoint)
 * @param[in] context Pointer to the ACME-DNS client context
 * @return Error code
 **/

error_t acmeDnsClientParseRegisterResponse(AcmeDnsClientContext *context)
{
   error_t error;
   const char_t *username;
   const char_t *password;
   const char_t *subDomain;
   const char_t *fullDomain;
   json_t *rootObj;
   json_t *usernameObj;
   json_t *passwordObj;
   json_t *subDomainObj;
   json_t *fullDomainObj;

   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //Check whether the body of the response is truncated
   if(context->bufferLen >= ACME_DNS_CLIENT_BUFFER_SIZE)
      return ERROR_RESPONSE_TOO_LARGE;

   //Initialize status code
   error = ERROR_INVALID_RESPONSE;

   //Clear credentials
   context->username[0] = '\0';
   context->password[0] = '\0';
   context->subDomain[0] = '\0';
   context->fullDomain[0] = '\0';

   //Decode JSON string
   rootObj = json_loads(context->buffer, 0, NULL);

   //Successful parsing?
   if(json_is_object(rootObj))
   {
      //The method returns a new unique subdomain and credentials needed to
      //update the record
      usernameObj = json_object_get(rootObj, "username");
      passwordObj = json_object_get(rootObj, "password");
      subDomainObj = json_object_get(rootObj, "subdomain");
      fullDomainObj = json_object_get(rootObj, "fulldomain");

      //Valid credentials?
      if(json_is_string(usernameObj) &&
         json_is_string(passwordObj) &&
         json_is_string(subDomainObj) &&
         json_is_string(fullDomainObj))
      {
         //The strings are NULL-terminated
         username = json_string_value(usernameObj);
         password = json_string_value(passwordObj);
         subDomain = json_string_value(subDomainObj);
         fullDomain = json_string_value(fullDomainObj);

         //Check the length of the URLs
         if(osStrlen(username) <= ACME_DNS_CLIENT_MAX_USERNAME_LEN &&
            osStrlen(password) <= ACME_DNS_CLIENT_MAX_PASSWORD_LEN &&
            osStrlen(subDomain) <= ACME_DNS_CLIENT_MAX_SUB_DOMAIN_LEN &&
            osStrlen(fullDomain) <= ACME_DNS_CLIENT_MAX_FULL_DOMAIN_LEN)
         {
            //Save the credentials
            osStrcpy(context->username, username);
            osStrcpy(context->password, password);
            osStrcpy(context->subDomain, subDomain);
            osStrcpy(context->fullDomain, fullDomain);

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


/**
 * @brief Format HTTP request body (update endpoint)
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] txt NULL-terminated string that contains the value of the TXT record
 * @return Error code
 **/

error_t acmeDnsClientFormatUpdateRequest(AcmeDnsClientContext *context,
   const char_t *txt)
{
   bool_t defaultPort;

   //Check the length of the TXT record
   if(osStrlen(txt) != ACME_DNS_TXT_RECORD_LEN)
      return ERROR_INVALID_LENGTH;

   //Create an HTTP request
   httpClientCreateRequest(&context->httpClientContext);
   httpClientSetMethod(&context->httpClientContext, "POST");
   httpClientSetUri(&context->httpClientContext, "/update");

#if (ACME_DNS_CLIENT_TLS_SUPPORT == ENABLED)
   //"https" URI scheme?
   if(context->tlsInitCallback != NULL)
   {
      //The default port number is 443 for "https" URI scheme
      defaultPort = (context->serverPort == HTTPS_PORT) ? TRUE : FALSE;
   }
   else
#endif
   //"http" URI scheme?
   {
      //The default port number is 80 for "http" URI scheme
      defaultPort = (context->serverPort == HTTP_PORT) ? TRUE : FALSE;
   }

   //A client must send a Host header field in all HTTP/1.1 requests (refer
   //to RFC 7230, section 5.4)
   if(defaultPort)
   {
      //A host without any trailing port information implies the default port
      //for the service requested
      httpClientAddHeaderField(&context->httpClientContext, "Host",
         context->serverName);
   }
   else
   {
      //Append the port number information to the host
      httpClientFormatHeaderField(&context->httpClientContext,
         "Host", "%s:%" PRIu16, context->serverName, context->serverPort);
   }

   //Add HTTP header fields
   httpClientAddHeaderField(&context->httpClientContext, "User-Agent",
      "Mozilla/5.0");

   httpClientAddHeaderField(&context->httpClientContext, "X-Api-User",
      context->username);

   httpClientAddHeaderField(&context->httpClientContext, "X-Api-Key",
      context->password);

   httpClientAddHeaderField(&context->httpClientContext, "Content-Type",
      "application/json");

   //Format the body of the POST request
   context->bufferLen = osSprintf(context->buffer,
      "{\"subdomain\":\"%s\",\"txt\":\"%s\"}", context->subDomain, txt);

   //The body of the request is empty
   httpClientSetContentLength(&context->httpClientContext, context->bufferLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse HTTP response (update endpoint)
 * @param[in] context Pointer to the ACME-DNS client context
 * @return Error code
 **/

error_t acmeDnsClientParseUpdateResponse(AcmeDnsClientContext *context)
{
   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //Check whether the body of the response is truncated
   if(context->bufferLen >= ACME_DNS_CLIENT_BUFFER_SIZE)
      return ERROR_RESPONSE_TOO_LARGE;

   //Successful processing
   return NO_ERROR;
}

#endif
