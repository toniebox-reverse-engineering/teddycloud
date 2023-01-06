/**
 * @file acme_dns_client.c
 * @brief ACME-DNS client
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
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_DNS_CLIENT_SUPPORT == ENABLED)


/**
 * @brief Initialize ACME-DNS client context
 * @param[in] context Pointer to the ACME-DNS client context
 * @return Error code
 **/

error_t acmeDnsClientInit(AcmeDnsClientContext *context)
{
   error_t error;

   //Make sure the ACME-DNS client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Clear ACME-DNS client context
   osMemset(context, 0, sizeof(AcmeDnsClientContext));

   //Initialize HTTP client context
   error = httpClientInit(&context->httpClientContext);
   //Any error to report?
   if(error)
      return error;

   //Initialize ACME-DNS client state
   context->state = ACME_DNS_CLIENT_STATE_DISCONNECTED;
   //Default timeout
   context->timeout = ACME_DNS_CLIENT_DEFAULT_TIMEOUT;

   //Successful initialization
   return NO_ERROR;
}


#if (ACME_DNS_CLIENT_TLS_SUPPORT == ENABLED)

/**
 * @brief Register TLS initialization callback function
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] callback TLS initialization callback function
 * @return Error code
 **/

error_t acmeDnsClientRegisterTlsInitCallback(AcmeDnsClientContext *context,
   AcmeDnsClientTlsInitCallback callback)
{
   //Make sure the ACME-DNS client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save callback function
   context->tlsInitCallback = callback;

   //Successful processing
   return NO_ERROR;
}

#endif


/**
 * @brief Set communication timeout
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] timeout Timeout value, in milliseconds
 * @return Error code
 **/

error_t acmeDnsClientSetTimeout(AcmeDnsClientContext *context,
   systime_t timeout)
{
   //Make sure the ACME-DNS client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the domain name of the ACME-DNS server
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] host NULL-terminated string containing the host name
 * @return Error code
 **/

error_t acmeDnsClientSetHost(AcmeDnsClientContext *context,
   const char_t *host)
{
   //Check parameters
   if(context == NULL || host == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the host name is acceptable
   if(osStrlen(host) > ACME_DNS_CLIENT_MAX_HOST_LEN)
      return ERROR_INVALID_LENGTH;

   //Save host name
   osStrcpy(context->serverName, host);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set user name
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] username NULL-terminated string containing the user name
 * @return Error code
 **/

error_t acmeDnsClientSetUsername(AcmeDnsClientContext *context,
   const char_t *username)
{
   //Check parameters
   if(context == NULL || username == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the user name is acceptable
   if(osStrlen(username) > ACME_DNS_CLIENT_MAX_USERNAME_LEN)
      return ERROR_INVALID_LENGTH;

   //Save user name
   osStrcpy(context->username, username);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set password
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] password NULL-terminated string containing the password
 * @return Error code
 **/

error_t acmeDnsClientSetPassword(AcmeDnsClientContext *context,
   const char_t *password)
{
   //Check parameters
   if(context == NULL || password == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the password is acceptable
   if(osStrlen(password) > ACME_DNS_CLIENT_MAX_PASSWORD_LEN)
      return ERROR_INVALID_LENGTH;

   //Save password
   osStrcpy(context->password, password);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set sub domain
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] subDomain NULL-terminated string containing the sub domain
 * @return Error code
 **/

error_t acmeDnsClientSetSubDomain(AcmeDnsClientContext *context,
   const char_t *subDomain)
{
   //Check parameters
   if(context == NULL || subDomain == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the length of the sub domain is acceptable
   if(osStrlen(subDomain) > ACME_DNS_CLIENT_MAX_SUB_DOMAIN_LEN)
      return ERROR_INVALID_LENGTH;

   //Save sub domain
   osStrcpy(context->subDomain, subDomain);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get user name
 * @param[in] context Pointer to the ACME-DNS client context
 * @return NULL-terminated string containing the user name
 **/

const char_t *acmeDnsClientGetUsername(AcmeDnsClientContext *context)
{
   const char_t *username;

   //Make sure the ACME-DNS client context is valid
   if(context != NULL)
   {
      username = context->username;
   }
   else
   {
      username = NULL;
   }

   //Return the user name
   return username;
}


/**
 * @brief Get password
 * @param[in] context Pointer to the ACME-DNS client context
 * @return NULL-terminated string containing the password
 **/

const char_t *acmeDnsClientGetPassword(AcmeDnsClientContext *context)
{
   const char_t *password;

   //Make sure the ACME-DNS client context is valid
   if(context != NULL)
   {
      password = context->password;
   }
   else
   {
      password = NULL;
   }

   //Return the password
   return password;
}


/**
 * @brief Get sub domain
 * @param[in] context Pointer to the ACME-DNS client context
 * @return NULL-terminated string containing the sub domain
 **/

const char_t *acmeDnsClientGetSubDomain(AcmeDnsClientContext *context)
{
   const char_t *subDomain;

   //Make sure the ACME-DNS client context is valid
   if(context != NULL)
   {
      subDomain = context->subDomain;
   }
   else
   {
      subDomain = NULL;
   }

   //Return the sub domain
   return subDomain;
}


/**
 * @brief Get full domain
 * @param[in] context Pointer to the ACME-DNS client context
 * @return NULL-terminated string containing the full domain
 **/

const char_t *acmeDnsClientGetFullDomain(AcmeDnsClientContext *context)
{
   const char_t *fullDomain;

   //Make sure the ACME-DNS client context is valid
   if(context != NULL)
   {
      fullDomain = context->fullDomain;
   }
   else
   {
      fullDomain = NULL;
   }

   //Return the full domain
   return fullDomain;
}


/**
 * @brief Bind the ACME-DNS client to a particular network interface
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] interface Network interface to be used
 * @return Error code
 **/

error_t acmeDnsClientBindToInterface(AcmeDnsClientContext *context,
   NetInterface *interface)
{
   //Make sure the ACME-DNS client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Explicitly associate the ACME-DNS client with the specified interface
   context->interface = interface;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Establish a connection with the specified ACME-DNS server
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] serverIpAddr IP address of the ACME-DNS server to connect to
 * @param[in] serverPort Port number
 * @return Error code
 **/

error_t acmeDnsClientConnect(AcmeDnsClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Make sure the ACME-DNS client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Establish connection with the HTTP server
   while(!error)
   {
      //Check ACME-DNS client state
      if(context->state == ACME_DNS_CLIENT_STATE_DISCONNECTED)
      {
         //Save the TCP port number to be used
         context->serverPort = serverPort;

#if (ACME_DNS_CLIENT_TLS_SUPPORT == ENABLED)
         //Register TLS initialization callback
         error = httpClientRegisterTlsInitCallback(&context->httpClientContext,
            context->tlsInitCallback);
#endif
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
            //Establish HTTP connection
            context->state = ACME_DNS_CLIENT_STATE_CONNECTING;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_CONNECTING)
      {
         //Establish HTTP connection
         error = httpClientConnect(&context->httpClientContext, serverIpAddr,
            serverPort);

         //Check status code
         if(error == NO_ERROR)
         {
            //The HTTP connection is established
            context->state = ACME_DNS_CLIENT_STATE_CONNECTED;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_CONNECTED)
      {
         //The client is connected to the ACME-DNS server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to establish connection with the ACME-DNS server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Clean up side effects
      httpClientClose(&context->httpClientContext);
      //Update ACME-DNS client state
      context->state = ACME_DNS_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Register endpoint
 * @param[in] context Pointer to the ACME-DNS client context
 * @return Error code
 **/

error_t acmeDnsClientRegister(AcmeDnsClientContext *context)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check ACME-DNS client state
      if(context->state == ACME_DNS_CLIENT_STATE_CONNECTED)
      {
         //Format the POST request (register endpoint)
         error = acmeDnsClientFormatRegisterRequest(context);

         //Check status code
         if(!error)
         {
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_SEND_HEADER;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_SEND_HEADER)
      {
         //Send HTTP request header
         error = httpClientWriteHeader(&context->httpClientContext);

         //Check status code
         if(!error)
         {
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_RECEIVE_HEADER;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_RECEIVE_HEADER)
      {
         //Receive HTTP response header
         error = httpClientReadHeader(&context->httpClientContext);

         //Check status code
         if(!error)
         {
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_PARSE_HEADER;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_PARSE_HEADER)
      {
         //Retrieve HTTP status code
         context->statusCode = httpClientGetStatus(&context->httpClientContext);

         //Flush the receive buffer
         context->bufferLen = 0;
         context->bufferPos = 0;

         //Update ACME-DNS client state
         context->state = ACME_DNS_CLIENT_STATE_RECEIVE_BODY;
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_RECEIVE_BODY)
      {
         //Receive HTTP response body
         if(context->bufferLen < ACME_DNS_CLIENT_BUFFER_SIZE)
         {
            //Receive more data
            error = httpClientReadBody(&context->httpClientContext,
               context->buffer + context->bufferLen,
               ACME_DNS_CLIENT_BUFFER_SIZE - context->bufferLen, &n, 0);

            //Check status code
            if(error == NO_ERROR)
            {
               //Advance data pointer
               context->bufferLen += n;
            }
            else if(error == ERROR_END_OF_STREAM)
            {
               //The end of the response body has been reached
               error = NO_ERROR;

               //Update ACME-DNS client state
               context->state = ACME_DNS_CLIENT_STATE_CLOSE_BODY;
            }
            else
            {
               //Just for sanity
            }
         }
         else
         {
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_CLOSE_BODY;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_CLOSE_BODY)
      {
         //Close HTTP response body
         error = httpClientCloseBody(&context->httpClientContext);

         //Check status code
         if(!error)
         {
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_PARSE_BODY;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_PARSE_BODY)
      {
         //Properly terminate the body with a NULL character
         context->buffer[context->bufferLen] = '\0';

         //Debug message
         TRACE_DEBUG("HTTP response body (%" PRIuSIZE " bytes):\r\n", context->bufferLen);
         TRACE_DEBUG("%s\r\n\r\n", context->buffer);

         //Parse the body of the HTTP response
         error = acmeDnsClientParseRegisterResponse(context);

         //The HTTP transaction is complete
         context->state = ACME_DNS_CLIENT_STATE_CONNECTED;
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
 * @brief Update endpoint
 * @param[in] context Pointer to the ACME-DNS client context
 * @param[in] txt NULL-terminated string that contains the value of the TXT record
 * @return Error code
 **/

error_t acmeDnsClientUpdate(AcmeDnsClientContext *context, const char_t *txt)
{
   error_t error;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Perform HTTP request
   while(!error)
   {
      //Check ACME-DNS client state
      if(context->state == ACME_DNS_CLIENT_STATE_CONNECTED)
      {
         //Format the POST request (update endpoint)
         error = acmeDnsClientFormatUpdateRequest(context, txt);

         //Check status code
         if(!error)
         {
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_SEND_HEADER;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_SEND_HEADER)
      {
         //Send HTTP request header
         error = httpClientWriteHeader(&context->httpClientContext);

         //Check status code
         if(!error)
         {
            //Debug message
            TRACE_DEBUG("HTTP request body (%" PRIuSIZE " bytes):\r\n", context->bufferLen);
            TRACE_DEBUG("%s\r\n\r\n", context->buffer);

            //Point to the first byte of the body
            context->bufferPos = 0;

            //Send HTTP request body
            context->state = ACME_DNS_CLIENT_STATE_SEND_BODY;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_SEND_BODY)
      {
         //Send HTTP request body
         if(context->bufferPos < context->bufferLen)
         {
            //Send more data
            error = httpClientWriteBody(&context->httpClientContext,
               context->buffer + context->bufferPos,
               context->bufferLen - context->bufferPos, &n, 0);

            //Check status code
            if(!error)
            {
               //Advance data pointer
               context->bufferPos += n;
            }
         }
         else
         {
            //Update HTTP request state
            context->state = ACME_DNS_CLIENT_STATE_RECEIVE_HEADER;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_RECEIVE_HEADER)
      {
         //Receive HTTP response header
         error = httpClientReadHeader(&context->httpClientContext);

         //Check status code
         if(!error)
         {
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_PARSE_HEADER;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_PARSE_HEADER)
      {
         //Retrieve HTTP status code
         context->statusCode = httpClientGetStatus(&context->httpClientContext);

         //Flush the receive buffer
         context->bufferLen = 0;
         context->bufferPos = 0;

         //Update ACME-DNS client state
         context->state = ACME_DNS_CLIENT_STATE_RECEIVE_BODY;
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_RECEIVE_BODY)
      {
         //Receive HTTP response body
         if(context->bufferLen < ACME_DNS_CLIENT_BUFFER_SIZE)
         {
            //Receive more data
            error = httpClientReadBody(&context->httpClientContext,
               context->buffer + context->bufferLen,
               ACME_DNS_CLIENT_BUFFER_SIZE - context->bufferLen, &n, 0);

            //Check status code
            if(error == NO_ERROR)
            {
               //Advance data pointer
               context->bufferLen += n;
            }
            else if(error == ERROR_END_OF_STREAM)
            {
               //The end of the response body has been reached
               error = NO_ERROR;

               //Update ACME-DNS client state
               context->state = ACME_DNS_CLIENT_STATE_CLOSE_BODY;
            }
            else
            {
               //Just for sanity
            }
         }
         else
         {
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_CLOSE_BODY;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_CLOSE_BODY)
      {
         //Close HTTP response body
         error = httpClientCloseBody(&context->httpClientContext);

         //Check status code
         if(!error)
         {
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_PARSE_BODY;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_PARSE_BODY)
      {
         //Properly terminate the body with a NULL character
         context->buffer[context->bufferLen] = '\0';

         //Debug message
         TRACE_DEBUG("HTTP response body (%" PRIuSIZE " bytes):\r\n", context->bufferLen);
         TRACE_DEBUG("%s\r\n\r\n", context->buffer);

         //Parse the body of the HTTP response
         error = acmeDnsClientParseUpdateResponse(context);

         //The HTTP transaction is complete
         context->state = ACME_DNS_CLIENT_STATE_CONNECTED;
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
 * @brief Gracefully disconnect from the ACME-DNS server
 * @param[in] context Pointer to the ACME-DNS client context
 * @return Error code
 **/

error_t acmeDnsClientDisconnect(AcmeDnsClientContext *context)
{
   error_t error;

   //Make sure the ACME-DNS client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Gracefully disconnect from the ACME-DNS server
   while(!error)
   {
      //Check ACME-DNS client state
      if(context->state == ACME_DNS_CLIENT_STATE_CONNECTED)
      {
         //Gracefully shutdown HTTP connection
         context->state = ACME_DNS_CLIENT_STATE_DISCONNECTING;
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_DISCONNECTING)
      {
         //Gracefully shutdown HTTP connection
         error = httpClientDisconnect(&context->httpClientContext);

         //Check status code
         if(error == NO_ERROR)
         {
            //Close HTTP connection
            httpClientClose(&context->httpClientContext);
            //Update ACME-DNS client state
            context->state = ACME_DNS_CLIENT_STATE_DISCONNECTED;
         }
      }
      else if(context->state == ACME_DNS_CLIENT_STATE_DISCONNECTED)
      {
         //The client is disconnected from the ACME-DNS server
         break;
      }
      else
      {
         //Invalid state
         error = ERROR_WRONG_STATE;
      }
   }

   //Failed to gracefully disconnect from the ACME-DNS server?
   if(error != NO_ERROR && error != ERROR_WOULD_BLOCK)
   {
      //Close HTTP connection
      httpClientClose(&context->httpClientContext);
      //Update ACME-DNS client state
      context->state = ACME_DNS_CLIENT_STATE_DISCONNECTED;
   }

   //Return status code
   return error;
}


/**
 * @brief Close the connection with the ACME-DNS server
 * @param[in] context Pointer to the ACME-DNS client context
 * @return Error code
 **/

error_t acmeDnsClientClose(AcmeDnsClientContext *context)
{
   //Make sure the ACME-DNS client context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Close HTTP connection
   httpClientClose(&context->httpClientContext);
   //Update ACME-DNS client state
   context->state = ACME_DNS_CLIENT_STATE_DISCONNECTED;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Release ACME-DNS client context
 * @param[in] context Pointer to the ACME-DNS client context
 **/

void acmeDnsClientDeinit(AcmeDnsClientContext *context)
{
   //Make sure the ACME-DNS client context is valid
   if(context != NULL)
   {
      //Release HTTP client context
      httpClientDeinit(&context->httpClientContext);

      //Clear ACME-DNS client context
      osMemset(context, 0, sizeof(AcmeDnsClientContext));
   }
}

#endif
