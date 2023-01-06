/**
 * @file acme_dns_client.h
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

#ifndef _ACME_DNS_CLIENT_H
#define _ACME_DNS_CLIENT_H

//Dependencies
#include "acme_config.h"
#include "core/net.h"
#include "http/http_client.h"

//ACME-DNS client support
#ifndef ACME_DNS_CLIENT_SUPPORT
   #define ACME_DNS_CLIENT_SUPPORT ENABLED
#elif (ACME_DNS_CLIENT_SUPPORT != ENABLED && ACME_DNS_CLIENT_SUPPORT != DISABLED)
   #error ACME_DNS_CLIENT_SUPPORT parameter is not valid
#endif

//ACME-DNS over TLS
#ifndef ACME_DNS_CLIENT_TLS_SUPPORT
   #define ACME_DNS_CLIENT_TLS_SUPPORT DISABLED
#elif (ACME_DNS_CLIENT_TLS_SUPPORT != ENABLED && ACME_DNS_CLIENT_TLS_SUPPORT != DISABLED)
   #error ACME_DNS_CLIENT_TLS_SUPPORT parameter is not valid
#endif

//Default timeout
#ifndef ACME_DNS_CLIENT_DEFAULT_TIMEOUT
   #define ACME_DNS_CLIENT_DEFAULT_TIMEOUT 20000
#elif (ACME_DNS_CLIENT_DEFAULT_TIMEOUT < 1000)
   #error ACME_DNS_CLIENT_DEFAULT_TIMEOUT parameter is not valid
#endif

//Size of the buffer for input/output operations
#ifndef ACME_DNS_CLIENT_BUFFER_SIZE
   #define ACME_DNS_CLIENT_BUFFER_SIZE 512
#elif (ACME_DNS_CLIENT_BUFFER_SIZE < 128)
   #error ACME_DNS_CLIENT_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of host name
#ifndef ACME_DNS_CLIENT_MAX_HOST_LEN
   #define ACME_DNS_CLIENT_MAX_HOST_LEN 64
#elif (ACME_DNS_CLIENT_MAX_HOST_LEN < 1)
   #error ACME_DNS_CLIENT_MAX_HOST_LEN parameter is not valid
#endif

//Maximum length of user name
#ifndef ACME_DNS_CLIENT_MAX_USERNAME_LEN
   #define ACME_DNS_CLIENT_MAX_USERNAME_LEN 64
#elif (ACME_DNS_CLIENT_MAX_USERNAME_LEN < 1)
   #error ACME_DNS_CLIENT_MAX_USERNAME_LEN parameter is not valid
#endif

//Maximum length of password
#ifndef ACME_DNS_CLIENT_MAX_PASSWORD_LEN
   #define ACME_DNS_CLIENT_MAX_PASSWORD_LEN 64
#elif (ACME_DNS_CLIENT_MAX_PASSWORD_LEN < 1)
   #error ACME_DNS_CLIENT_MAX_PASSWORD_LEN parameter is not valid
#endif

//Maximum length of sub domain
#ifndef ACME_DNS_CLIENT_MAX_SUB_DOMAIN_LEN
   #define ACME_DNS_CLIENT_MAX_SUB_DOMAIN_LEN 64
#elif (ACME_DNS_CLIENT_MAX_SUB_DOMAIN_LEN < 1)
   #error ACME_DNS_CLIENT_MAX_SUB_DOMAIN_LEN parameter is not valid
#endif

//Maximum length of full domain
#ifndef ACME_DNS_CLIENT_MAX_FULL_DOMAIN_LEN
   #define ACME_DNS_CLIENT_MAX_FULL_DOMAIN_LEN 128
#elif (ACME_DNS_CLIENT_MAX_FULL_DOMAIN_LEN < 1)
   #error ACME_DNS_CLIENT_MAX_FULL_DOMAIN_LEN parameter is not valid
#endif

//TXT record length
#define ACME_DNS_TXT_RECORD_LEN 43

//TLS supported?
#if (ACME_DNS_CLIENT_TLS_SUPPORT == ENABLED)
   #include "core/crypto.h"
   #include "tls.h"
#endif

//Forward declaration of AcmeDnsClientContext structure
struct _AcmeDnsClientContext;
#define AcmeDnsClientContext struct _AcmeDnsClientContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ACME-DNS client states
 **/

typedef enum
{
   ACME_DNS_CLIENT_STATE_DISCONNECTED   = 0,
   ACME_DNS_CLIENT_STATE_CONNECTING     = 1,
   ACME_DNS_CLIENT_STATE_CONNECTED      = 2,
   ACME_DNS_CLIENT_STATE_SEND_HEADER    = 3,
   ACME_DNS_CLIENT_STATE_SEND_BODY      = 4,
   ACME_DNS_CLIENT_STATE_RECEIVE_HEADER = 5,
   ACME_DNS_CLIENT_STATE_PARSE_HEADER   = 6,
   ACME_DNS_CLIENT_STATE_RECEIVE_BODY   = 7,
   ACME_DNS_CLIENT_STATE_PARSE_BODY     = 8,
   ACME_DNS_CLIENT_STATE_CLOSE_BODY     = 9,
   ACME_DNS_CLIENT_STATE_DISCONNECTING  = 10
} AcmeDnsClientState;


//TLS supported?
#if (ACME_DNS_CLIENT_TLS_SUPPORT == ENABLED)

/**
 * @brief TLS initialization callback function
 **/

typedef error_t (*AcmeDnsClientTlsInitCallback)(HttpClientContext *context,
   TlsContext *tlsContext);

#endif



/**
 * @brief ACME-DNS client context
 **/

struct _AcmeDnsClientContext
{
   AcmeDnsClientState state;                                   ///<ACME-DNS client state
   NetInterface *interface;                                    ///<Underlying network interface
   systime_t timeout;                                          ///<Timeout value
   HttpClientContext httpClientContext;                        ///<HTTP client context
#if (ACME_DNS_CLIENT_TLS_SUPPORT == ENABLED)
   AcmeDnsClientTlsInitCallback tlsInitCallback;               ///<TLS initialization callback function
#endif
   char_t serverName[ACME_DNS_CLIENT_MAX_HOST_LEN + 1];        ///<Host name of the ACME-DNS server
   uint16_t serverPort;                                        ///<TCP port number
   char_t username[ACME_DNS_CLIENT_MAX_USERNAME_LEN + 1];      ///<User name
   char_t password[ACME_DNS_CLIENT_MAX_PASSWORD_LEN + 1];      ///<Password
   char_t subDomain[ACME_DNS_CLIENT_MAX_SUB_DOMAIN_LEN + 1];   ///<Sub domain
   char_t fullDomain[ACME_DNS_CLIENT_MAX_FULL_DOMAIN_LEN + 1]; ///<Full domain
   char_t buffer[ACME_DNS_CLIENT_BUFFER_SIZE + 1];             ///<Memory buffer for input/output operations
   size_t bufferLen;                                           ///<Length of the buffer, in bytes
   size_t bufferPos;                                           ///<Current position in the buffer
   uint_t statusCode;                                          ///<HTTP status code
};


//ACME-DNS client related functions
error_t acmeDnsClientInit(AcmeDnsClientContext *context);

#if (ACME_DNS_CLIENT_TLS_SUPPORT == ENABLED)

error_t acmeDnsClientRegisterTlsInitCallback(AcmeDnsClientContext *context,
   AcmeDnsClientTlsInitCallback callback);

#endif

error_t acmeDnsClientSetTimeout(AcmeDnsClientContext *context,
   systime_t timeout);

error_t acmeDnsClientSetHost(AcmeDnsClientContext *context,
   const char_t *host);

error_t acmeDnsClientSetUsername(AcmeDnsClientContext *context,
   const char_t *username);

error_t acmeDnsClientSetPassword(AcmeDnsClientContext *context,
   const char_t *password);

error_t acmeDnsClientSetSubDomain(AcmeDnsClientContext *context,
   const char_t *subDomain);

const char_t *acmeDnsClientGetUsername(AcmeDnsClientContext *context);
const char_t *acmeDnsClientGetPassword(AcmeDnsClientContext *context);
const char_t *acmeDnsClientGetSubDomain(AcmeDnsClientContext *context);
const char_t *acmeDnsClientGetFullDomain(AcmeDnsClientContext *context);

error_t acmeDnsClientBindToInterface(AcmeDnsClientContext *context,
   NetInterface *interface);

error_t acmeDnsClientConnect(AcmeDnsClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort);

error_t acmeDnsClientRegister(AcmeDnsClientContext *context);
error_t acmeDnsClientUpdate(AcmeDnsClientContext *context, const char_t *txt);

error_t acmeDnsClientDisconnect(AcmeDnsClientContext *context);
error_t acmeDnsClientClose(AcmeDnsClientContext *context);

void acmeDnsClientDeinit(AcmeDnsClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
