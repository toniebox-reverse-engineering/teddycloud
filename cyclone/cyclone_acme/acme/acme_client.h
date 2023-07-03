/**
 * @file acme_client.h
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

#ifndef _ACME_CLIENT_H
#define _ACME_CLIENT_H

//Dependencies
#include "acme_config.h"
#include "core/net.h"
#include "http/http_client.h"
#include "tls.h"
#include "pkix/x509_common.h"


/*
 * CycloneACME Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneACME Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneACME Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneACME Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#ifndef GPL_LICENSE_TERMS_ACCEPTED
   #error Before compiling CycloneACME Open, you must accept the terms of the GPL license
#endif

//Version string
#define CYCLONE_ACME_VERSION_STRING "2.2.0"
//Major version
#define CYCLONE_ACME_MAJOR_VERSION 2
//Minor version
#define CYCLONE_ACME_MINOR_VERSION 2
//Revision number
#define CYCLONE_ACME_REV_NUMBER 0

//ACME client support
#ifndef ACME_CLIENT_SUPPORT
   #define ACME_CLIENT_SUPPORT ENABLED
#elif (ACME_CLIENT_SUPPORT != ENABLED && ACME_CLIENT_SUPPORT != DISABLED)
   #error ACME_CLIENT_SUPPORT parameter is not valid
#endif

//HTTP challenge support
#ifndef ACME_CLIENT_HTTP_CHALLENGE_SUPPORT
   #define ACME_CLIENT_HTTP_CHALLENGE_SUPPORT ENABLED
#elif (ACME_CLIENT_HTTP_CHALLENGE_SUPPORT != ENABLED && \
   ACME_CLIENT_HTTP_CHALLENGE_SUPPORT != DISABLED)
   #error ACME_CLIENT_HTTP_CHALLENGE_SUPPORT is not valid
#endif

//DNS challenge support
#ifndef ACME_CLIENT_DNS_CHALLENGE_SUPPORT
   #define ACME_CLIENT_DNS_CHALLENGE_SUPPORT ENABLED
#elif (ACME_CLIENT_DNS_CHALLENGE_SUPPORT != ENABLED && \
   ACME_CLIENT_DNS_CHALLENGE_SUPPORT != DISABLED)
   #error ACME_CLIENT_DNS_CHALLENGE_SUPPORT is not valid
#endif

//TLS-ALPN challenge support
#ifndef ACME_CLIENT_TLS_ALPN_CHALLENGE_SUPPORT
   #define ACME_CLIENT_TLS_ALPN_CHALLENGE_SUPPORT DISABLED
#elif (ACME_CLIENT_TLS_ALPN_CHALLENGE_SUPPORT != ENABLED && \
   ACME_CLIENT_TLS_ALPN_CHALLENGE_SUPPORT != DISABLED)
   #error ACME_CLIENT_TLS_ALPN_CHALLENGE_SUPPORT is not valid
#endif

//RSA key support
#ifndef ACME_CLIENT_RSA_SUPPORT
   #define ACME_CLIENT_RSA_SUPPORT ENABLED
#elif (ACME_CLIENT_RSA_SUPPORT != ENABLED && ACME_CLIENT_RSA_SUPPORT != DISABLED)
   #error ACME_CLIENT_RSA_SUPPORT parameter is not valid
#endif

//ECDSA key support
#ifndef ACME_CLIENT_ECDSA_SUPPORT
   #define ACME_CLIENT_ECDSA_SUPPORT ENABLED
#elif (ACME_CLIENT_ECDSA_SUPPORT != ENABLED && ACME_CLIENT_ECDSA_SUPPORT != DISABLED)
   #error ACME_CLIENT_ECDSA_SUPPORT parameter is not valid
#endif

//Ed25519 key support
#ifndef ACME_CLIENT_ED25519_SUPPORT
   #define ACME_CLIENT_ED25519_SUPPORT DISABLED
#elif (ACME_CLIENT_ED25519_SUPPORT != ENABLED && ACME_CLIENT_ED25519_SUPPORT != DISABLED)
   #error ACME_CLIENT_ED25519_SUPPORT parameter is not valid
#endif

//Ed448 key support
#ifndef ACME_CLIENT_ED448_SUPPORT
   #define ACME_CLIENT_ED448_SUPPORT DISABLED
#elif (ACME_CLIENT_ED448_SUPPORT != ENABLED && ACME_CLIENT_ED448_SUPPORT != DISABLED)
   #error ACME_CLIENT_ED448_SUPPORT parameter is not valid
#endif

//Default timeout
#ifndef ACME_CLIENT_DEFAULT_TIMEOUT
   #define ACME_CLIENT_DEFAULT_TIMEOUT 20000
#elif (ACME_CLIENT_DEFAULT_TIMEOUT < 1000)
   #error ACME_CLIENT_DEFAULT_TIMEOUT parameter is not valid
#endif

//Maximum number of contacts per account
#ifndef ACME_CLIENT_MAX_CONTACTS
   #define ACME_CLIENT_MAX_CONTACTS 4
#elif (ACME_CLIENT_MAX_CONTACTS < 1)
   #error ACME_CLIENT_MAX_CONTACTS parameter is not valid
#endif

//Maximum number of domains per certificate order
#ifndef ACME_CLIENT_MAX_DOMAINS
   #define ACME_CLIENT_MAX_DOMAINS 2
#elif (ACME_CLIENT_MAX_DOMAINS < 1)
   #error ACME_CLIENT_MAX_DOMAINS parameter is not valid
#endif

//Size of the buffer for input/output operations
#ifndef ACME_CLIENT_BUFFER_SIZE
   #define ACME_CLIENT_BUFFER_SIZE 6144
#elif (ACME_CLIENT_BUFFER_SIZE < 2048)
   #error ACME_CLIENT_BUFFER_SIZE parameter is not valid
#endif

//Maximum length of domain names
#ifndef ACME_CLIENT_MAX_NAME_LEN
   #define ACME_CLIENT_MAX_NAME_LEN 64
#elif (ACME_CLIENT_MAX_NAME_LEN < 1)
   #error ACME_CLIENT_MAX_NAME_LEN parameter is not valid
#endif

//Maximum length of URIs
#ifndef ACME_CLIENT_MAX_URI_LEN
   #define ACME_CLIENT_MAX_URI_LEN 32
#elif (ACME_CLIENT_MAX_URI_LEN < 1)
   #error ACME_CLIENT_MAX_URI_LEN parameter is not valid
#endif

//Maximum length of URLs
#ifndef ACME_CLIENT_MAX_URL_LEN
   #define ACME_CLIENT_MAX_URL_LEN 128
#elif (ACME_CLIENT_MAX_URL_LEN < 1)
   #error ACME_CLIENT_MAX_URL_LEN parameter is not valid
#endif

//Maximum length of URNs
#ifndef ACME_CLIENT_MAX_URN_LEN
   #define ACME_CLIENT_MAX_URN_LEN 64
#elif (ACME_CLIENT_MAX_URN_LEN < 1)
   #error ACME_CLIENT_MAX_URN_LEN parameter is not valid
#endif

//Maximum length of nonces
#ifndef ACME_CLIENT_MAX_NONCE_LEN
   #define ACME_CLIENT_MAX_NONCE_LEN 64
#elif (ACME_CLIENT_MAX_NONCE_LEN < 1)
   #error ACME_CLIENT_MAX_NONCE_LEN parameter is not valid
#endif

//Maximum length of tokens
#ifndef ACME_CLIENT_MAX_TOKEN_LEN
   #define ACME_CLIENT_MAX_TOKEN_LEN 64
#elif (ACME_CLIENT_MAX_TOKEN_LEN < 1)
   #error ACME_CLIENT_MAX_TOKEN_LEN parameter is not valid
#endif

//Maximum length of key authorizations
#ifndef ACME_CLIENT_MAX_KEY_AUTH_LEN
   #define ACME_CLIENT_MAX_KEY_AUTH_LEN 128
#elif (ACME_CLIENT_MAX_KEY_AUTH_LEN < 1)
   #error ACME_CLIENT_MAX_KEY_AUTH_LEN parameter is not valid
#endif

//Maximum length of TLS-ALPN certificates
#ifndef ACME_CLIENT_MAX_TLS_ALPN_CERT_LEN
   #define ACME_CLIENT_MAX_TLS_ALPN_CERT_LEN 1536
#elif (ACME_CLIENT_MAX_TLS_ALPN_CERT_LEN < 1)
   #error ACME_CLIENT_MAX_TLS_ALPN_CERT_LEN parameter is not valid
#endif

//Maximum length of media types
#ifndef ACME_CLIENT_MAX_CONTENT_TYPE_LEN
   #define ACME_CLIENT_MAX_CONTENT_TYPE_LEN 40
#elif (ACME_CLIENT_MAX_CONTENT_TYPE_LEN < 1)
   #error ACME_CLIENT_MAX_CONTENT_TYPE_LEN parameter is not valid
#endif

//Maximum number of bad nonce errors
#ifndef ACME_CLIENT_MAX_BAD_NONCE_ERRORS
   #define ACME_CLIENT_MAX_BAD_NONCE_ERRORS 5
#elif (ACME_CLIENT_MAX_BAD_NONCE_ERRORS < 0)
   #error ACME_CLIENT_MAX_BAD_NONCE_ERRORS parameter is not valid
#endif

//Forward declaration of AcmeClientContext structure
struct _AcmeClientContext;
#define AcmeClientContext struct _AcmeClientContext

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief ACME client states
 **/

typedef enum
{
   ACME_CLIENT_STATE_DISCONNECTED       = 0,
   ACME_CLIENT_STATE_CONNECTING         = 1,
   ACME_CLIENT_STATE_CONNECTED          = 2,
   ACME_CLIENT_STATE_DIRECTORY          = 3,
   ACME_CLIENT_STATE_NEW_NONCE          = 4,
   ACME_CLIENT_STATE_NEW_ACCOUNT        = 5,
   ACME_CLIENT_STATE_UPDATE_ACCOUNT     = 6,
   ACME_CLIENT_STATE_CHANGE_KEY         = 7,
   ACME_CLIENT_STATE_DEACTIVATE_ACCOUNT = 8,
   ACME_CLIENT_STATE_NEW_ORDER          = 9,
   ACME_CLIENT_STATE_AUTHORIZATION      = 10,
   ACME_CLIENT_STATE_CHALLENGE_READY    = 11,
   ACME_CLIENT_STATE_POLL_STATUS_1      = 12,
   ACME_CLIENT_STATE_FINALIZE           = 13,
   ACME_CLIENT_STATE_POLL_STATUS_2      = 14,
   ACME_CLIENT_STATE_DOWNLOAD_CERT      = 15,
   ACME_CLIENT_STATE_REVOKE_CERT        = 16,
   ACME_CLIENT_STATE_DISCONNECTING      = 17
} AcmeClientState;


/**
 * @brief HTTP request states
 */

typedef enum
{
   ACME_REQ_STATE_INIT           = 0,
   ACME_REQ_STATE_FORMAT_HEADER  = 1,
   ACME_REQ_STATE_SEND_HEADER    = 2,
   ACME_REQ_STATE_FORMAT_BODY    = 3,
   ACME_REQ_STATE_SEND_BODY      = 4,
   ACME_REQ_STATE_RECEIVE_HEADER = 5,
   ACME_REQ_STATE_PARSE_HEADER   = 6,
   ACME_REQ_STATE_RECEIVE_BODY   = 7,
   ACME_REQ_STATE_PARSE_BODY     = 8,
   ACME_REQ_STATE_CLOSE_BODY     = 9,
} AcmeRequestState;


/**
 * @brief Account status
 **/

typedef enum
{
   ACME_ACCOUNT_STATUS_NONE        = 0,
   ACME_ACCOUNT_STATUS_VALID       = 1,
   ACME_ACCOUNT_STATUS_DEACTIVATED = 2,
   ACME_ACCOUNT_STATUS_REVOKED     = 3
} AcmeAccountStatus;


/**
 * @brief Order status
 **/

typedef enum
{
   ACME_ORDER_STATUS_NONE       = 0,
   ACME_ORDER_STATUS_PENDING    = 1,
   ACME_ORDER_STATUS_READY      = 2,
   ACME_ORDER_STATUS_PROCESSING = 3,
   ACME_ORDER_STATUS_VALID      = 4,
   ACME_ORDER_STATUS_INVALID    = 5
} AcmeOrderStatus;


/**
 * @brief Authorization status
 **/

typedef enum
{
   ACME_AUTH_STATUS_NONE        = 0,
   ACME_AUTH_STATUS_PENDING     = 1,
   ACME_AUTH_STATUS_VALID       = 2,
   ACME_AUTH_STATUS_INVALID     = 3,
   ACME_AUTH_STATUS_EXPIRED     = 4,
   ACME_AUTH_STATUS_DEACTIVATED = 5,
   ACME_AUTH_STATUS_REVOKED     = 6
} AcmeAuthStatus;


/**
 * @brief Challenge status
 **/

typedef enum
{
   ACME_CHALLENGE_STATUS_NONE       = 0,
   ACME_CHALLENGE_STATUS_PENDING    = 1,
   ACME_CHALLENGE_STATUS_PROCESSING = 2,
   ACME_CHALLENGE_STATUS_VALID      = 3,
   ACME_CHALLENGE_STATUS_INVALID    = 4
} AcmeChallengeStatus;


/**
 * @brief Challenge types
 **/

typedef enum
{
   ACME_CHALLENGE_TYPE_NONE        = 0,
   ACME_CHALLENGE_TYPE_HTTP_01     = 1,
   ACME_CHALLENGE_TYPE_DNS_01      = 2,
   ACME_CHALLENGE_TYPE_TLS_ALPN_01 = 3
} AcmeChallengeType;


/**
 * @brief Revocation reason codes
 **/

typedef enum
{
   ACME_REASON_UNSPECIFIED            = 0,
   ACME_REASON_KEY_COMPROMISE         = 1,
   ACME_REASON_CA_COMPROMISE          = 2,
   ACME_REASON_AFFILIATION_CHANGED    = 3,
   ACME_REASON_SUPERSEDED             = 4,
   ACME_REASON_CESSATION_OF_OPERATION = 5,
   ACME_REASON_CERTIFICATE_HOLD       = 6,
   ACME_REMOVE_FROM_CRL               = 8,
   ACME_REASON_PRIVILEGE_WITHDRAWN    = 9,
   ACME_REASON_AA_COMPROMISE          = 10
} AcmeReasonCode;


/**
 * @brief TLS initialization callback function
 **/

typedef error_t (*AcmeClientTlsInitCallback)(HttpClientContext *context,
   TlsContext *tlsContext);


/**
 * @brief CSR generation callback function
 **/

typedef error_t (*AcmeClientCsrCallback)(AcmeClientContext *context,
   uint8_t *buffer, size_t size, size_t *length);


/**
 * @brief Public/private key pair
 **/

typedef struct
{
   X509KeyType type;
   char_t alg[8];
   char_t crv[8];
   const void *publicKey;
   const void *privateKey;
#if (ACME_CLIENT_RSA_SUPPORT == ENABLED)
   RsaPublicKey rsaPublicKey;
   RsaPrivateKey rsaPrivateKey;
#endif
#if (ACME_CLIENT_ECDSA_SUPPORT == ENABLED)
   EcDomainParameters ecParams;
   EcPublicKey ecPublicKey;
   EcPrivateKey ecPrivateKey;
#endif
#if (ACME_CLIENT_ED25519_SUPPORT == ENABLED || \
   ACME_CLIENT_ED448_SUPPORT == ENABLED)
   EddsaPublicKey eddsaPublicKey;
   EddsaPrivateKey eddsaPrivateKey;
#endif
} AcmeKeyPair;


/**
 * @brief ACME account creation parameters
 **/

typedef struct
{
   uint_t numContacts;                               ///<Number of contact URLs
   const char_t *contacts[ACME_CLIENT_MAX_CONTACTS]; ///<Array of URLs that the server can use to contact the client
   bool_t termsOfServiceAgreed;                      ///<Indicates the client's agreement with the terms of service
   const char_t *publicKey;                          ///<Account public key
   size_t publicKeyLen;                              ///<Length of the account public key, in bytes
   const char_t *privateKey;                         ///<Account private key
   size_t privateKeyLen;                             ///<Length of the account private key, in bytes
   const char_t *status;                             ///<Status of the account
} AcmeAccountParams;


/**
 * @brief Domain parameters
 **/

typedef struct
{
   const char_t *name;              ///<Domain name
   AcmeChallengeType challengeType; ///<Challenge type
} AcmeDomainParams;


/**
 * @brief Certificate order parameters
 **/

typedef struct
{
   uint_t numDomains;                                 ///<Number of domain names
   AcmeDomainParams domains[ACME_CLIENT_MAX_DOMAINS]; ///<Domain names that the client wishes to submit an order for
   DateTime notBefore;                                ///<The requested value of the notBefore field in the certificate
   DateTime notAfter;                                 ///<The requested value of the notAfter field in the certificate
   const char_t *publicKey;                           ///<Certificate public key
   size_t publicKeyLen;                               ///<Length of the certificate public key, in bytes
   const char_t *privateKey;                          ///<Certificate private key
   size_t privateKeyLen;                              ///<Length of the certificate private key, in bytes
} AcmeOrderParams;


/**
 * @brief Directory object
 **/

typedef struct
{
   char_t newNonce[ACME_CLIENT_MAX_URL_LEN + 1];   ///<New nonce
   char_t newAccount[ACME_CLIENT_MAX_URL_LEN + 1]; ///<New account
   char_t newOrder[ACME_CLIENT_MAX_URL_LEN + 1];   ///<New order
   char_t revokeCert[ACME_CLIENT_MAX_URL_LEN + 1]; ///<Revoke certificate
   char_t keyChange[ACME_CLIENT_MAX_URL_LEN + 1];  ///<Key change
} AcmeDirectory;


/**
 * @brief Account object
 **/

typedef struct
{
   AcmeAccountStatus status;                ///<Status of the account
   char_t url[ACME_CLIENT_MAX_URL_LEN + 1]; ///<Account URL
} AcmeAccount;


/**
 * @brief Identifier object
 **/

typedef struct
{
   char_t value[ACME_CLIENT_MAX_NAME_LEN + 1]; ///<Domain name
   AcmeChallengeType challengeType;            ///<Challenge type
} AcmeIdentifier;


/**
 * @brief Order object
 **/

typedef struct
{
   AcmeOrderStatus status;                          ///<Status of the order
   char_t url[ACME_CLIENT_MAX_URL_LEN + 1];         ///<Order URL
   char_t finalize[ACME_CLIENT_MAX_URL_LEN + 1];    ///<Finalize URL
   char_t certificate[ACME_CLIENT_MAX_URL_LEN + 1]; ///<Certificate URL
} AcmeOrder;


/**
 * @brief Authorization object
 **/

typedef struct
{
   AcmeAuthStatus status;                   ///<Status of the authorization
   char_t url[ACME_CLIENT_MAX_URL_LEN + 1]; ///<Authorization URL
   bool_t wildcard;                         ///<Wildcard domain name
} AcmeAuthorization;


/**
 * @brief Challenge object
 **/

typedef struct
{
   AcmeChallengeType type;                             ///<Challenge type
   AcmeChallengeStatus status;                         ///<Status of the challenge
   char_t identifier[ACME_CLIENT_MAX_NAME_LEN + 1];    ///<Domain name
   bool_t wildcard;                                    ///<Wildcard domain name
   char_t url[ACME_CLIENT_MAX_URL_LEN + 1];            ///<Challenge URL
   char_t token[ACME_CLIENT_MAX_TOKEN_LEN + 1];        ///<Token value
   char_t keyAuth[ACME_CLIENT_MAX_KEY_AUTH_LEN + 1];   ///<Key authorization
#if (ACME_CLIENT_TLS_ALPN_CHALLENGE_SUPPORT == ENABLED)
   char_t cert[ACME_CLIENT_MAX_TLS_ALPN_CERT_LEN + 1]; ///<TLS-ALPN certificate
#endif
} AcmeChallenge;


/**
 * @brief ACME client context
 **/

struct _AcmeClientContext
{
   AcmeClientState state;                                     ///<ACME client state
   AcmeRequestState requestState;                             ///<HTTP request state
   NetInterface *interface;                                   ///<Underlying network interface
   systime_t timeout;                                         ///<Timeout value
   const PrngAlgo *prngAlgo;                                  ///<Pseudo-random number generator to be used
   void *prngContext;                                         ///<Pseudo-random number generator context
   HttpClientContext httpClientContext;                       ///<HTTP client context
   AcmeClientTlsInitCallback tlsInitCallback;                 ///<TLS initialization callback function
   AcmeClientCsrCallback csrCallback;                         ///<CSR generation callback function
   AcmeKeyPair accountKey;                                    ///<ACME account key
   AcmeKeyPair certKey;                                       ///<Certificate key
   char_t serverName[ACME_CLIENT_MAX_NAME_LEN + 1];           ///<Host name of the ACME server
   uint16_t serverPort;                                       ///<TCP port number
   char_t directoryUri[ACME_CLIENT_MAX_URI_LEN + 1];          ///<Directory URI
   char_t nonce[ACME_CLIENT_MAX_NONCE_LEN + 1];               ///<Value of the Replay-Nonce header field
   AcmeDirectory directory;                                   ///<Directory object
   AcmeAccount account;                                       ///<Account object
   AcmeOrder order;                                           ///<Order object
   uint_t numIdentifiers;                                     ///<Number of identifiers
   AcmeIdentifier identifiers[ACME_CLIENT_MAX_DOMAINS];       ///<Array of identifiers objects
   uint_t numAuthorizations;                                  ///<Number of authorizations
   AcmeAuthorization authorizations[ACME_CLIENT_MAX_DOMAINS]; ///<Array of authorization objects
   uint_t numChallenges;                                      ///<Number of challenges
   uint_t index;                                              ///<Current index
   AcmeChallenge challenges[ACME_CLIENT_MAX_DOMAINS];         ///<Array of challenge objects
   char_t buffer[ACME_CLIENT_BUFFER_SIZE + 1];                ///<Memory buffer for input/output operations
   size_t bufferLen;                                          ///<Length of the buffer, in bytes
   size_t bufferPos;                                          ///<Current position in the buffer
   uint_t statusCode;                                         ///<HTTP status code
   char_t contentType[ACME_CLIENT_MAX_CONTENT_TYPE_LEN + 1];  ///<Content type of the response
   char_t errorType[ACME_CLIENT_MAX_URN_LEN + 1];             ///<ACME error type
   uint_t badNonceErrors;                                     ///<Number of consecutive bad nonce errors
};


//ACME client related functions
error_t acmeClientInit(AcmeClientContext *context);

error_t acmeClientRegisterTlsInitCallback(AcmeClientContext *context,
   AcmeClientTlsInitCallback callback);

error_t acmeClientRegisterCsrCallback(AcmeClientContext *context,
   AcmeClientCsrCallback callback);

error_t acmeClientSetPrng(AcmeClientContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

error_t acmeClientSetTimeout(AcmeClientContext *context, systime_t timeout);
error_t acmeClientSetHost(AcmeClientContext *context, const char_t *host);

error_t acmeClientSetDirectoryUri(AcmeClientContext *context,
   const char_t *directoryUri);

error_t acmeClientBindToInterface(AcmeClientContext *context,
   NetInterface *interface);

error_t acmeClientConnect(AcmeClientContext *context,
   const IpAddr *serverIpAddr, uint16_t serverPort);

error_t acmeClientSetAccountKey(AcmeClientContext *context,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen);

error_t acmeClientCreateAccount(AcmeClientContext *context,
   const AcmeAccountParams *params);

error_t acmeClientUpdateAccount(AcmeClientContext *context,
   const AcmeAccountParams *params);

error_t acmeClientChangeAccountKey(AcmeClientContext *context,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen);

error_t acmeClientDeactivateAccount(AcmeClientContext *context);

error_t acmeClientCreateOrder(AcmeClientContext *context,
   const AcmeOrderParams *params);

const char_t *acmeClientGetHttpKeyAuthorization(AcmeClientContext *context,
   const char_t *token);

const char_t *acmeClientGetDnsKeyAuthorization(AcmeClientContext *context,
   const char_t *identifier);

const char_t *acmeClientGetTlsAlpnCertificate(AcmeClientContext *context,
   const char_t *identifier);

error_t acmeClientPollOrderStatus(AcmeClientContext *context,
   AcmeOrderStatus *orderStatus);

error_t acmeClientDownloadCertificate(AcmeClientContext *context,
   char_t *buffer, size_t size, size_t *length);

error_t acmeClientRevokeCertificate(AcmeClientContext *context,
   const char_t *cert, size_t certLen, const char_t *privateKey,
   size_t privateKeyLen, AcmeReasonCode reason);

error_t acmeClientDisconnect(AcmeClientContext *context);
error_t acmeClientClose(AcmeClientContext *context);

void acmeClientDeinit(AcmeClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
