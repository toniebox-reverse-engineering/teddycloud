/**
 * @file tls.c
 * @brief TLS (Transport Layer Security)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSL Open.
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
 * @section Description
 *
 * The TLS protocol provides communications security over the Internet. The
 * protocol allows client/server applications to communicate in a way that
 * is designed to prevent eavesdropping, tampering, or message forgery
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include <ctype.h>
#include "tls.h"
#include "tls_handshake.h"
#include "tls_common.h"
#include "tls_certificate.h"
#include "tls_transcript_hash.h"
#include "tls_record.h"
#include "tls_misc.h"
#include "tls13_client_misc.h"
#include "tls13_ticket.h"
#include "dtls_record.h"
#include "pkix/pem_import.h"
#include "pkix/x509_cert_parse.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief TLS context initialization
 * @return Handle referencing the fully initialized TLS context
 **/

TlsContext *tlsInit(void)
{
   TlsContext *context;

   //Allocate a memory buffer to hold the TLS context
   context = tlsAllocMem(sizeof(TlsContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Clear TLS context
      osMemset(context, 0, sizeof(TlsContext));

      //Default state
      context->state = TLS_STATE_INIT;
      //Default transport protocol
      context->transportProtocol = TLS_TRANSPORT_PROTOCOL_STREAM;
      //Default operation mode
      context->entity = TLS_CONNECTION_END_CLIENT;
      //Default client authentication mode
      context->clientAuthMode = TLS_CLIENT_AUTH_NONE;

      //Minimum and maximum versions accepted by the implementation
      context->versionMin = TLS_MIN_VERSION;
      context->versionMax = TLS_MAX_VERSION;

      //Default record layer version number
      context->version = TLS_MIN_VERSION;
      context->encryptionEngine.version = TLS_MIN_VERSION;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //Select default named group
      if(tls13IsGroupSupported(context, TLS_GROUP_ECDH_X25519))
      {
         context->preferredGroup = TLS_GROUP_ECDH_X25519;
      }
      else if(tls13IsGroupSupported(context, TLS_GROUP_SECP256R1))
      {
         context->preferredGroup = TLS_GROUP_SECP256R1;
      }
      else
      {
         context->preferredGroup = TLS_GROUP_NONE;
      }
#endif

#if (DTLS_SUPPORT == ENABLED)
      //Default PMTU
      context->pmtu = DTLS_DEFAULT_PMTU;
      //Default timeout
      context->timeout = INFINITE_DELAY;
#endif

#if (DTLS_SUPPORT == ENABLED && DTLS_REPLAY_DETECTION_SUPPORT == ENABLED)
      //Anti-replay mechanism is enabled by default
      context->replayDetectionEnabled = TRUE;
#endif

#if (TLS_DH_SUPPORT == ENABLED)
      //Initialize Diffie-Hellman context
      dhInit(&context->dhContext);
#endif

#if (TLS_ECDH_SUPPORT == ENABLED)
      //Initialize ECDH context
      ecdhInit(&context->ecdhContext);
#endif

#if (TLS_RSA_SUPPORT == ENABLED)
      //Initialize peer's RSA public key
      rsaInitPublicKey(&context->peerRsaPublicKey);
#endif

#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //Initialize peer's DSA public key
      dsaInitPublicKey(&context->peerDsaPublicKey);
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_EDDSA_SIGN_SUPPORT == ENABLED)
      //Initialize peer's EC domain parameters
      ecInitDomainParameters(&context->peerEcParams);
      //Initialize peer's EC public key
      ecInitPublicKey(&context->peerEcPublicKey);
#endif

      //Maximum number of plaintext data the TX and RX buffers can hold
      context->txBufferMaxLen = TLS_MAX_RECORD_LENGTH;
      context->rxBufferMaxLen = TLS_MAX_RECORD_LENGTH;

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
      //Maximum fragment length
      context->maxFragLen = TLS_MAX_RECORD_LENGTH;
#endif
#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
      //Maximum record size the peer is willing to receive
      context->recordSizeLimit = TLS_MAX_RECORD_LENGTH;
#endif

#if (DTLS_SUPPORT == ENABLED)
      //Calculate the required size for the TX buffer
      context->txBufferSize = context->txBufferMaxLen + sizeof(DtlsRecord) +
         TLS_MAX_RECORD_OVERHEAD;

      //Calculate the required size for the RX buffer
      context->rxBufferSize = context->rxBufferMaxLen + sizeof(DtlsRecord) +
         TLS_MAX_RECORD_OVERHEAD;
#else
      //Calculate the required size for the TX buffer
      context->txBufferSize = context->txBufferMaxLen + sizeof(TlsRecord) +
         TLS_MAX_RECORD_OVERHEAD;

      //Calculate the required size for the RX buffer
      context->rxBufferSize = context->rxBufferMaxLen + sizeof(TlsRecord) +
         TLS_MAX_RECORD_OVERHEAD;
#endif
   }

   //Return a pointer to the freshly created TLS context
   return context;
}


/**
 * @brief Retrieve current state
 * @param[in] context Pointer to the TLS context
 * @return Current TLS state
 **/

TlsState tlsGetState(TlsContext *context)
{
   TlsState state;

   //Valid TLS context?
   if(context != NULL)
      state = context->state;
   else
      state = TLS_STATE_INIT;

   //Return current state
   return state;
}


/**
 * @brief Set socket send and receive callbacks
 * @param[in] context Pointer to the TLS context
 * @param[in] socketSendCallback Send callback function
 * @param[in] socketReceiveCallback Receive callback function
 * @param[in] handle Socket handle
 * @return Error code
 **/

error_t tlsSetSocketCallbacks(TlsContext *context,
   TlsSocketSendCallback socketSendCallback,
   TlsSocketReceiveCallback socketReceiveCallback, TlsSocketHandle handle)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(socketSendCallback == NULL || socketReceiveCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save send and receive callback functions
   context->socketSendCallback = socketSendCallback;
   context->socketReceiveCallback = socketReceiveCallback;

   //This socket handle will be directly passed to the callback functions
   context->socketHandle = handle;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set minimum and maximum versions permitted
 * @param[in] context Pointer to the TLS context
 * @param[in] versionMin Minimum version accepted by the TLS implementation
 * @param[in] versionMax Maximum version accepted by the TLS implementation
 * @return Error code
 **/

error_t tlsSetVersion(TlsContext *context, uint16_t versionMin,
   uint16_t versionMax)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(versionMin < TLS_MIN_VERSION || versionMax > TLS_MAX_VERSION)
      return ERROR_INVALID_PARAMETER;
   if(versionMin > versionMax)
      return ERROR_INVALID_PARAMETER;

   //Minimum version accepted by the implementation
   context->versionMin = versionMin;
   //Maximum version accepted by the implementation
   context->versionMax = versionMax;

   //Default record layer version number
   context->version = context->versionMin;
   context->encryptionEngine.version = context->versionMin;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the transport protocol to be used
 * @param[in] context Pointer to the TLS context
 * @param[in] transportProtocol Transport protocol to be used
 * @return Error code
 **/

error_t tlsSetTransportProtocol(TlsContext *context,
   TlsTransportProtocol transportProtocol)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(transportProtocol != TLS_TRANSPORT_PROTOCOL_STREAM &&
      transportProtocol != TLS_TRANSPORT_PROTOCOL_DATAGRAM)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Set transport protocol
   context->transportProtocol = transportProtocol;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set operation mode (client or server)
 * @param[in] context Pointer to the TLS context
 * @param[in] entity Specifies whether this entity is considered a client or a server
 * @return Error code
 **/

error_t tlsSetConnectionEnd(TlsContext *context, TlsConnectionEnd entity)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(entity != TLS_CONNECTION_END_CLIENT && entity != TLS_CONNECTION_END_SERVER)
      return ERROR_INVALID_PARAMETER;

   //Check whether TLS operates as a client or a server
   context->entity = entity;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the pseudo-random number generator to be used
 * @param[in] context Pointer to the TLS context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t tlsSetPrng(TlsContext *context, const PrngAlgo *prngAlgo,
   void *prngContext)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(prngAlgo == NULL || prngContext == NULL)
      return ERROR_INVALID_PARAMETER;

   //PRNG algorithm that will be used to generate random numbers
   context->prngAlgo = prngAlgo;
   //PRNG context
   context->prngContext = prngContext;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set the server name
 * @param[in] context Pointer to the TLS context
 * @param[in] serverName Fully qualified domain name of the server
 * @return Error code
 **/

error_t tlsSetServerName(TlsContext *context, const char_t *serverName)
{
   size_t i;
   size_t length;

   //Check parameters
   if(context == NULL || serverName == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the server name
   length = osStrlen(serverName);

   //Check whether the server name has already been configured
   if(context->serverName != NULL)
   {
      //Release memory
      tlsFreeMem(context->serverName);
      context->serverName = NULL;
   }

   //Valid server name?
   if(length > 0)
   {
      //Allocate a memory block to hold the hostname
      context->serverName = tlsAllocMem(length + 1);
      //Failed to allocate memory?
      if(context->serverName == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Convert the hostname into lowercase
      for(i = 0; i < length; i++)
         context->serverName[i] = osTolower(serverName[i]);

      //Properly terminate the string with a NULL character
      context->serverName[length] = '\0';
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the server name
 * @param[in] context Pointer to the TLS context
 * @return Fully qualified domain name of the server
 **/

const char_t *tlsGetServerName(TlsContext *context)
{
   static const char_t defaultServerName[] = "";

   //Valid protocol name?
   if(context != NULL && context->serverName != NULL)
   {
      //Return the fully qualified domain name of the server
      return context->serverName;
   }
   else
   {
      //Return an empty string
      return defaultServerName;
   }
}


/**
 * @brief Set session cache
 * @param[in] context Pointer to the TLS context
 * @param[in] cache Session cache that will be used to save/resume TLS sessions
 * @return Error code
 **/

error_t tlsSetCache(TlsContext *context, TlsCache *cache)
{
   //Check parameters
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //The cache will be used to save/resume TLS sessions
   context->cache = cache;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set client authentication mode (for servers only)
 * @param[in] context Pointer to the TLS context
 * @param[in] mode Client authentication mode
 * @return Error code
 **/

error_t tlsSetClientAuthMode(TlsContext *context, TlsClientAuthMode mode)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save client authentication mode
   context->clientAuthMode = mode;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set TLS buffer size
 * @param[in] context Pointer to the TLS context
 * @param[in] txBufferSize TX buffer size
 * @param[in] rxBufferSize RX buffer size
 * @return Error code
 **/

error_t tlsSetBufferSize(TlsContext *context, size_t txBufferSize,
   size_t rxBufferSize)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(txBufferSize < TLS_MIN_RECORD_LENGTH ||
      rxBufferSize < TLS_MIN_RECORD_LENGTH)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Maximum number of plaintext data the TX and RX buffers can hold
   context->txBufferMaxLen = txBufferSize;
   context->rxBufferMaxLen = rxBufferSize;

#if (DTLS_SUPPORT == ENABLED)
   //Calculate the required size for the TX buffer
   context->txBufferSize = txBufferSize + sizeof(DtlsRecord) +
      TLS_MAX_RECORD_OVERHEAD;

   //Calculate the required size for the RX buffer
   context->rxBufferSize = rxBufferSize + sizeof(DtlsRecord) +
      TLS_MAX_RECORD_OVERHEAD;
#else
   //Calculate the required size for the TX buffer
   context->txBufferSize = txBufferSize + sizeof(TlsRecord) +
      TLS_MAX_RECORD_OVERHEAD;

   //Calculate the required size for the RX buffer
   context->rxBufferSize = rxBufferSize + sizeof(TlsRecord) +
      TLS_MAX_RECORD_OVERHEAD;
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set maximum fragment length
 * @param[in] context Pointer to the TLS context
 * @param[in] maxFragLen Maximum fragment length
 * @return Error code
 **/

error_t tlsSetMaxFragmentLength(TlsContext *context, size_t maxFragLen)
{
#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the specified value is acceptable (ref to RFC 6066, section 4)
   if(maxFragLen != 512 && maxFragLen != 1024 &&
      maxFragLen != 2048 && maxFragLen != 4096 &&
      maxFragLen != 16384)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Set maximum fragment length
   context->maxFragLen = maxFragLen;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Specify the list of allowed cipher suites
 * @param[in] context Pointer to the TLS context
 * @param[in] cipherSuites List of allowed cipher suites (most preferred
 *   first). This parameter is taken as reference
 * @param[in] length Number of cipher suites in the list
 * @return Error code
 **/

error_t tlsSetCipherSuites(TlsContext *context, const uint16_t *cipherSuites,
   uint_t length)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(cipherSuites == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Restrict the cipher suites that can be used
   context->cipherSuites = cipherSuites;
   context->numCipherSuites = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Specify the list of allowed ECDHE and FFDHE groups
 * @param[in] context Pointer to the TLS context
 * @param[in] groups List of named groups (most preferred first). This
 *   parameter is taken as reference
 * @param[in] length Number of named groups in the list
 * @return Error code
 **/

error_t tlsSetSupportedGroups(TlsContext *context, const uint16_t *groups,
   uint_t length)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(groups == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Restrict the named groups that can be used
   context->supportedGroups = groups;
   context->numSupportedGroups = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Specify the preferred ECDHE or FFDHE group
 * @param[in] context Pointer to the TLS context
 * @param[in] group Preferred ECDHE or FFDHE named group
 * @return Error code
 **/

error_t tlsSetPreferredGroup(TlsContext *context, uint16_t group)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the preferred named group
   context->preferredGroup = group;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import Diffie-Hellman parameters
 * @param[in] context Pointer to the TLS context
 * @param[in] params PEM structure that holds Diffie-Hellman parameters. This
 *   parameter is taken as reference
 * @param[in] length Total length of the DER structure
 * @return Error code
 **/

error_t tlsSetDhParameters(TlsContext *context, const char_t *params,
   size_t length)
{
#if (TLS_DH_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(params == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Decode the PEM structure that holds Diffie-Hellman parameters
   return pemImportDhParameters(params, length, &context->dhContext.params);
#else
   //Diffie-Hellman is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register ECDH key agreement callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] ecdhCallback ECDH callback function
 * @return Error code
 **/

error_t tlsSetEcdhCallback(TlsContext *context, TlsEcdhCallback ecdhCallback)
{
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || ecdhCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the ECDH key agreement callback function
   context->ecdhCallback = ecdhCallback;

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature generation callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] ecdsaSignCallback ECDSA signature generation callback function
 * @return Error code
 **/

error_t tlsSetEcdsaSignCallback(TlsContext *context,
   TlsEcdsaSignCallback ecdsaSignCallback)
{
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || ecdsaSignCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the ECDSA signature generation callback function
   context->ecdsaSignCallback = ecdsaSignCallback;

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register ECDSA signature verification callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] ecdsaVerifyCallback ECDSA signature verification callback function
 * @return Error code
 **/

error_t tlsSetEcdsaVerifyCallback(TlsContext *context,
   TlsEcdsaVerifyCallback ecdsaVerifyCallback)
{
#if (TLS_ECC_CALLBACK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || ecdsaVerifyCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the ECDSA signature verification callback function
   context->ecdsaVerifyCallback = ecdsaVerifyCallback;

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register key logging callback function (for debugging purpose only)
 * @param[in] context Pointer to the TLS context
 * @param[in] keyLogCallback Key logging callback function
 * @return Error code
 **/

error_t tlsSetKeyLogCallback(TlsContext *context,
   TlsKeyLogCallback keyLogCallback)
{
#if (TLS_KEY_LOG_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || keyLogCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the key logging callback function
   context->keyLogCallback = keyLogCallback;

   //Successful processing
   return NO_ERROR;
#else
   //Key logging is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Allow unknown ALPN protocols
 * @param[in] context Pointer to the TLS context
 * @param[in] allowed Specifies whether unknown ALPN protocols are allowed
 * @return Error code
 **/

error_t tlsAllowUnknownAlpnProtocols(TlsContext *context, bool_t allowed)
{
#if (TLS_ALPN_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Allow or disallow unknown ALPN protocols
   context->unknownProtocolsAllowed = allowed;

   //Successful processing
   return NO_ERROR;
#else
   //ALPN is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set the list of supported ALPN protocols
 * @param[in] context Pointer to the TLS context
 * @param[in] protocolList Comma-delimited list of supported protocols
 * @return Error code
 **/

error_t tlsSetAlpnProtocolList(TlsContext *context, const char_t *protocolList)
{
#if (TLS_ALPN_SUPPORT == ENABLED)
   size_t length;

   //Check parameters
   if(context == NULL || protocolList == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the list
   length = osStrlen(protocolList);

   //Check whether the list of supported protocols has already been configured
   if(context->protocolList != NULL)
   {
      //Release memory
      tlsFreeMem(context->protocolList);
      context->protocolList = NULL;
   }

   //Check whether the list of protocols is valid
   if(length > 0)
   {
      //Allocate a memory block to hold the list
      context->protocolList = tlsAllocMem(length + 1);
      //Failed to allocate memory?
      if(context->protocolList == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the list of supported protocols
      osStrcpy(context->protocolList, protocolList);
   }

   //Successful processing
   return NO_ERROR;
#else
   //ALPN is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register ALPN callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] alpnCallback ALPN callback function
 * @return Error code
 **/

error_t tlsSetAlpnCallback(TlsContext *context, TlsAlpnCallback alpnCallback)
{
#if (TLS_ALPN_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || alpnCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the ALPN callback function
   context->alpnCallback = alpnCallback;

   //Successful processing
   return NO_ERROR;
#else
   //ALPN is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Get the name of the selected ALPN protocol
 * @param[in] context Pointer to the TLS context
 * @return Pointer to the protocol name
 **/

const char_t *tlsGetAlpnProtocol(TlsContext *context)
{
   static const char_t defaultProtocolName[] = "";

#if (TLS_ALPN_SUPPORT == ENABLED)
   //Valid protocol name?
   if(context != NULL && context->selectedProtocol != NULL)
   {
      //Return the name of the selected protocol
      return context->selectedProtocol;
   }
   else
#endif
   {
      //Return an empty string
      return defaultProtocolName;
   }
}


/**
 * @brief Set the pre-shared key to be used
 * @param[in] context Pointer to the TLS context
 * @param[in] psk Pointer to the pre-shared key
 * @param[in] length Length of the pre-shared key, in bytes
 * @return Error code
 **/

error_t tlsSetPsk(TlsContext *context, const uint8_t *psk, size_t length)
{
#if (TLS_PSK_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(psk == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Check whether the pre-shared key has already been configured
   if(context->psk != NULL)
   {
      //Release memory
      osMemset(context->psk, 0, context->pskLen);
      tlsFreeMem(context->psk);
      context->psk = NULL;
      context->pskLen = 0;
   }

   //Valid PSK?
   if(length > 0)
   {
      //Allocate a memory block to hold the pre-shared key
      context->psk = tlsAllocMem(length);
      //Failed to allocate memory?
      if(context->psk == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the pre-shared key
      osMemcpy(context->psk, psk, length);
      //Save the length of the key
      context->pskLen = length;
   }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //For externally established PSKs, the hash algorithm must be set when the
   //PSK is established, or default to SHA-256 if no such algorithm is defined
   context->pskHashAlgo = TLS_HASH_ALGO_SHA256;

   //The cipher suite must be provisioned along with the key
   context->pskCipherSuite = 0;
#endif

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set the PSK identity to be used by the client
 * @param[in] context Pointer to the TLS context
 * @param[in] pskIdentity NULL-terminated string that contains the PSK identity
 * @return Error code
 **/

error_t tlsSetPskIdentity(TlsContext *context, const char_t *pskIdentity)
{
#if (TLS_PSK_SUPPORT == ENABLED)
   size_t length;

   //Check parameters
   if(context == NULL || pskIdentity == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the PSK identity
   length = osStrlen(pskIdentity);

   //Check whether the PSK identity has already been configured
   if(context->pskIdentity != NULL)
   {
      //Release memory
      tlsFreeMem(context->pskIdentity);
      context->pskIdentity = NULL;
   }

   //Valid PSK identity?
   if(length > 0)
   {
      //Allocate a memory block to hold the PSK identity
      context->pskIdentity = tlsAllocMem(length + 1);
      //Failed to allocate memory?
      if(context->pskIdentity == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the PSK identity
      osStrcpy(context->pskIdentity, pskIdentity);
   }

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set the PSK identity hint to be used by the server
 * @param[in] context Pointer to the TLS context
 * @param[in] pskIdentityHint NULL-terminated string that contains the PSK identity hint
 * @return Error code
 **/

error_t tlsSetPskIdentityHint(TlsContext *context, const char_t *pskIdentityHint)
{
#if (TLS_PSK_SUPPORT == ENABLED)
   size_t length;

   //Check parameters
   if(context == NULL || pskIdentityHint == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the PSK identity hint
   length = osStrlen(pskIdentityHint);

   //Check whether the PSK identity hint has already been configured
   if(context->pskIdentityHint != NULL)
   {
      //Release memory
      tlsFreeMem(context->pskIdentityHint);
      context->pskIdentityHint = NULL;
   }

   //Valid PSK identity hint?
   if(length > 0)
   {
      //Allocate a memory block to hold the PSK identity hint
      context->pskIdentityHint = tlsAllocMem(length + 1);
      //Failed to allocate memory?
      if(context->pskIdentityHint == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save the PSK identity hint
      osStrcpy(context->pskIdentityHint, pskIdentityHint);
   }

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register PSK callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] pskCallback PSK callback function
 * @return Error code
 **/

error_t tlsSetPskCallback(TlsContext *context, TlsPskCallback pskCallback)
{
#if (TLS_PSK_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || pskCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the PSK callback function
   context->pskCallback = pskCallback;

   //Successful processing
   return NO_ERROR;
#else
   //PSK key exchange is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Register the raw public key verification callback function
 * @param[in] context Pointer to the TLS context
 * @param[in] rpkVerifyCallback RPK verification callback function
 * @return Error code
 **/

error_t tlsSetRpkVerifyCallback(TlsContext *context,
   TlsRpkVerifyCallback rpkVerifyCallback)
{
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Check parameters
   if(context == NULL || rpkVerifyCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the raw public key verification callback function
   context->rpkVerifyCallback = rpkVerifyCallback;

   //Successful processing
   return NO_ERROR;
#else
   //Raw public keys are not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import a trusted CA list
 * @param[in] context Pointer to the TLS context
 * @param[in] trustedCaList List of trusted CA (PEM format)
 * @param[in] length Total length of the list
 * @return Error code
 **/

error_t tlsSetTrustedCaList(TlsContext *context,
   const char_t *trustedCaList, size_t length)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(trustedCaList == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Save the list of trusted CA
   context->trustedCaList = trustedCaList;
   context->trustedCaListLen = length;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Import a certificate and the corresponding private key
 * @param[in] context Pointer to the TLS context
 * @param[in] certChain Certificate chain (PEM format). This parameter is
 *   taken as reference
 * @param[in] certChainLen Total length of the certificate chain
 * @param[in] privateKey Private key (PEM format). This parameter is taken
 *   as reference
 * @param[in] privateKeyLen Total length of the private key
 * @return Error code
 **/

error_t tlsAddCertificate(TlsContext *context, const char_t *certChain,
   size_t certChainLen, const char_t *privateKey, size_t privateKeyLen)
{
   error_t error;
   uint8_t *derCert;
   size_t derCertLen;
   X509CertificateInfo *certInfo;
   TlsCertificateType certType;
   TlsSignatureAlgo certSignAlgo;
   TlsHashAlgo certHashAlgo;
   TlsNamedGroup namedCurve;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check whether the certificate chain is valid
   if(certChain == NULL || certChainLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The private key is optional
   if(privateKey == NULL && privateKeyLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Make sure there is enough room to add the certificate
   if(context->numCerts >= TLS_MAX_CERTIFICATES)
      return ERROR_OUT_OF_RESOURCES;

   //Initialize variables
   derCert = NULL;
   certInfo = NULL;

   //Start of exception handling block
   do
   {
      //The first pass calculates the length of the DER-encoded certificate
      error = pemImportCertificate(certChain, certChainLen, NULL, &derCertLen,
         NULL);
      //Any error to report?
      if(error)
         break;

      //Allocate a memory buffer to hold the DER-encoded certificate
      derCert = tlsAllocMem(derCertLen);
      //Failed to allocate memory?
      if(derCert == NULL)
      {
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //The second pass decodes the PEM certificate
      error = pemImportCertificate(certChain, certChainLen, derCert,
         &derCertLen, NULL);
      //Any error to report?
      if(error)
         break;

      //Allocate a memory buffer to store X.509 certificate info
      certInfo = tlsAllocMem(sizeof(X509CertificateInfo));
      //Failed to allocate memory?
      if(certInfo == NULL)
      {
         error = ERROR_OUT_OF_MEMORY;
         break;
      }

      //Parse X.509 certificate
      error = x509ParseCertificateEx(derCert, derCertLen, certInfo, TRUE);
      //Failed to parse the X.509 certificate?
      if(error)
         break;

      //Retrieve the signature algorithm that has been used to sign the
      //certificate
      error = tlsGetCertificateType(certInfo, &certType, &certSignAlgo,
         &certHashAlgo, &namedCurve);
      //The specified signature algorithm is not supported?
      if(error)
         break;

      //End of exception handling block
   } while(0);

   //Valid certificate?
   if(!error)
   {
      //Point to the structure that describes the certificate
      TlsCertDesc *cert = &context->certs[context->numCerts];

      //Save the certificate chain and the corresponding private key
      cert->certChain = certChain;
      cert->certChainLen = certChainLen;
      cert->privateKey = privateKey;
      cert->privateKeyLen = privateKeyLen;
      cert->type = certType;
      cert->signAlgo = certSignAlgo;
      cert->hashAlgo = certHashAlgo;
      cert->namedCurve = namedCurve;

      //Update the number of certificates
      context->numCerts++;
   }

   //Release previously allocated memory
   tlsFreeMem(derCert);
   tlsFreeMem(certInfo);

   //Return status code
   return error;
}


/**
 * @brief Set certificate verification callback
 * @param[in] context Pointer to the TLS context
 * @param[in] certVerifyCallback Certificate verification callback
 * @param[in] param An opaque pointer passed to the callback function
 * @return Error code
 **/

error_t tlsSetCertificateVerifyCallback(TlsContext *context,
   TlsCertVerifyCallback certVerifyCallback, void *param)
{
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save certificate verification callback
   context->certVerifyCallback = certVerifyCallback;
   //This opaque pointer will be directly passed to the callback function
   context->certVerifyParam = param;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Enable session ticket mechanism
 * @param[in] context Pointer to the TLS context
 * @param[in] enabled Specifies whether session tickets are allowed
 * @return Error code
 **/

error_t tlsEnableSessionTickets(TlsContext *context, bool_t enabled)
{
#if (TLS_TICKET_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Enable or disable session ticket mechanism
   context->sessionTicketEnabled = enabled;

   //Successful processing
   return NO_ERROR;
#else
   //Session ticket mechanism is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Enable secure renegotiation
 * @param[in] context Pointer to the TLS context
 * @param[in] enabled Specifies whether secure renegotiation is allowed
 * @return Error code
 **/

error_t tlsEnableSecureRenegotiation(TlsContext *context, bool_t enabled)
{
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Enable or disable secure renegotiation
   context->secureRenegoEnabled = enabled;

   //Successful processing
   return NO_ERROR;
#else
   //Secure renegotiation is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Perform fallback retry (for clients only)
 * @param[in] context Pointer to the TLS context
 * @param[in] enabled Specifies whether FALLBACK_SCSV is enabled
 * @return Error code
 **/

error_t tlsEnableFallbackScsv(TlsContext *context, bool_t enabled)
{
#if (TLS_FALLBACK_SCSV_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Enable or disable support for FALLBACK_SCSV
   context->fallbackScsvEnabled = enabled;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set ticket encryption/decryption callbacks
 * @param[in] context Pointer to the TLS context
 * @param[in] ticketEncryptCallback Ticket encryption callback function
 * @param[in] ticketDecryptCallback Ticket decryption callback function
 * @param[in] param An opaque pointer passed to the callback functions
 * @return Error code
 **/

error_t tlsSetTicketCallbacks(TlsContext *context,
   TlsTicketEncryptCallback ticketEncryptCallback,
   TlsTicketDecryptCallback ticketDecryptCallback, void *param)
{
#if (TLS_TICKET_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save ticket encryption/decryption callback functions
   context->ticketEncryptCallback = ticketEncryptCallback;
   context->ticketDecryptCallback = ticketDecryptCallback;

   //This opaque pointer will be directly passed to the callback functions
   context->ticketParam = param;

   //Successful processing
   return NO_ERROR;
#else
   //Session ticket mechanism is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set PMTU value (for DTLS only)
 * @param[in] context Pointer to the TLS context
 * @param[in] pmtu PMTU value
 * @return Error code
 **/

error_t tlsSetPmtu(TlsContext *context, size_t pmtu)
{
#if (DTLS_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the PMTU value is acceptable
   if(pmtu < DTLS_MIN_PMTU)
      return ERROR_INVALID_PARAMETER;

   //Save PMTU value
   context->pmtu = pmtu;

   //Successful processing
   return NO_ERROR;
#else
   //DTLS is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set timeout for blocking calls (for DTLS only)
 * @param[in] context Pointer to the TLS context
 * @param[in] timeout Maximum time to wait
 * @return Error code
 **/

error_t tlsSetTimeout(TlsContext *context, systime_t timeout)
{
#if (DTLS_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save timeout value
   context->timeout = timeout;

   //Successful processing
   return NO_ERROR;
#else
   //DTLS is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Set cookie generation/verification callbacks (for DTLS only)
 * @param[in] context Pointer to the TLS context
 * @param[in] cookieGenerateCallback Cookie generation callback function
 * @param[in] cookieVerifyCallback Cookie verification callback function
 * @param[in] param An opaque pointer passed to the callback functions
 * @return Error code
 **/

error_t tlsSetCookieCallbacks(TlsContext *context,
   DtlsCookieGenerateCallback cookieGenerateCallback,
   DtlsCookieVerifyCallback cookieVerifyCallback, void *param)
{
#if (DTLS_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(cookieGenerateCallback == NULL || cookieVerifyCallback == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save cookie generation/verification callback functions
   context->cookieGenerateCallback = cookieGenerateCallback;
   context->cookieVerifyCallback = cookieVerifyCallback;

   //This opaque pointer will be directly passed to the callback functions
   context->cookieParam = param;

   //Successful processing
   return NO_ERROR;
#else
   //DTLS is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Enable anti-replay mechanism (for DTLS only)
 * @param[in] context Pointer to the TLS context
 * @param[in] enabled Specifies whether anti-replay protection is enabled
 * @return Error code
 **/

error_t tlsEnableReplayDetection(TlsContext *context, bool_t enabled)
{
#if (DTLS_SUPPORT == ENABLED && DTLS_REPLAY_DETECTION_SUPPORT == ENABLED)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Enable or disable anti-replay mechanism
   context->replayDetectionEnabled = enabled;

   //Successful processing
   return NO_ERROR;
#else
   //Anti-replay mechanism is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send the maximum amount of 0-RTT data the server can accept
 * @param[in] context Pointer to the TLS context
 * @param[in] maxEarlyDataSize Maximum amount of 0-RTT data that the client
 *   is allowed to send
 * @return Error code
 **/


error_t tlsSetMaxEarlyDataSize(TlsContext *context, size_t maxEarlyDataSize)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Save the maximum amount of 0-RTT data that the client is allowed to send
   context->maxEarlyDataSize = maxEarlyDataSize;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send early data to the remote TLS server
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to a buffer containing the data to be transmitted
 * @param[in] length Number of bytes to be transmitted
 * @param[out] written Actual number of bytes written (optional parameter)
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t tlsWriteEarlyData(TlsContext *context, const void *data,
   size_t length, size_t *written, uint_t flags)
{
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3 && \
   TLS_CLIENT_SUPPORT == ENABLED && TLS13_EARLY_DATA_SUPPORT == ENABLED)
   size_t n;
   error_t error;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Check operation mode
   if(context->entity != TLS_CONNECTION_END_CLIENT)
      return ERROR_FAILURE;

   //Make sure TLS 1.3 is supported by the client
   if(context->versionMax < TLS_VERSION_1_3)
      return ERROR_FAILURE;

   //Check transport protocol
   if(context->transportProtocol != TLS_TRANSPORT_PROTOCOL_STREAM)
      return ERROR_FAILURE;

   //Ensure the send/receive functions are properly registered
   if(context->socketSendCallback == NULL || context->socketReceiveCallback == NULL)
      return ERROR_NOT_CONFIGURED;

   //Verify that the PRNG is properly set
   if(context->prngAlgo == NULL || context->prngContext == NULL)
      return ERROR_NOT_CONFIGURED;

#if (DTLS_SUPPORT == ENABLED)
   //Save current time
   context->startTime = osGetSystemTime();
#endif

   //Send 0-RTT data
   error = tls13SendEarlyData(context, data, length, &n);

   //Total number of data that have been written
   if(written != NULL)
      *written = n;

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Initiate the TLS handshake
 * @param[in] context Pointer to the TLS context
 * @return Error code
 **/

error_t tlsConnect(TlsContext *context)
{
   error_t error;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ensure the send/receive functions are properly registered
   if(context->socketSendCallback == NULL || context->socketReceiveCallback == NULL)
      return ERROR_NOT_CONFIGURED;

   //Verify that the PRNG is properly set
   if(context->prngAlgo == NULL || context->prngContext == NULL)
      return ERROR_NOT_CONFIGURED;

#if (DTLS_SUPPORT == ENABLED)
   //Save current time
   context->startTime = osGetSystemTime();
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3 && \
   TLS_CLIENT_SUPPORT == ENABLED && TLS13_EARLY_DATA_SUPPORT == ENABLED)
   //Any 0-RTT data sent by the client?
   if(context->entity == TLS_CONNECTION_END_CLIENT &&
      context->state == TLS_STATE_EARLY_DATA)
   {
      //Save current sequence number
      context->earlyDataSeqNum = context->encryptionEngine.seqNum;
      //Wait for a ServerHello message
      context->state = TLS_STATE_SERVER_HELLO_3;
   }
#endif

   //Perform TLS handshake
   error = tlsPerformHandshake(context);
   //Return status code
   return error;
}


/**
 * @brief Check whether the server has accepted or rejected the early data
 * @param[in] context Pointer to the TLS context
 * @return TLS_EARLY_DATA_ACCEPTED if the early data was accepted, else
 *   TLS_EARLY_DATA_REJECT if the early data was rejected
 **/

TlsEarlyDataStatus tlsGetEarlyDataStatus(TlsContext *context)
{
   TlsEarlyDataStatus status;

   //Initialize early data status
   status = TLS_EARLY_DATA_REJECTED;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3 && \
   TLS_CLIENT_SUPPORT == ENABLED && TLS13_EARLY_DATA_SUPPORT == ENABLED)
   //Make sure the TLS context is valid
   if(context != NULL)
   {
      //Client mode?
      if(context->entity == TLS_CONNECTION_END_CLIENT)
      {
         //Any 0-RTT data sent by the client?
         if(context->earlyDataEnabled)
         {
            //Check whether the server has accepted or rejected the early data
            if(context->earlyDataExtReceived && !context->earlyDataRejected)
            {
               status = TLS_EARLY_DATA_ACCEPTED;
            }
         }
      }
   }
#endif

   //Return early data status
   return status;
}


/**
 * @brief Send application data to the remote host using TLS
 * @param[in] context Pointer to the TLS context
 * @param[in] data Pointer to a buffer containing the data to be transmitted
 * @param[in] length Number of bytes to be transmitted
 * @param[out] written Actual number of bytes written (optional parameter)
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t tlsWrite(TlsContext *context, const void *data,
   size_t length, size_t *written, uint_t flags)
{
   error_t error;
   size_t n;
   size_t totalLength;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   //Ensure the send/receive functions are properly registered
   if(context->socketSendCallback == NULL || context->socketReceiveCallback == NULL)
      return ERROR_NOT_CONFIGURED;

#if (DTLS_SUPPORT == ENABLED)
   //Save current time
   context->startTime = osGetSystemTime();
#endif

   //Initialize status code
   error = NO_ERROR;

   //Actual number of bytes written
   totalLength = 0;

   //Send as much data as possible
   while(totalLength < length)
   {
      //Check current state
      if(context->state < TLS_STATE_APPLICATION_DATA)
      {
         //Perform TLS handshake
         error = tlsConnect(context);
      }
      else if(context->state == TLS_STATE_APPLICATION_DATA)
      {
#if (DTLS_SUPPORT == ENABLED)
         //DTLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
         {
            //Length of the payload data
            n = length;

            //Send a datagram
            error = dtlsWriteProtocolData(context, data, n,
               TLS_TYPE_APPLICATION_DATA);
         }
         else
#endif
         //TLS protocol?
         {
            //Calculate the number of bytes to write at a time
            n = MIN(length - totalLength, context->txBufferMaxLen);
            //The record length must not exceed 16384 bytes
            n = MIN(n, TLS_MAX_RECORD_LENGTH);

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
            //Do not exceed the negotiated maximum fragment length
            n = MIN(n, context->maxFragLen);
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
            //Maximum record size the peer is willing to receive
            n = MIN(n, context->recordSizeLimit);
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_0)
            //The 1/n-1 record splitting technique is a workaround for the
            //BEAST attack
            if(context->version <= TLS_VERSION_1_0 &&
               context->cipherSuite.cipherMode == CIPHER_MODE_CBC &&
               context->txLastRecordLen != 1 &&
               totalLength == 0)
            {
               n = 1;
            }
#endif
            //Send application data
            error = tlsWriteProtocolData(context, data, n,
               TLS_TYPE_APPLICATION_DATA);
         }

         //Check status code
         if(!error)
         {
#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_0)
            //Save the length of the TLS record
            context->txLastRecordLen = n;
#endif
            //Advance data pointer
            data = (uint8_t *) data + n;
            //Update byte counter
            totalLength += n;
         }
         else
         {
            //Send an alert message to the peer, if applicable
            tlsProcessError(context, error);
         }
      }
      else
      {
         //The connection has not yet been established
         error = ERROR_NOT_CONNECTED;
      }

      //Any error to report?
      if(error)
         break;
   }

   //Total number of data that have been written
   if(written != NULL)
      *written = totalLength;

   //Return status code
   return error;
}


/**
 * @brief Receive application data from a the remote host using TLS
 * @param[in] context Pointer to the TLS context
 * @param[out] data Buffer into which received data will be placed
 * @param[in] size Maximum number of bytes that can be received
 * @param[out] received Number of bytes that have been received
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t tlsRead(TlsContext *context, void *data,
   size_t size, size_t *received, uint_t flags)
{
   error_t error;
   size_t i;
   size_t n;
   uint8_t *p;
   TlsContentType contentType;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check parameters
   if(data == NULL || received == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ensure the send/receive functions are properly registered
   if(context->socketSendCallback == NULL || context->socketReceiveCallback == NULL)
      return ERROR_NOT_CONFIGURED;

#if (DTLS_SUPPORT == ENABLED)
   //Save current time
   context->startTime = osGetSystemTime();
#endif

   //Initialize status code
   error = NO_ERROR;

   //No data has been read yet
   *received = 0;

   //Read as much data as possible
   while(*received < size)
   {
      //Check current state
      if(context->state < TLS_STATE_APPLICATION_DATA)
      {
         //Perform TLS handshake
         error = tlsConnect(context);
      }
      else if(context->state == TLS_STATE_APPLICATION_DATA)
      {
#if (DTLS_SUPPORT == ENABLED)
         //DTLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
         {
            //Receive a datagram
            error = dtlsReadProtocolData(context, &p, &n, &contentType);
         }
         else
#endif
         //TLS protocol?
         {
            //The record layer receives uninterpreted data from higher layers
            error = tlsReadProtocolData(context, &p, &n, &contentType);
         }

         //Check status code
         if(!error)
         {
            //Application data received?
            if(contentType == TLS_TYPE_APPLICATION_DATA)
            {
#if (DTLS_SUPPORT == ENABLED)
               //DTLS protocol?
               if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
               {
                  //Make sure the user buffer is large enough to hold the whole
                  //datagram
                  if(n > size)
                  {
                     //Report an error
                     error = ERROR_BUFFER_OVERFLOW;
                  }
                  else
                  {
                     //Copy data to user buffer
                     osMemcpy(data, p, n);
                     //Total number of data that have been read
                     *received = n;
                  }

                  //If the TLS_FLAG_PEEK flag is set, the data is copied into
                  //the buffer but is not removed from the receive queue
                  if((flags & TLS_FLAG_PEEK) == 0)
                  {
                     //Flush receive buffer
                     context->rxBufferPos = 0;
                     context->rxBufferLen = 0;
                  }

                  //We are done
                  break;
               }
               else
#endif
               //TLS protocol?
               {
                  //Limit the number of bytes to read at a time
                  n = MIN(n, size - *received);

                  //The TLS_FLAG_BREAK_CHAR flag causes the function to stop reading
                  //data as soon as the specified break character is encountered
                  if((flags & TLS_FLAG_BREAK_CHAR) != 0)
                  {
                     //Retrieve the break character code
                     char_t c = LSB(flags);

                     //Search for the specified break character
                     for(i = 0; i < n && p[i] != c; i++);
                     //Adjust the number of data to read
                     n = MIN(n, i + 1);

                     //Copy data to user buffer
                     osMemcpy(data, p, n);
                     //Total number of data that have been read
                     *received += n;

                     //Advance data pointer
                     context->rxBufferPos += n;
                     //Number of bytes still pending in the receive buffer
                     context->rxBufferLen -= n;

                     //Check whether a break character has been found
                     if(n > 0 && p[n - 1] == c)
                        break;
                  }
                  else
                  {
                     //Copy data to user buffer
                     osMemcpy(data, p, n);
                     //Total number of data that have been read
                     *received += n;

                     //Advance data pointer
                     context->rxBufferPos += n;
                     //Number of bytes still pending in the receive buffer
                     context->rxBufferLen -= n;

                     //The TLS_FLAG_WAIT_ALL flag causes the function to return
                     //only when the requested number of bytes have been read
                     if((flags & TLS_FLAG_WAIT_ALL) == 0)
                        break;
                  }

                  //Advance data pointer
                  data = (uint8_t *) data + n;
               }
            }
            //Handshake message received?
            else if(contentType == TLS_TYPE_HANDSHAKE)
            {
               //Advance data pointer
               context->rxBufferPos += n;
               //Number of bytes still pending in the receive buffer
               context->rxBufferLen -= n;

               //Parse handshake message
               error = tlsParseHandshakeMessage(context, p, n);
            }
            //Alert message received?
            else if(contentType == TLS_TYPE_ALERT)
            {
               //Advance data pointer
               context->rxBufferPos += n;
               //Number of bytes still pending in the receive buffer
               context->rxBufferLen -= n;

               //Parse Alert message
               error = tlsParseAlert(context, (TlsAlert *) p, n);
            }
            //An inappropriate message was received?
            else
            {
               //Report an error
               error = ERROR_UNEXPECTED_MESSAGE;
            }
         }

         //Any error to report?
         if(error)
         {
            //Send an alert message to the peer, if applicable
            tlsProcessError(context, error);
         }
      }
      else if(context->state == TLS_STATE_CLOSING ||
         context->state == TLS_STATE_CLOSED)
      {
         //Check whether a fatal alert message has been sent or received
         if(context->fatalAlertSent || context->fatalAlertReceived)
         {
            //Alert messages with a level of fatal result in the immediate
            //termination of the connection
            error = ERROR_FAILURE;
         }
         else
         {
            //The user must be satisfied with data already on hand
            if(*received > 0)
            {
               //Some data are pending in the receive buffer
               error = NO_ERROR;
               break;
            }
            else
            {
               //The receive buffer is empty
               error = ERROR_END_OF_STREAM;
            }
         }
      }
      else
      {
         //The connection has not yet been established
         error = ERROR_NOT_CONNECTED;
      }

      //Any error to report?
      if(error)
         break;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether some data is ready for transmission
 * @param[in] context Pointer to the TLS context
 * @return The function returns TRUE if some data is ready for transmission.
 *   Otherwise, FALSE is returned
 **/

bool_t tlsIsTxReady(TlsContext *context)
{
   bool_t ready;

   //Initialize flag
   ready = FALSE;

   //Make sure the TLS context is valid
   if(context != NULL)
   {
      //TLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
      {
         //Check whether some data is pending in the transmit buffer
         if(context->txBufferPos < context->txBufferLen)
         {
            ready = TRUE;
         }
      }
   }

   //The function returns TRUE if some data is ready for transmission
   return ready;
}


/**
 * @brief Check whether some data is available in the receive buffer
 * @param[in] context Pointer to the TLS context
 * @return The function returns TRUE if some data is pending and can be read
 *   immediately without blocking. Otherwise, FALSE is returned
 **/

bool_t tlsIsRxReady(TlsContext *context)
{
   bool_t ready;

   //Initialize flag
   ready = FALSE;

   //Make sure the TLS context is valid
   if(context != NULL)
   {
#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //Check whether a datagram is pending in the receive buffer
         if(context->rxBufferLen > 0 ||
            context->rxRecordLen > 0 ||
            context->rxDatagramLen > 0)
         {
            ready = TRUE;
         }
      }
      else
#endif
      //TLS protocol?
      {
         //Check whether some data is pending in the receive buffer
         if(context->rxBufferLen > 0)
         {
            ready = TRUE;
         }
      }
   }

   //The function returns TRUE if some data can be read immediately
   //without blocking
   return ready;
}


/**
 * @brief Gracefully close TLS session
 * @param[in] context Pointer to the TLS context
 **/

error_t tlsShutdown(TlsContext *context)
{
   //Either party may initiate a close by sending a close_notify alert
   return tlsShutdownEx(context, FALSE);
}


/**
 * @brief Gracefully close TLS session
 * @param[in] context Pointer to the TLS context
 * @param[in] waitForCloseNotify Wait for the close notify alert from the peer
 **/

error_t tlsShutdownEx(TlsContext *context, bool_t waitForCloseNotify)
{
   error_t error;
   size_t n;
   uint8_t *p;
   TlsContentType contentType;

   //Invalid TLS context?
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Ensure the send/receive functions are properly registered
   if(context->socketSendCallback == NULL || context->socketReceiveCallback == NULL)
      return ERROR_NOT_CONFIGURED;

#if (DTLS_SUPPORT == ENABLED)
   //Save current time
   context->startTime = osGetSystemTime();
#endif

   //Initialize status code
   error = NO_ERROR;

   //Wait for the TLS session to be closed
   while(context->state != TLS_STATE_CLOSED)
   {
      //Check current state
      if(context->state == TLS_STATE_APPLICATION_DATA)
      {
         //TLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
         {
            //Flush send buffer
            error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);
         }

         //Check status code
         if(!error)
         {
            //Either party may initiate a close by sending a close_notify alert
            context->state = TLS_STATE_CLOSING;
         }
      }
      else if(context->state == TLS_STATE_CLOSING)
      {
         //TLS protocol?
         if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
         {
            //Flush send buffer
            error = tlsWriteProtocolData(context, NULL, 0, TLS_TYPE_NONE);
         }

         //Check status code
         if(!error)
         {
            //Unless some other fatal alert has been transmitted, each party
            //is required to send a close_notify alert before closing the
            //write side of the connection
            if(context->fatalAlertSent || context->fatalAlertReceived)
            {
               //Close the connection immediately
               context->state = TLS_STATE_CLOSED;
            }
            else if(!context->closeNotifySent)
            {
               //Notifies the recipient that the sender will not send any
               //more messages on this connection
               error = tlsSendAlert(context, TLS_ALERT_LEVEL_WARNING,
                  TLS_ALERT_CLOSE_NOTIFY);
            }
            else if(!context->closeNotifyReceived && waitForCloseNotify)
            {
#if (DTLS_SUPPORT == ENABLED)
               //DTLS protocol?
               if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
               {
                  //Wait for the responding close_notify alert
                  error = dtlsReadProtocolData(context, &p, &n, &contentType);
               }
               else
#endif
               //TLS protocol?
               {
                  //Wait for the responding close_notify alert
                  error = tlsReadProtocolData(context, &p, &n, &contentType);
               }

               //Check status code
               if(!error)
               {
                  //Advance data pointer
                  context->rxBufferPos += n;
                  //Number of bytes still pending in the receive buffer
                  context->rxBufferLen -= n;

                  //Application data received?
                  if(contentType == TLS_TYPE_APPLICATION_DATA)
                  {
                     //Discard application data
                  }
                  //Alert message received?
                  else if(contentType == TLS_TYPE_ALERT)
                  {
                     //Parse Alert message
                     error = tlsParseAlert(context, (TlsAlert *) p, n);
                  }
                  else if(contentType == TLS_TYPE_HANDSHAKE)
                  {
                     //Parse handshake message
                     error = tlsParseHandshakeMessage(context, p, n);
                  }
                  //An inappropriate message was received?
                  else
                  {
                     //Report an error
                     error = ERROR_UNEXPECTED_MESSAGE;
                  }
               }
            }
            else
            {
               //The connection is closed
               context->state = TLS_STATE_CLOSED;
            }
         }
      }
      else
      {
         //Report an error
         error = ERROR_NOT_CONNECTED;
      }

      //Any error to report?
      if(error)
         break;
   }

   //Return status code
   return error;
}


/**
 * @brief Release TLS context
 * @param[in] context Pointer to the TLS context
 **/

void tlsFree(TlsContext *context)
{
   //Valid TLS context?
   if(context != NULL)
   {
      //Release server name
      if(context->serverName != NULL)
      {
         tlsFreeMem(context->serverName);
      }

      //Release cookie
      if(context->cookie != NULL)
      {
         osMemset(context->cookie, 0, context->cookieLen);
         tlsFreeMem(context->cookie);
      }

      //Release send buffer
      if(context->txBuffer != NULL)
      {
         osMemset(context->txBuffer, 0, context->txBufferSize);
         tlsFreeMem(context->txBuffer);
      }

      //Release receive buffer
      if(context->rxBuffer != NULL)
      {
         osMemset(context->rxBuffer, 0, context->rxBufferSize);
         tlsFreeMem(context->rxBuffer);
      }

      //Release transcript hash context
      tlsFreeTranscriptHash(context);

      //Release session ticket
      if(context->ticket != NULL)
      {
         osMemset(context->ticket, 0, context->ticketLen);
         tlsFreeMem(context->ticket);
      }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //Release the ALPN protocol associated with the ticket
      if(context->ticketAlpn != NULL)
      {
         tlsFreeMem(context->ticketAlpn);
      }
#endif

#if (TLS_DH_SUPPORT == ENABLED)
      //Release Diffie-Hellman context
      dhFree(&context->dhContext);
#endif

#if (TLS_ECDH_SUPPORT == ENABLED)
      //Release ECDH context
      ecdhFree(&context->ecdhContext);
#endif

#if (TLS_RSA_SUPPORT == ENABLED)
      //Release peer's RSA public key
      rsaFreePublicKey(&context->peerRsaPublicKey);
#endif

#if (TLS_DSA_SIGN_SUPPORT == ENABLED)
      //Release peer's DSA public key
      dsaFreePublicKey(&context->peerDsaPublicKey);
#endif

#if (TLS_ECDSA_SIGN_SUPPORT == ENABLED || TLS_EDDSA_SIGN_SUPPORT == ENABLED)
      //Release peer's EC domain parameters
      ecFreeDomainParameters(&context->peerEcParams);
      //Release peer's EC public key
      ecFreePublicKey(&context->peerEcPublicKey);
#endif

#if (TLS_PSK_SUPPORT == ENABLED)
      //Release the pre-shared key
      if(context->psk != NULL)
      {
         osMemset(context->psk, 0, context->pskLen);
         tlsFreeMem(context->psk);
      }

      //Release the PSK identity
      if(context->pskIdentity != NULL)
      {
         tlsFreeMem(context->pskIdentity);
      }

      //Release the PSK identity hint
      if(context->pskIdentityHint != NULL)
      {
         tlsFreeMem(context->pskIdentityHint);
      }
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
      //Release the list of supported ALPN protocols
      if(context->protocolList != NULL)
      {
         tlsFreeMem(context->protocolList);
      }

      //Release the selected ALPN protocol
      if(context->selectedProtocol != NULL)
      {
         tlsFreeMem(context->selectedProtocol);
      }
#endif

      //Release encryption engine
      tlsFreeEncryptionEngine(&context->encryptionEngine);
      //Release decryption engine
      tlsFreeEncryptionEngine(&context->decryptionEngine);

#if (DTLS_SUPPORT == ENABLED)
      //Release previous encryption engine
      tlsFreeEncryptionEngine(&context->prevEncryptionEngine);
#endif

      //Clear the TLS context before freeing memory
      osMemset(context, 0, sizeof(TlsContext));
      tlsFreeMem(context);
   }
}


/**
 * @brief Initialize session state
 * @param[in] session Pointer to the session state
 * @return Error code
 **/

error_t tlsInitSessionState(TlsSessionState *session)
{
   //Make sure the session state is valid
   if(session == NULL)
      return ERROR_INVALID_PARAMETER;

   //Erase session state
   osMemset(session, 0, sizeof(TlsSessionState));

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Save TLS session
 * @param[in] context Pointer to the TLS context
 * @param[out] session Pointer to the session state
 * @return Error code
 **/

error_t tlsSaveSessionState(const TlsContext *context,
   TlsSessionState *session)
{
   error_t error;

   //Check parameters
   if(context == NULL || session == NULL)
      return ERROR_INVALID_PARAMETER;

   //Release previous session state
   tlsFreeSessionState(session);

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(context->version >= TLS_VERSION_1_0 && context->version <= TLS_VERSION_1_2)
   {
      //Valid session?
      if(context->ticketLen > 0)
      {
         //Save session ticket
         error = tlsSaveSessionTicket(context, session);
      }
      else if(context->sessionIdLen > 0)
      {
         //Save session identifier
         error = tlsSaveSessionId(context, session);
      }
      else
      {
         //No valid session to save
         error = ERROR_INVALID_SESSION;
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(context->version == TLS_VERSION_1_3)
   {
      //Save session ticket
      error = tls13SaveSessionTicket(context, session);
   }
   else
#endif
   //Invalid TLS version?
   {
      //Do not save session state
      error = ERROR_INVALID_VERSION;
   }

   //Check status code
   if(error)
   {
      //Clean up side effects
      tlsFreeSessionState(session);
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Restore TLS session
 * @param[in] context Pointer to the TLS context
 * @param[in] session Pointer to the session state to be restored
 * @return Error code
 **/

error_t tlsRestoreSessionState(TlsContext *context,
   const TlsSessionState *session)
{
   //Check parameters
   if(context == NULL || session == NULL)
      return ERROR_INVALID_PARAMETER;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.0, TLS 1.1 or TLS 1.2 currently selected?
   if(session->version >= TLS_VERSION_1_0 && session->version <= TLS_VERSION_1_2)
   {
      //Valid session?
      if(session->ticketLen > 0)
      {
         //Restore a TLS session using session ticket
         tlsRestoreSessionTicket(context, session);
      }
      else if(session->sessionIdLen > 0)
      {
         //Restore a TLS session using session ID
         tlsRestoreSessionId(context, session);
      }
      else
      {
         //No valid session to restore
      }
   }
   else
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //TLS 1.3 currently selected?
   if(session->version == TLS_VERSION_1_3)
   {
      //Restore TLS session using session ticket
      tls13RestoreSessionTicket(context, session);
   }
   else
#endif
   //Invalid TLS version?
   {
      //Do not restore session state
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Properly dispose a session state
 * @param[in] session Pointer to the session state to be released
 **/

void tlsFreeSessionState(TlsSessionState *session)
{
   //Make sure the session state is valid
   if(session != NULL)
   {
      //Release session ticket
      if(session->ticket != NULL)
      {
         osMemset(session->ticket, 0, session->ticketLen);
         tlsFreeMem(session->ticket);
      }

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      //Release the ALPN protocol associated with the ticket
      if(session->ticketAlpn != NULL)
      {
         tlsFreeMem(session->ticketAlpn);
      }
#endif

#if (TLS_SNI_SUPPORT == ENABLED)
      //Release server name
      if(session->serverName != NULL)
      {
         tlsFreeMem(session->serverName);
      }
#endif

      //Erase session state
      osMemset(session, 0, sizeof(TlsSessionState));
   }
}

#endif
