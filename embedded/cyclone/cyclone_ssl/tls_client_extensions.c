/**
 * @file tls_client_extensions.c
 * @brief Formatting and parsing of extensions (TLS client)
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL TLS_TRACE_LEVEL

//Dependencies
#include <string.h>
#include "tls.h"
#include "tls_cipher_suites.h"
#include "tls_client_extensions.h"
#include "tls_client_misc.h"
#include "tls_extensions.h"
#include "tls_ffdhe.h"
#include "tls_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_CLIENT_SUPPORT == ENABLED)

//List of supported ECDHE or FFDHE groups
const uint16_t tlsSupportedGroups[] =
{
   TLS_GROUP_ECDH_X25519,
   TLS_GROUP_ECDH_X448,
   TLS_GROUP_SECP160R1,
   TLS_GROUP_SECP160R2,
   TLS_GROUP_SECP192K1,
   TLS_GROUP_SECP192R1,
   TLS_GROUP_SECP224K1,
   TLS_GROUP_SECP224R1,
   TLS_GROUP_SECP256K1,
   TLS_GROUP_SECP256R1,
   TLS_GROUP_SECP384R1,
   TLS_GROUP_SECP521R1,
   TLS_GROUP_BRAINPOOLP256R1_TLS13,
   TLS_GROUP_BRAINPOOLP384R1_TLS13,
   TLS_GROUP_BRAINPOOLP512R1_TLS13,
   TLS_GROUP_BRAINPOOLP256R1,
   TLS_GROUP_BRAINPOOLP384R1,
   TLS_GROUP_BRAINPOOLP512R1,
   TLS_GROUP_FFDHE2048,
   TLS_GROUP_FFDHE3072,
   TLS_GROUP_FFDHE4096,
   TLS_GROUP_FFDHE6144,
   TLS_GROUP_FFDHE8192
};


/**
 * @brief Format SupportedVersions extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the SupportedVersions extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientSupportedVersionsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_2 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //In TLS 1.2, the client can indicate its version preferences in the
   //SupportedVersions extension, in preference to the legacy_version field
   //of the ClientHello
   if(context->versionMax >= TLS_VERSION_1_2)
   {
      TlsExtension *extension;
      TlsSupportedVersionList *supportedVersionList;

      //Add the SupportedVersions extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SUPPORTED_VERSIONS);

      //Point to the extension data field
      supportedVersionList = (TlsSupportedVersionList *) extension->value;

      //The extension contains a list of supported versions in preference
      //order, with the most preferred version first
      n = 0;

#if (DTLS_SUPPORT == ENABLED)
      //DTLS protocol?
      if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_DATAGRAM)
      {
         //Check whether DTLS 1.2 is supported
         if(context->versionMax >= TLS_VERSION_1_2 &&
            context->versionMin <= TLS_VERSION_1_2)
         {
            supportedVersionList->value[n++] = HTONS(DTLS_VERSION_1_2);
         }

         //Check whether DTLS 1.0 is supported
         if(context->versionMax >= TLS_VERSION_1_1 &&
            context->versionMin <= TLS_VERSION_1_1)
         {
            supportedVersionList->value[n++] = HTONS(DTLS_VERSION_1_0);
         }
      }
      else
#endif
      //TLS protocol?
      {
         //Check whether TLS 1.3 is supported
         if(context->versionMax >= TLS_VERSION_1_3 &&
            context->versionMin <= TLS_VERSION_1_3)
         {
            supportedVersionList->value[n++] = HTONS(TLS_VERSION_1_3);
         }

         //Check whether TLS 1.2 is supported
         if(context->versionMax >= TLS_VERSION_1_2 &&
            context->versionMin <= TLS_VERSION_1_2)
         {
            supportedVersionList->value[n++] = HTONS(TLS_VERSION_1_2);
         }

         //Check whether TLS 1.1 is supported
         if(context->versionMax >= TLS_VERSION_1_1 &&
            context->versionMin <= TLS_VERSION_1_1)
         {
            supportedVersionList->value[n++] = HTONS(TLS_VERSION_1_1);
         }

         //Check whether TLS 1.0 is supported
         if(context->versionMax >= TLS_VERSION_1_0 &&
            context->versionMin <= TLS_VERSION_1_0)
         {
            supportedVersionList->value[n++] = HTONS(TLS_VERSION_1_0);
         }
      }

      //Compute the length, in bytes, of the list
      n *= sizeof(uint16_t);
      //Fix the length of the list
      supportedVersionList->length = (uint8_t) n;

      //Consider the length field that precedes the list
      n += sizeof(TlsSupportedVersionList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the SupportedVersions extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SNI extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ServerName extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientSniExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_SNI_SUPPORT == ENABLED)
   //In order to provide the server name, clients may include a ServerName
   //extension
   if(context->serverName != NULL)
   {
      //Determine the length of the server name
      n = osStrlen(context->serverName);

      //The server name must be a valid DNS hostname
      if(tlsCheckDnsHostname(context->serverName, n))
      {
         TlsExtension *extension;
         TlsServerNameList *serverNameList;
         TlsServerName *serverName;

         //Add SNI (Server Name Indication) extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_SERVER_NAME);

         //Point to the list of server names
         serverNameList = (TlsServerNameList *) extension->value;
         //In practice, current client implementations only send one name
         serverName = (TlsServerName *) serverNameList->value;

         //Fill in the type and the length fields
         serverName->type = TLS_NAME_TYPE_HOSTNAME;
         serverName->length = htons(n);
         //Copy server name
         osMemcpy(serverName->hostname, context->serverName, n);

         //Compute the length, in byte, of the structure
         n += sizeof(TlsServerName);
         //Fix the length of the list
         serverNameList->length = htons(n);

         //Consider the 2-byte length field that precedes the list
         n += sizeof(TlsServerNameList);
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the ServerName extension
         n += sizeof(TlsExtension);
      }
      else
      {
         //The server name is not a valid DNS hostname
         n = 0;
      }
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format MaxFragmentLength extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the MaxFragmentLength extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientMaxFragLenExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //In order to negotiate smaller maximum fragment lengths, clients may
   //include a MaxFragmentLength extension
   if(context->maxFragLen == 512 || context->maxFragLen == 1024 ||
      context->maxFragLen == 2048 || context->maxFragLen == 4096)
   {
      TlsExtension *extension;

      //Add the MaxFragmentLength extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_MAX_FRAGMENT_LENGTH);

      //Set the maximum fragment length
      switch(context->maxFragLen)
      {
      case 512:
         extension->value[0] = TLS_MAX_FRAGMENT_LENGTH_512;
         break;
      case 1024:
         extension->value[0] = TLS_MAX_FRAGMENT_LENGTH_1024;
         break;
      case 2048:
         extension->value[0] = TLS_MAX_FRAGMENT_LENGTH_2048;
         break;
      default:
         extension->value[0] = TLS_MAX_FRAGMENT_LENGTH_4096;
         break;
      }

      //The extension data field contains a single byte
      n = sizeof(uint8_t);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the MaxFragmentLength extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RecordSizeLimit extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the RecordSizeLimit extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientRecordSizeLimitExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   size_t recordSizeLimit;
   TlsExtension *extension;

   //Add the RecordSizeLimit extension
   extension = (TlsExtension *) p;
   //Type of the extension
   extension->type = HTONS(TLS_EXT_RECORD_SIZE_LIMIT);

   //An endpoint must not send a value higher than the protocol-defined
   //maximum record size (refer to RFC 8449, section 4)
   recordSizeLimit = MIN(context->rxBufferMaxLen, TLS_MAX_RECORD_LENGTH);

   //Check whether TLS 1.3 is supported
   if(context->versionMax >= TLS_VERSION_1_3 &&
      context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
   {
      //The value includes the content type and padding added in TLS 1.3
      recordSizeLimit++;
   }

   //The value of RecordSizeLimit is the maximum size of record in octets
   //that the endpoint is willing to receive
   STORE16BE(recordSizeLimit, extension->value);

   //The extension data field contains a 16-bit unsigned integer
   n = sizeof(uint16_t);
   //Fix the length of the extension
   extension->length = htons(n);

   //Compute the length, in bytes, of the RecordSizeLimit extension
   n += sizeof(TlsExtension);
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SupportedGroups extension
 * @param[in] context Pointer to the TLS context
 * @param[in] cipherSuiteTypes Types of cipher suites proposed by the client
 * @param[in] p Output stream where to write the SupportedGroups extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatSupportedGroupsExtension(TlsContext *context,
   uint_t cipherSuiteTypes, uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_ECDH_SUPPORT == ENABLED || TLS_FFDHE_SUPPORT == ENABLED)
   uint_t i;
   uint_t numSupportedGroups;
   const uint16_t *supportedGroups;
   TlsExtension *extension;
   TlsSupportedGroupList *supportedGroupList;

   //Add the SupportedGroups extension
   extension = (TlsExtension *) p;
   //Type of the extension
   extension->type = HTONS(TLS_EXT_SUPPORTED_GROUPS);

   //Point to the list of supported groups
   supportedGroupList = (TlsSupportedGroupList *) extension->value;
   //The groups are ordered according to client's preferences
   n = 0;

   //Any preferred ECDHE or FFDHE groups?
   if(context->numSupportedGroups > 0)
   {
      //Point to the list of preferred named groups
      supportedGroups = context->supportedGroups;
      numSupportedGroups = context->numSupportedGroups;
   }
   else
   {
      //Point to the list of default named groups
      supportedGroups = tlsSupportedGroups;
      numSupportedGroups = arraysize(tlsSupportedGroups);
   }

   //Loop through the list of named groups
   for(i = 0; i < numSupportedGroups; i++)
   {
#if (TLS_ECDH_SUPPORT == ENABLED)
      //Elliptic curve group?
      if(tlsGetCurveInfo(context, supportedGroups[i]) != NULL)
      {
         //Any ECC cipher suite proposed by the client?
         if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_ECC) != 0 ||
            (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
         {
            //Add the current named group to the list
            supportedGroupList->value[n++] = htons(supportedGroups[i]);
         }
      }
      else
#endif
#if (TLS_FFDHE_SUPPORT == ENABLED)
      //Finite field group?
      if(tlsGetFfdheGroup(context, supportedGroups[i]) != NULL)
      {
         //Any FFDHE cipher suite proposed by the client?
         if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_FFDHE) != 0 ||
            (cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_TLS13) != 0)
         {
            //Add the current named group to the list
            supportedGroupList->value[n++] = htons(supportedGroups[i]);
         }
      }
      else
#endif
      //Unknown group?
      {
         //Discard current named group
      }
   }

   //If the client supports and wants ECDHE and FFDHE key exchanges, it must
   //use a single SupportedGroups extension to include all supported groups
   //(both ECDHE and FFDHE groups)
   if(n != 0)
   {
      //Compute the length, in bytes, of the list
      n *= 2;
      //Fix the length of the list
      supportedGroupList->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsSupportedGroupList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the SupportedGroups extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format EcPointFormats extension
 * @param[in] context Pointer to the TLS context
 * @param[in] cipherSuiteTypes Types of cipher suites proposed by the client
 * @param[in] p Output stream where to write the EcPointFormats extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientEcPointFormatsExtension(TlsContext *context,
   uint_t cipherSuiteTypes, uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.3 has removed point format negotiation in favor of a single point
   //format for each curve (refer to RFC 8446, section 1.2)
   if(context->versionMin <= TLS_VERSION_1_2)
   {
#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
      //A client that proposes ECC cipher suites in its ClientHello message
      //should send the EcPointFormats extension
      if((cipherSuiteTypes & TLS_CIPHER_SUITE_TYPE_ECC) != 0)
      {
         TlsExtension *extension;
         TlsEcPointFormatList *ecPointFormatList;

         //Add the EcPointFormats extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_EC_POINT_FORMATS);

         //Point to the list of supported EC point formats
         ecPointFormatList = (TlsEcPointFormatList *) extension->value;
         //Items in the list are ordered according to client's preferences
         n = 0;

         //The client can parse only the uncompressed point format...
         ecPointFormatList->value[n++] = TLS_EC_POINT_FORMAT_UNCOMPRESSED;
         //Fix the length of the list
         ecPointFormatList->length = (uint8_t) n;

         //Consider the length field that precedes the list
         n += sizeof(TlsEcPointFormatList);
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the EcPointFormats extension
         n += sizeof(TlsExtension);
      }
#endif
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ALPN extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ALPN extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientAlpnExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_ALPN_SUPPORT == ENABLED)
   //The ALPN extension contains the list of protocols advertised by the
   //client, in descending order of preference
   if(context->protocolList != NULL)
   {
      uint_t i;
      uint_t j;
      TlsExtension *extension;
      TlsProtocolName *protocolName;
      TlsProtocolNameList *protocolNameList;

      //Add ALPN (Application-Layer Protocol Negotiation) extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_ALPN);

      //Point to the list of protocol names
      protocolNameList = (TlsProtocolNameList *) extension->value;

      //Move back to the beginning of the list
      i = 0;
      j = 0;
      n = 0;

      //Parse the list of supported protocols
      do
      {
         //Delimiter character found?
         if(context->protocolList[i] == ',' || context->protocolList[i] == '\0')
         {
            //Discard empty tokens
            if((i - j) > 0)
            {
               //Point to the protocol name
               protocolName = (TlsProtocolName *) (protocolNameList->value + n);

               //Fill in the length field
               protocolName->length = i - j;
               //Copy protocol name
               osMemcpy(protocolName->value, context->protocolList + j, i - j);

               //Adjust the length of the list
               n += sizeof(TlsProtocolName) + i - j;
            }

            //Move to the next token
            j = i + 1;
         }

         //Loop until the NULL character is reached
      } while(context->protocolList[i++] != '\0');

      //Fix the length of the list
      protocolNameList->length = htons(n);

      //Consider the 2-byte length field that precedes the list
      n += sizeof(TlsProtocolNameList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the ALPN extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ClientCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ClientCertType extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientCertTypeListExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   TlsExtension *extension;
   TlsCertTypeList *clientCertTypeList;

   //Add the ClientCertType extension
   extension = (TlsExtension *) p;
   //Type of the extension
   extension->type = HTONS(TLS_EXT_CLIENT_CERT_TYPE);

   //The ClientCertType extension in the ClientHello indicates the certificate
   //types the client is able to provide to the server, when requested using a
   //CertificateRequest message
   clientCertTypeList = (TlsCertTypeList *) extension->value;

   //The ClientCertType extension carries a list of supported certificate
   //types, sorted by client preference
   n = 0;

   //Raw public key type
   clientCertTypeList->value[n++] = TLS_CERT_FORMAT_RAW_PUBLIC_KEY;
   //X.509 certificate type
   clientCertTypeList->value[n++] = TLS_CERT_FORMAT_X509;

   //Fix the length of the list
   clientCertTypeList->length = (uint8_t) n;

   //Consider the length field that precedes the list
   n += sizeof(TlsCertTypeList);
   //Fix the length of the extension
   extension->length = htons(n);

   //Compute the length, in bytes, of the ClientCertType extension
   n += sizeof(TlsExtension);
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ServerCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ServerCertType extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerCertTypeListExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //Ensure the client is able to process raw public keys
   if(context->rpkVerifyCallback != NULL)
   {
      TlsExtension *extension;
      TlsCertTypeList *serverCertTypeList;

      //Add the ServerCertType extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SERVER_CERT_TYPE);

      //The ServerCertType extension in the ClientHello indicates the types of
      //certificates the client is able to process when provided by the server
      //in a subsequent certificate payload
      serverCertTypeList = (TlsCertTypeList *) extension->value;

      //The ServerCertType extension carries a list of supported certificate
      //types, sorted by client preference
      n = 0;

      //Raw public key type
      serverCertTypeList->value[n++] = TLS_CERT_FORMAT_RAW_PUBLIC_KEY;
      //X.509 certificate type
      serverCertTypeList->value[n++] = TLS_CERT_FORMAT_X509;

      //Fix the length of the list
      serverCertTypeList->length = (uint8_t) n;

      //Consider the length field that precedes the list
      n += sizeof(TlsCertTypeList);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the ServerCertType extension
      n += sizeof(TlsExtension);
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ExtendedMasterSecret extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ExtendedMasterSecret extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientEmsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Implementations which support both TLS 1.3 and earlier versions should
   //indicate the use of the ExtendedMasterSecret extension whenever TLS 1.3
   //is used (refer to RFC 8446, appendix D)
   if(context->versionMax >= TLS_VERSION_1_0 &&
      context->versionMin <= TLS_VERSION_1_2)
   {
#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      TlsExtension *extension;

      //Add the ExtendedMasterSecret extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_EXTENDED_MASTER_SECRET);

      //The extension data field of this extension is empty
      extension->length = HTONS(0);

      //Compute the length, in bytes, of the ExtendedMasterSecret extension
      n = sizeof(TlsExtension);
#endif
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SessionTicket extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the SessionTicket extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientSessionTicketExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //In versions of TLS prior to TLS 1.3, the SessionTicket extension is used
   //to resume a TLS session without requiring session-specific state at the
   //TLS server
   if(context->versionMin <= TLS_VERSION_1_2)
   {
#if (TLS_TICKET_SUPPORT == ENABLED)
      //Check whether session ticket mechanism is enabled
      if(context->sessionTicketEnabled)
      {
         TlsExtension *extension;

         //Add the SessionTicket extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_SESSION_TICKET);

         //Valid ticket?
         if(tlsIsTicketValid(context))
         {
            //If the client possesses a ticket that it wants to use to resume
            //a session, then it includes the ticket in the SessionTicket
            //extension in the ClientHello
            osMemcpy(extension->value, context->ticket, context->ticketLen);

            //The extension_data field of SessionTicket extension contains the
            //ticket
            n = context->ticketLen;
         }
         else
         {
            //If the client does not have a ticket and is prepared to receive
            //one in the NewSessionTicket handshake message, then it must
            //include a zero-length ticket in the SessionTicket extension
            n = 0;
         }

         //Set the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the SessionTicket extension
         n += sizeof(TlsExtension);
      }
#endif
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format RenegotiationInfo extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the RenegotiationInfo extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientRenegoInfoExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.3 forbids renegotiation
   if(context->versionMin <= TLS_VERSION_1_2)
   {
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      //Check whether secure renegotiation is enabled
      if(context->secureRenegoEnabled)
      {
         //During secure renegotiation, the client must include the
         //RenegotiationInfo extension containing the saved client_verify_data
         if(context->secureRenegoFlag)
         {
            TlsExtension *extension;
            TlsRenegoInfo *renegoInfo;

            //Determine the length of the verify data
            n = context->clientVerifyDataLen;

            //Add the RenegotiationInfo extension
            extension = (TlsExtension *) p;
            //Type of the extension
            extension->type = HTONS(TLS_EXT_RENEGOTIATION_INFO);

            //Point to the renegotiated_connection field
            renegoInfo = (TlsRenegoInfo *) extension->value;
            //Set the length of the verify data
            renegoInfo->length = (uint8_t) n;

            //Copy the verify data from the Finished message sent by the client
            //on the immediately previous handshake
            osMemcpy(renegoInfo->value, context->clientVerifyData, n);

            //Consider the length field that precedes the renegotiated_connection
            //field
            n += sizeof(TlsRenegoInfo);
            //Fix the length of the extension
            extension->length = htons(n);

            //Compute the length, in bytes, of the RenegotiationInfo extension
            n += sizeof(TlsExtension);
         }
      }
#endif
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format ClientHello Padding extension
 * @param[in] context Pointer to the TLS context
 * @param[in] clientHelloLen Actual length of the ClientHello message
 * @param[in] p Output stream where to write the ClientHello Padding extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientHelloPaddingExtension(TlsContext *context,
   size_t clientHelloLen, uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_CLIENT_HELLO_PADDING_SUPPORT == ENABLED)
   //TLS protocol?
   if(context->transportProtocol == TLS_TRANSPORT_PROTOCOL_STREAM)
   {
      TlsExtension *extension;

      //After building a ClientHello as normal, the client can add four bytes
      //to the length and test whether the resulting length falls into the
      //range 256 to 511 (refer to RFC 7685, section 4)
      clientHelloLen += sizeof(TlsHandshake);

      //Check the resulting length
      if(clientHelloLen >= 256 && clientHelloLen < 512)
      {
         //The ClientHello Padding extension will be added in order to push
         //the length to (at least) 512 bytes
         extension = (TlsExtension *) p;

         //Type of the extension
         extension->type = HTONS(TLS_EXT_PADDING);

         //Calculate the length of the padding
         if((clientHelloLen + sizeof(TlsExtension)) < 512)
         {
            n = 512 - sizeof(TlsExtension) - clientHelloLen;
         }
         else
         {
            n = 0;
         }

         //The padding string consists of an arbitrary number of zero bytes
         osMemset(extension->value, 0, n);
         //Set the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the padding extension
         n += sizeof(TlsExtension);
      }
   }
#endif

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SNI extension
 * @param[in] context Pointer to the TLS context
 * @param[in] serverNameList Pointer to the ServerName extension
 * @return Error code
 **/

error_t tlsParseServerSniExtension(TlsContext *context,
   const TlsServerNameList *serverNameList)
{
#if (TLS_SNI_SUPPORT == ENABLED)
   //SNI extension found?
   if(serverNameList != NULL)
   {
      //If a client receives an extension type in the ServerHello that it did
      //not request in the associated ClientHello, it must abort the handshake
      //with an unsupported_extension fatal alert
      if(context->serverName == NULL)
         return ERROR_UNSUPPORTED_EXTENSION;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse MaxFragmentLength extension
 * @param[in] context Pointer to the TLS context
 * @param[in] maxFragLen Pointer to the MaxFragmentLength extension
 * @return Error code
 **/

error_t tlsParseServerMaxFragLenExtension(TlsContext *context,
   const TlsExtension *maxFragLen)
{
#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //MaxFragmentLength extension found?
   if(maxFragLen != NULL)
   {
      size_t n;

      //Retrieve the value advertised by the server
      switch(maxFragLen->value[0])
      {
      case TLS_MAX_FRAGMENT_LENGTH_512:
         n = 512;
         break;
      case TLS_MAX_FRAGMENT_LENGTH_1024:
         n = 1024;
         break;
      case TLS_MAX_FRAGMENT_LENGTH_2048:
         n = 2048;
         break;
      case TLS_MAX_FRAGMENT_LENGTH_4096:
         n = 4096;
         break;
      default:
         n = 0;
         break;
      }

      //If a client receives a maximum fragment length negotiation response
      //that differs from the length it requested, it must also abort the
      //handshake with an illegal_parameter alert
      if(n != context->maxFragLen)
         return ERROR_ILLEGAL_PARAMETER;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RecordSizeLimit extension
 * @param[in] context Pointer to the TLS context
 * @param[in] recordSizeLimit Pointer to the RecordSizeLimit extension
 * @return Error code
 **/

error_t tlsParseServerRecordSizeLimitExtension(TlsContext *context,
   const TlsExtension *recordSizeLimit)
{
#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //RecordSizeLimit extension found?
   if(recordSizeLimit != NULL)
   {
      uint16_t n;

      //The value of RecordSizeLimit is the maximum size of record in octets
      //that the peer is willing to receive
      n = LOAD16BE(recordSizeLimit->value);

      //Endpoints must not send a RecordSizeLimit extension with a value
      //smaller than 64
      if(n < 64)
      {
         //An endpoint must treat receipt of a smaller value as a fatal error
         //and generate an illegal_parameter alert
         return ERROR_ILLEGAL_PARAMETER;
      }

      //TLS 1.3 currently selected?
      if(context->version == TLS_VERSION_1_3)
      {
         //The value includes the content type and padding added in TLS 1.3
         n--;
      }

      //The peer can include any limit up to the protocol-defined limit for
      //maximum record size. Even if a larger value is provided by a peer, an
      //endpoint must not send records larger than the protocol-defined limit
      context->recordSizeLimit = MIN(n, TLS_MAX_RECORD_LENGTH);

      //The RecordSizeLimit extension has been successfully negotiated
      context->recordSizeLimitExtReceived = TRUE;
   }
   else
   {
      //If this extension is not negotiated, endpoints can send records of any
      //size permitted by the protocol or other negotiated extensions
      context->recordSizeLimit = TLS_MAX_RECORD_LENGTH;

      //The RecordSizeLimit extension is not supported by the server
      context->recordSizeLimitExtReceived = FALSE;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse EcPointFormats extension
 * @param[in] context Pointer to the TLS context
 * @param[in] ecPointFormatList Pointer to the EcPointFormats extension
 * @return Error code
 **/

error_t tlsParseServerEcPointFormatsExtension(TlsContext *context,
   const TlsEcPointFormatList *ecPointFormatList)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //EcPointFormats extension found?
   if(ecPointFormatList != NULL)
   {
      uint_t i;

      //Loop through the list of supported EC point formats
      for(i = 0; i < ecPointFormatList->length; i++)
      {
         //Uncompressed point format?
         if(ecPointFormatList->value[i] == TLS_EC_POINT_FORMAT_UNCOMPRESSED)
         {
            break;
         }
      }

      //If the EcPointFormats extension is sent, it must contain the value 0
      //as one of the items in the list of point formats (refer to RFC 4492,
      //section 5.2)
      if(i >= ecPointFormatList->length)
      {
         //Report an error
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse ALPN extension
 * @param[in] context Pointer to the TLS context
 * @param[in] protocolNameList Pointer to the ALPN extension
 * @return Error code
 **/

error_t tlsParseServerAlpnExtension(TlsContext *context,
   const TlsProtocolNameList *protocolNameList)
{
#if (TLS_ALPN_SUPPORT == ENABLED)
   //ALPN extension found?
   if(protocolNameList != NULL)
   {
      size_t length;
      const TlsProtocolName *protocolName;

      //If a client receives an extension type in the ServerHello that it
      //did not request in the associated ClientHello, it must abort the
      //handshake with an unsupported_extension fatal alert
      if(context->protocolList == NULL)
         return ERROR_UNSUPPORTED_EXTENSION;

      //Retrieve the length of the list
      length = ntohs(protocolNameList->length);

      //The list must not be be empty
      if(length == 0)
         return ERROR_DECODING_FAILED;

      //Point to the selected protocol
      protocolName = (TlsProtocolName *) protocolNameList->value;

      //The list must contain exactly one protocol name
      if(length < sizeof(TlsProtocolName))
         return ERROR_DECODING_FAILED;
      if(length != (sizeof(TlsProtocolName) + protocolName->length))
         return ERROR_DECODING_FAILED;

      //Retrieve the length of the protocol name
      length -= sizeof(TlsProtocolName);

      //Empty strings must not be included in the list
      if(length == 0)
         return ERROR_DECODING_FAILED;

      //Check whether the protocol is supported by the client
      if(!tlsIsAlpnProtocolSupported(context, protocolName->value, length))
      {
         //Report an error if unknown ALPN protocols are disallowed
         if(!context->unknownProtocolsAllowed)
            return ERROR_ILLEGAL_PARAMETER;
      }

      //Sanity check
      if(context->selectedProtocol != NULL)
      {
         //Release memory
         tlsFreeMem(context->selectedProtocol);
         context->selectedProtocol = NULL;
      }

      //Allocate a memory block to hold the protocol name
      context->selectedProtocol = tlsAllocMem(length + 1);
      //Failed to allocate memory?
      if(context->selectedProtocol == NULL)
         return ERROR_OUT_OF_MEMORY;

      //Save protocol name
      osMemcpy(context->selectedProtocol, protocolName->value, length);
      //Properly terminate the string with a NULL character
      context->selectedProtocol[length] = '\0';
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ClientCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] clientCertType Pointer to the ClientCertType extension
 * @return Error code
 **/

error_t tlsParseClientCertTypeExtension(TlsContext *context,
   const TlsExtension *clientCertType)
{
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //ClientCertType extension found?
   if(clientCertType != NULL)
   {
      //The value conveyed in the extension must be selected from one of the
      //values provided in the ClientCertType extension sent in the ClientHello
      if(clientCertType->value[0] != TLS_CERT_FORMAT_X509 &&
         clientCertType->value[0] != TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
      {
         return ERROR_ILLEGAL_PARAMETER;
      }

      //The ClientCertType extension in the ServerHello indicates the type
      //of certificates the client is requested to provide in a subsequent
      //certificate payload
      context->certFormat = (TlsCertificateFormat) clientCertType->value[0];
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ServerCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] serverCertType Pointer to the ServerCertType extension
 * @return Error code
 **/

error_t tlsParseServerCertTypeExtension(TlsContext *context,
   const TlsExtension *serverCertType)
{
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //ServerCertType extension found?
   if(serverCertType != NULL)
   {
      //If a client receives an extension type in the ServerHello that it did
      //not request in the associated ClientHello, it must abort the handshake
      //with an unsupported_extension fatal alert
      if(context->rpkVerifyCallback == NULL &&
         serverCertType->value[0] != TLS_CERT_FORMAT_X509)
      {
         return ERROR_UNSUPPORTED_EXTENSION;
      }

      //The value conveyed in the extension must be selected from one of the
      //values provided in the ServerCertType extension sent in the ClientHello
      if(serverCertType->value[0] != TLS_CERT_FORMAT_X509 &&
         serverCertType->value[0] != TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
      {
         return ERROR_ILLEGAL_PARAMETER;
      }

      //With the ServerCertType extension in the ServerHello, the TLS server
      //indicates the certificate type carried in the certificate payload
      context->peerCertFormat = (TlsCertificateFormat) serverCertType->value[0];
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ExtendedMasterSecret extension
 * @param[in] context Pointer to the TLS context
 * @param[in] extendedMasterSecret Pointer to the ExtendedMasterSecret extension
 * @return Error code
 **/

error_t tlsParseServerEmsExtension(TlsContext *context,
   const TlsExtension *extendedMasterSecret)
{
#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //ExtendedMasterSecret extension found?
   if(extendedMasterSecret != NULL)
   {
      //Abbreviated handshake?
      if(context->resume)
      {
         //If the original session did not use the ExtendedMasterSecret
         //extension but the new ServerHello contains the extension, the
         //client must abort the handshake
         if(!context->emsExtReceived)
            return ERROR_HANDSHAKE_FAILED;
      }

      //A valid ExtendedMasterSecret extension has been received
      context->emsExtReceived = TRUE;
   }
   else
   {
      //Abbreviated handshake?
      if(context->resume)
      {
         //If the original session used the ExtendedMasterSecret extension
         //but the new ServerHello does not contain the extension, the client
         //must abort the handshake
         if(context->emsExtReceived)
            return ERROR_HANDSHAKE_FAILED;
      }

      //The ServerHello does not contain any ExtendedMasterSecret extension
      context->emsExtReceived = FALSE;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SessionTicket extension
 * @param[in] context Pointer to the TLS context
 * @param[in] sessionTicket Pointer to the SessionTicket extension
 * @return Error code
 **/

error_t tlsParseServerSessionTicketExtension(TlsContext *context,
   const TlsExtension *sessionTicket)
{
#if (TLS_TICKET_SUPPORT == ENABLED)
   //SessionTicket extension found?
   if(sessionTicket != NULL)
   {
      //If a client receives an extension type in the ServerHello that it did
      //not request in the associated ClientHello, it must abort the handshake
      //with an unsupported_extension fatal alert
      if(!context->sessionTicketEnabled)
         return ERROR_UNSUPPORTED_EXTENSION;

      //The server uses the SessionTicket extension to indicate to the client
      //that it will send a new session ticket using the NewSessionTicket
      //handshake message
      context->sessionTicketExtReceived = TRUE;
   }
   else
   {
      //The ServerHello does not contain any SessionTicket extension
      context->sessionTicketExtReceived = FALSE;
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse RenegotiationInfo extension
 * @param[in] context Pointer to the TLS context
 * @param[in] extensions ServerHello extensions offered by the server
 * @return Error code
 **/

error_t tlsParseServerRenegoInfoExtension(TlsContext *context,
   const TlsHelloExtensions *extensions)
{
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Initial handshake?
   if(context->clientVerifyDataLen == 0)
   {
      //RenegotiationInfo extension found?
      if(extensions->renegoInfo != NULL)
      {
         //If the extension is present, set the secure_renegotiation flag to TRUE
         context->secureRenegoFlag = TRUE;

         //Verify that the length of the renegotiated_connection field is zero
         if(extensions->renegoInfo->length != 0)
         {
            //If it is not, the client must abort the handshake by sending a
            //fatal handshake failure alert
            return ERROR_HANDSHAKE_FAILED;
         }
      }
      else
      {
         //If the extension is not present, the server does not support secure
         //renegotiation
         context->secureRenegoFlag = FALSE;
      }
   }
   //Secure renegotiation?
   else
   {
      //RenegotiationInfo extension found?
      if(extensions->renegoInfo != NULL)
      {
         //Check the length of the renegotiated_connection field
         if(extensions->renegoInfo->length != (context->clientVerifyDataLen +
            context->serverVerifyDataLen))
         {
            //The client must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }

         //The client must verify that the first half of the field is equal to
         //the saved client_verify_data value
         if(osMemcmp(extensions->renegoInfo->value, context->clientVerifyData,
            context->clientVerifyDataLen))
         {
            //If it is not, the client must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }

         //The client must verify that the second half of the field is equal to
         //the saved server_verify_data value
         if(osMemcmp(extensions->renegoInfo->value + context->clientVerifyDataLen,
            context->serverVerifyData, context->serverVerifyDataLen))
         {
            //If it is not, the client must abort the handshake
            return ERROR_HANDSHAKE_FAILED;
         }

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
         //ExtendedMasterSecret extension found?
         if(extensions->extendedMasterSecret != NULL)
         {
            //If the initial handshake did not use the ExtendedMasterSecret
            //extension but the new ServerHello contains the extension, the
            //client must abort the handshake
            if(!context->emsExtReceived)
               return ERROR_HANDSHAKE_FAILED;
         }
         else
         {
            //If the initial handshake used the ExtendedMasterSecret extension
            //but the new ServerHello does not contain the extension, the
            //client must abort the handshake
            if(context->emsExtReceived)
               return ERROR_HANDSHAKE_FAILED;
         }
#endif
      }
      else
      {
         //If the RenegotiationInfo extension is not present, the client
         //must abort the handshake
         return ERROR_HANDSHAKE_FAILED;
      }
   }
#endif

   //Successful processing
   return NO_ERROR;
}

#endif
