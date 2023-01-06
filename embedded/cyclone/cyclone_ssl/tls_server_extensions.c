/**
 * @file tls_server_extensions.c
 * @brief Formatting and parsing of extensions (TLS server)
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
#include "tls_server_extensions.h"
#include "tls_extensions.h"
#include "tls_misc.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED && TLS_SERVER_SUPPORT == ENABLED)


/**
 * @brief Format SNI extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ServerName extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerSniExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_SNI_SUPPORT == ENABLED)
   //A server that receives a ClientHello containing the SNI extension may use
   //the information contained in the extension to guide its selection of an
   //appropriate certificate to return to the client. In this event, the server
   //shall include an extension of type SNI in the ServerHello
   if(context->serverName != NULL)
   {
      //Full handshake?
      if(!context->resume)
      {
         TlsExtension *extension;

         //Add SNI (Server Name Indication) extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_SERVER_NAME);

         //The extension data field of this extension shall be empty (refer to
         //RFC 6066, section 3)
         extension->length = HTONS(0);

         //Compute the length, in bytes, of the ServerName extension
         n = sizeof(TlsExtension);
      }
      else
      {
         //When resuming a session, the server must not include a ServerName
         //extension in the ServerHello (refer to RFC 6066, section 3)
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

error_t tlsFormatServerMaxFragLenExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //An extension type must not appear in the ServerHello unless the same
   //extension type appeared in the corresponding ClientHello
   if(context->maxFragLenExtReceived)
   {
      //Servers that receive an ClientHello containing a MaxFragmentLength
      //extension may accept the requested maximum fragment length by including
      //an extension of type MaxFragmentLength in the ServerHello
      if(context->maxFragLen == 512 || context->maxFragLen == 1024 ||
         context->maxFragLen == 2048 || context->maxFragLen == 4096)
      {
         TlsExtension *extension;

         //Add the MaxFragmentLength extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_MAX_FRAGMENT_LENGTH);

         //The data field of this extension shall contain a MaxFragmentLength
         //whose value is the same as the requested maximum fragment length
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

error_t tlsFormatServerRecordSizeLimitExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //An extension type must not appear in the ServerHello unless the same
   //extension type appeared in the corresponding ClientHello
   if(context->recordSizeLimitExtReceived)
   {
      size_t recordSizeLimit;
      TlsExtension *extension;

      //Add the RecordSizeLimit extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_RECORD_SIZE_LIMIT);

      //An endpoint must not send a value higher than the protocol-defined
      //maximum record size (refer to RFC 8449, section 4)
      recordSizeLimit = MIN(context->rxBufferMaxLen, TLS_MAX_RECORD_LENGTH);

      //TLS 1.3 currently selected?
      if(context->version == TLS_VERSION_1_3)
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
 * @param[in] p Output stream where to write the EcPointFormats extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatServerEcPointFormatsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //TLS 1.3 has removed point format negotiation in favor of a single point
   //format for each curve (refer to RFC 8446, section 1.2)
   if(context->version <= TLS_VERSION_1_2)
   {
#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
      //An extension type must not appear in the ServerHello unless the same
      //extension type appeared in the corresponding ClientHello
      if(context->ecPointFormatsExtReceived)
      {
         uint16_t identifier;

         //Retrieve the selected cipher suite
         identifier = context->cipherSuite.identifier;

         //A server that selects an ECC cipher suite in response to a ClientHello
         //message including an EcPointFormats extension appends this extension
         //to its ServerHello message
         if((tlsGetCipherSuiteType(identifier) & TLS_CIPHER_SUITE_TYPE_ECC) != 0)
         {
            TlsExtension *extension;
            TlsEcPointFormatList *ecPointFormatList;

            //Add the EcPointFormats extension
            extension = (TlsExtension *) p;
            //Type of the extension
            extension->type = HTONS(TLS_EXT_EC_POINT_FORMATS);

            //Point to the list of supported EC point formats
            ecPointFormatList = (TlsEcPointFormatList *) extension->value;
            //Items in the list are ordered according to server's preferences
            n = 0;

            //The server can parse only the uncompressed point format...
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

error_t tlsFormatServerAlpnExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_ALPN_SUPPORT == ENABLED)
   //The ALPN extension may be returned to the client within the extended
   //ServerHello message
   if(context->selectedProtocol != NULL)
   {
      //Empty strings must not be included
      if(context->selectedProtocol[0] != '\0')
      {
         TlsExtension *extension;
         TlsProtocolName *protocolName;
         TlsProtocolNameList *protocolNameList;

         //Add ALPN (Application-Layer Protocol Negotiation) extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_ALPN);

         //Point to the list of protocol names
         protocolNameList = (TlsProtocolNameList *) extension->value;
         //The list must contain exactly one protocol name
         protocolName = (TlsProtocolName *) protocolNameList->value;

         //Retrieve the length of the protocol name
         n = osStrlen(context->selectedProtocol);

         //Fill in the length field
         protocolName->length = (uint8_t) n;
         //Copy protocol name
         osMemcpy(protocolName->value, context->selectedProtocol, n);

         //Adjust the length of the list
         n += sizeof(TlsProtocolName);
         //Fix the length of the list
         protocolNameList->length = htons(n);

         //Consider the 2-byte length field that precedes the list
         n += sizeof(TlsProtocolNameList);
         //Fix the length of the extension
         extension->length = htons(n);

         //Compute the length, in bytes, of the ALPN extension
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
 * @brief Format ClientCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] p Output stream where to write the ClientCertType extension
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t tlsFormatClientCertTypeExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //An extension type must not appear in the ServerHello unless the same
   //extension type appeared in the corresponding ClientHello
   if(context->clientCertTypeExtReceived)
   {
      TlsExtension *extension;

      //Add the ClientCertType extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_CLIENT_CERT_TYPE);

      //The ClientCertType extension in the ServerHello indicates the type
      //of certificates the client is requested to provide in a subsequent
      //certificate payload
      extension->value[0] = context->peerCertFormat;

      //The extension data field contains a single byte
      n = sizeof(uint8_t);
      //Fix the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the ClientCertType extension
      n += sizeof(TlsExtension);
   }
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

error_t tlsFormatServerCertTypeExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //An extension type must not appear in the ServerHello unless the same
   //extension type appeared in the corresponding ClientHello
   if(context->serverCertTypeExtReceived)
   {
      TlsExtension *extension;

      //Add the ServerCertType extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SERVER_CERT_TYPE);

      //With the ServerCertType extension in the ServerHello, the TLS server
      //indicates the certificate type carried in the certificate payload
      extension->value[0] = context->certFormat;

      //The extension data field contains a single byte
      n = sizeof(uint8_t);
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

error_t tlsFormatServerEmsExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //If the server receives a ClientHello without the ExtendedMasterSecret
   //extension, then it must not include the extension in the ServerHello
   if(context->emsExtReceived)
   {
      TlsExtension *extension;

      //Add the ExtendedMasterSecret extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_EXTENDED_MASTER_SECRET);

      //The extension data field of this extension is empty
      extension->length = HTONS(0);

      //Compute the length, in bytes, of the ExtendedMasterSecret extension
      n = sizeof(TlsExtension);
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

error_t tlsFormatServerSessionTicketExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_TICKET_SUPPORT == ENABLED)
   //The server must not send this extension if it does not receive one in the
   //ClientHello (refer to RFC 5077, section 3.2)
   if(context->sessionTicketExtSent)
   {
      TlsExtension *extension;

      //Add the SessionTicket extension
      extension = (TlsExtension *) p;
      //Type of the extension
      extension->type = HTONS(TLS_EXT_SESSION_TICKET);

      //The server uses a zero-length SessionTicket extension to indicate to the
      //client that it will send a new session ticket using the NewSessionTicket
      //handshake message
      n = 0;

      //Set the length of the extension
      extension->length = htons(n);

      //Compute the length, in bytes, of the SessionTicket extension
      n += sizeof(TlsExtension);
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

error_t tlsFormatServerRenegoInfoExtension(TlsContext *context,
   uint8_t *p, size_t *written)
{
   size_t n = 0;

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //Check whether secure renegotiation is enabled
   if(context->secureRenegoEnabled)
   {
      //During secure renegotiation, the server must include a renegotiation_info
      //extension containing the saved client_verify_data and server_verify_data
      if(context->secureRenegoFlag)
      {
         TlsExtension *extension;
         TlsRenegoInfo *renegoInfo;

         //Determine the length of the renegotiated_connection field
         n = context->clientVerifyDataLen + context->serverVerifyDataLen;

         //Add the RenegotiationInfo extension
         extension = (TlsExtension *) p;
         //Type of the extension
         extension->type = HTONS(TLS_EXT_RENEGOTIATION_INFO);

         //Point to the renegotiated_connection field
         renegoInfo = (TlsRenegoInfo *) extension->value;
         //Set the length of the verify data
         renegoInfo->length = (uint8_t) n;

         //Copy the saved client_verify_data
         osMemcpy(renegoInfo->value, context->clientVerifyData,
            context->clientVerifyDataLen);

         //Copy the saved client_verify_data
         osMemcpy(renegoInfo->value + context->clientVerifyDataLen,
            context->serverVerifyData, context->serverVerifyDataLen);

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

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SupportedVersions extension
 * @param[in] context Pointer to the TLS context
 * @param[in] supportedVersionList Pointer to the SupportedVersions extension
 * @return Error code
 **/

error_t tlsParseClientSupportedVersionsExtension(TlsContext *context,
   const TlsSupportedVersionList *supportedVersionList)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint_t n;

   //Supported TLS versions
   const uint16_t supportedVersions[] =
   {
      TLS_VERSION_1_3,
      TLS_VERSION_1_2,
      TLS_VERSION_1_1,
      TLS_VERSION_1_0
   };

   //Initialize status code
   error = ERROR_VERSION_NOT_SUPPORTED;

   //Retrieve the number of items in the list
   n = supportedVersionList->length / sizeof(uint16_t);

   //Loop through the list of TLS versions supported by the server
   for(i = 0; i < arraysize(supportedVersions) && error; i++)
   {
      //The extension contains a list of TLS versions supported by the client
      for(j = 0; j < n && error; j++)
      {
         //Servers must only select a version of TLS present in that extension
         //and must ignore any unknown versions
         if(ntohs(supportedVersionList->value[j]) == supportedVersions[i])
         {
            //Set the TLS version to be used
            error = tlsSelectVersion(context, supportedVersions[i]);
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SNI extension
 * @param[in] context Pointer to the TLS context
 * @param[in] serverNameList Pointer to the SNI extension
 * @return Error code
 **/

error_t tlsParseClientSniExtension(TlsContext *context,
   const TlsServerNameList *serverNameList)
{
#if (TLS_SNI_SUPPORT == ENABLED)
   //SNI extension found?
   if(serverNameList != NULL)
   {
      size_t i;
      size_t n;
      size_t length;
      const TlsServerName *serverName;

      //In order to provide the server name, clients may include ServerName
      //extension
      if(context->serverName != NULL)
      {
         //Release memory
         tlsFreeMem(context->serverName);
         context->serverName = NULL;
      }

      //Retrieve the length of the list
      length = ntohs(serverNameList->length);

      //Loop through the list of server names advertised by the client
      for(i = 0; i < length; i += sizeof(TlsServerName) + n)
      {
         //Point to the current server name
         serverName = (TlsServerName *) (serverNameList->value + i);

         //Malformed extension?
         if(length < (i + sizeof(TlsServerName)))
            return ERROR_DECODING_FAILED;
         if(length < (i + sizeof(TlsServerName) + ntohs(serverName->length)))
            return ERROR_DECODING_FAILED;

         //Retrieve the length of the server name
         n = ntohs(serverName->length);

         //Empty strings must not be included in the list
         if(n == 0)
            return ERROR_DECODING_FAILED;

         //Currently, the only server names supported are DNS hostnames
         if(serverName->type == TLS_NAME_TYPE_HOSTNAME)
         {
            //The server name must be a valid DNS hostname
            if(!tlsCheckDnsHostname(serverName->hostname, n))
               return ERROR_ILLEGAL_PARAMETER;

            //The ServerNameList must not contain more than one name of the
            //same type (refer to RFC 6066, section 3)
            if(context->serverName != NULL)
               return ERROR_ILLEGAL_PARAMETER;

            //Check the length of the name
            if(n <= TLS_MAX_SERVER_NAME_LEN)
            {
               //Allocate a memory block to hold the server name
               context->serverName = tlsAllocMem(n + 1);
               //Failed to allocate memory?
               if(context->serverName == NULL)
                  return ERROR_OUT_OF_MEMORY;

               //Save server name
               osMemcpy(context->serverName, serverName->hostname, n);
               //Properly terminate the string with a NULL character
               context->serverName[n] = '\0';
            }
         }
      }
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

error_t tlsParseClientMaxFragLenExtension(TlsContext *context,
   const TlsExtension *maxFragLen)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
   //MaxFragmentLength extension found?
   if(maxFragLen != NULL)
   {
      size_t n;

      //Retrieve the value advertised by the client
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

      //Acceptable value?
      if(n > 0)
      {
         //Once a maximum fragment length has been successfully negotiated,
         //the server must immediately begin fragmenting messages (including
         //handshake messages) to ensure that no fragment larger than the
         //negotiated length is sent
         context->maxFragLen = n;
      }
      else
      {
         //If a server receives a maximum fragment length negotiation request
         //for a value other than the allowed values, it must abort the handshake
         //with an illegal_parameter alert
         error = ERROR_ILLEGAL_PARAMETER;
      }

      //The ClientHello includes a MaxFragmentLength extension
      context->maxFragLenExtReceived = TRUE;
   }
   else
   {
      //The ClientHello does not contain any MaxFragmentLength extension
      context->maxFragLenExtReceived = FALSE;
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse RecordSizeLimit extension
 * @param[in] context Pointer to the TLS context
 * @param[in] recordSizeLimit Pointer to the RecordSizeLimit extension
 * @return Error code
 **/

error_t tlsParseClientRecordSizeLimitExtension(TlsContext *context,
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

      //Initial or updated ClientHello?
      if(context->state == TLS_STATE_CLIENT_HELLO_2)
      {
         //When responding to a HelloRetryRequest, the client must send the
         //same ClientHello without modification
         if(!context->recordSizeLimitExtReceived ||
            context->recordSizeLimit != n)
         {
            return ERROR_ILLEGAL_PARAMETER;
         }
      }

      //The peer can include any limit up to the protocol-defined limit for
      //maximum record size. Even if a larger value is provided by a peer, an
      //endpoint must not send records larger than the protocol-defined limit
      context->recordSizeLimit = MIN(n, TLS_MAX_RECORD_LENGTH);

      //The ClientHello includes a RecordSizeLimit extension
      context->recordSizeLimitExtReceived = TRUE;
   }
   else
   {
      //Initial or updated ClientHello?
      if(context->state == TLS_STATE_CLIENT_HELLO_2)
      {
         //When responding to a HelloRetryRequest, the client must send the
         //same ClientHello without modification
         if(context->recordSizeLimitExtReceived)
            return ERROR_ILLEGAL_PARAMETER;
      }

      //If this extension is not negotiated, endpoints can send records of any
      //size permitted by the protocol or other negotiated extensions
      context->recordSizeLimit = TLS_MAX_RECORD_LENGTH;

      //The RecordSizeLimit extension is not supported by the client
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

error_t tlsParseClientEcPointFormatsExtension(TlsContext *context,
   const TlsEcPointFormatList *ecPointFormatList)
{
   error_t error;

#if (TLS_MAX_VERSION >= TLS_VERSION_1_0 && TLS_MIN_VERSION <= TLS_VERSION_1_2)
   //Initialize status code
   error = NO_ERROR;

#if (TLS_ECDH_ANON_KE_SUPPORT == ENABLED || TLS_ECDHE_RSA_KE_SUPPORT == ENABLED || \
   TLS_ECDHE_ECDSA_KE_SUPPORT == ENABLED || TLS_ECDHE_PSK_KE_SUPPORT == ENABLED)
   //EcPointFormats extension found?
   if(ecPointFormatList != NULL)
   {
      uint_t i;

      //The ClientHello includes a EcPointFormats extension
      context->ecPointFormatsExtReceived = TRUE;

      //Loop through the list of supported EC point formats
      for(i = 0; i < ecPointFormatList->length; i++)
      {
         //Uncompressed point format?
         if(ecPointFormatList->value[i] == TLS_EC_POINT_FORMAT_UNCOMPRESSED)
         {
            break;
         }
      }

      //The uncompressed point format must be supported by any TLS application
      //that supports this extension (refer to RFC 4492, section 5.1)
      if(i >= ecPointFormatList->length)
      {
         //Report an error
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
   else
   {
      //If no SupportedPointsFormat extension is sent, the uncompressed format
      //has to be used
      context->ecPointFormatsExtReceived = FALSE;
   }
#endif
#else
   //Not implemented
   error = ERROR_NOT_IMPLEMENTED;
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

error_t tlsParseClientAlpnExtension(TlsContext *context,
   const TlsProtocolNameList *protocolNameList)
{
#if (TLS_ALPN_SUPPORT == ENABLED)
   //The protocol identified in the ALPN extension type in the ServerHello
   //shall be definitive for the connection, until renegotiated (refer to
   //RFC 7301, section 3.2)
   if(context->selectedProtocol != NULL)
   {
      //Release memory
      tlsFreeMem(context->selectedProtocol);
      context->selectedProtocol = NULL;
   }

   //ALPN extension found?
   if(protocolNameList != NULL)
   {
      size_t i;
      size_t n;
      size_t length;
      const TlsProtocolName *protocolName;

      //Retrieve the length of the list
      length = ntohs(protocolNameList->length);

      //The list must not be be empty
      if(length == 0)
         return ERROR_DECODING_FAILED;

      //Loop through the list of protocols advertised by the client
      for(i = 0; i < length; i += sizeof(TlsProtocolName) + n)
      {
         //Point to the current protocol
         protocolName = (TlsProtocolName *) (protocolNameList->value + i);

         //Malformed extension?
         if(length < (i + sizeof(TlsProtocolName)))
            return ERROR_DECODING_FAILED;
         if(length < (i + sizeof(TlsProtocolName) + protocolName->length))
            return ERROR_DECODING_FAILED;

         //Retrieve the length of the protocol name
         n = protocolName->length;

         //Empty strings must not be included in the list
         if(n == 0)
            return ERROR_DECODING_FAILED;

         //Check whether the protocol is supported by the server
         if(tlsIsAlpnProtocolSupported(context, protocolName->value, n))
         {
            //Select the current protocol
            if(context->selectedProtocol == NULL)
            {
               //Allocate a memory block to hold the protocol name
               context->selectedProtocol = tlsAllocMem(n + 1);
               //Failed to allocate memory?
               if(context->selectedProtocol == NULL)
                  return ERROR_OUT_OF_MEMORY;

               //Save protocol name
               osMemcpy(context->selectedProtocol, protocolName->value, n);
               //Properly terminate the string with a NULL character
               context->selectedProtocol[n] = '\0';
            }
         }
      }

      //ALPN protocol selection failed?
      if(context->protocolList != NULL && context->selectedProtocol == NULL)
      {
         //Report an error if unknown ALPN protocols are disallowed
         if(!context->unknownProtocolsAllowed)
         {
            //In the event that the server supports no protocols that the
            //client advertises, then the server shall respond with a fatal
            //no_application_protocol alert
            return ERROR_NO_APPLICATION_PROTOCOL;
         }
      }
   }

   //Any registered callback?
   if(context->alpnCallback != NULL)
   {
      //Invoke user callback function
      return context->alpnCallback(context, context->selectedProtocol);
   }
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse ClientCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] clientCertTypeList Pointer to the ClientCertType extension
 * @return Error code
 **/

error_t tlsParseClientCertTypeListExtension(TlsContext *context,
   const TlsCertTypeList *clientCertTypeList)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //ClientCertType extension found?
   if(clientCertTypeList != NULL)
   {
      //If the server does not send any CertificateRequest message, then the
      //ClientCertType extension in the ServerHello must be omitted
      if(context->clientAuthMode != TLS_CLIENT_AUTH_NONE)
      {
         uint_t i;

         //The ClientCertType extension carries a list of supported certificate
         //types, sorted by client preference
         for(i = 0; i < clientCertTypeList->length; i++)
         {
            //Check certificate type
            if(clientCertTypeList->value[i] == TLS_CERT_FORMAT_X509)
            {
               //Select X.509 certificate format
               context->peerCertFormat = TLS_CERT_FORMAT_X509;
               //Exit immediately
               break;
            }
            else if(clientCertTypeList->value[i] == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
            {
               //Ensure the server is able to process raw public keys
               if(context->rpkVerifyCallback != NULL)
               {
                  //Select raw public key format
                  context->peerCertFormat = TLS_CERT_FORMAT_RAW_PUBLIC_KEY;
                  //Exit immediately
                  break;
               }
            }
            else
            {
               //Unsupported certificate type
            }
         }

         //If the server does not have any certificate type in common with the
         //client, then the server terminates the session with a fatal alert
         if(i >= clientCertTypeList->length)
         {
            //Report an error
            error = ERROR_UNSUPPORTED_CERTIFICATE;
         }

         //The ClientHello includes a ClientCertType extension
         context->clientCertTypeExtReceived = TRUE;
      }
   }
   else
   {
      //The ClientHello does not contain any ClientCertType extension
      context->clientCertTypeExtReceived = FALSE;
      //Select default certificate format
      context->peerCertFormat = TLS_CERT_FORMAT_X509;
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse ServerCertType extension
 * @param[in] context Pointer to the TLS context
 * @param[in] serverCertTypeList Pointer to the ServerCertType extension
 * @return Error code
 **/

error_t tlsParseServerCertTypeListExtension(TlsContext *context,
   const TlsCertTypeList *serverCertTypeList)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
   //ServerCertType extension found?
   if(serverCertTypeList != NULL)
   {
      uint_t i;

      //The ServerCertType extension carries a list of supported certificate
      //types, sorted by client preference
      for(i = 0; i < serverCertTypeList->length; i++)
      {
         //Check certificate type
         if(serverCertTypeList->value[i] == TLS_CERT_FORMAT_X509 ||
            serverCertTypeList->value[i] == TLS_CERT_FORMAT_RAW_PUBLIC_KEY)
         {
            //The certificate type is selected from one of the values provided
            //by the client
            context->certFormat = (TlsCertificateFormat) serverCertTypeList->value[i];

            //We are done
            break;
         }
      }

      //If the server does not have any certificate type in common with the
      //client, then the server terminates the session with a fatal alert
      if(i >= serverCertTypeList->length)
      {
         //Report an error
         error = ERROR_UNSUPPORTED_CERTIFICATE;
      }

      //The ClientHello includes a ServerCertType extension
      context->serverCertTypeExtReceived = TRUE;
   }
   else
   {
      //The ClientHello does not contain any ServerCertType extension
      context->serverCertTypeExtReceived = FALSE;
      //Select default certificate format
      context->certFormat = TLS_CERT_FORMAT_X509;
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse ExtendedMasterSecret extension
 * @param[in] context Pointer to the TLS context
 * @param[in] extendedMasterSecret Pointer to the ExtendedMasterSecret extension
 * @return Error code
 **/

error_t tlsParseClientEmsExtension(TlsContext *context,
   const TlsExtension *extendedMasterSecret)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
   //ExtendedMasterSecret extension found?
   if(extendedMasterSecret != NULL)
   {
      //Use the extended master secret computation
      context->emsExtReceived = TRUE;
   }
   else
   {
      //Abbreviated handshake?
      if(context->resume)
      {
         //If the original session used the ExtendedMasterSecret extension but
         //the new ClientHello does not contain it, the server must abort the
         //abbreviated handshake
         if(context->emsExtReceived)
         {
            //Report an error
            error = ERROR_HANDSHAKE_FAILED;
         }
      }

      //If the client and server choose to continue a full handshake without
      //the extension, they must use the standard master secret derivation
      //for the new session
      context->emsExtReceived = FALSE;
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Parse SessionTicket extension
 * @param[in] context Pointer to the TLS context
 * @param[in] sessionTicket Pointer to the SessionTicket extension
 * @return Error code
 **/

error_t tlsParseClientSessionTicketExtension(TlsContext *context,
   const TlsExtension *sessionTicket)
{
#if (TLS_TICKET_SUPPORT == ENABLED)
   //SessionTicket extension found?
   if(sessionTicket != NULL)
   {
      //Check whether session ticket mechanism is enabled
      if(context->sessionTicketEnabled &&
         context->ticketEncryptCallback != NULL &&
         context->ticketDecryptCallback != NULL)
      {
         //The ClientHello includes a SessionTicket extension
         context->sessionTicketExtReceived = TRUE;
      }
   }
#endif

   //Return status code
   return NO_ERROR;
}


/**
 * @brief Parse RenegotiationInfo extension
 * @param[in] context Pointer to the TLS context
 * @param[in] extensions ClientHello extensions offered by the client
 * @return Error code
 **/

error_t tlsParseClientRenegoInfoExtension(TlsContext *context,
   const TlsHelloExtensions *extensions)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
   //RenegotiationInfo extension found?
   if(extensions->renegoInfo != NULL)
   {
      //Initial handshake?
      if(context->clientVerifyDataLen == 0)
      {
         //Set the secure_renegotiation flag to TRUE
         context->secureRenegoFlag = TRUE;

         //The server must then verify that the length of the
         //renegotiated_connection field is zero
         if(extensions->renegoInfo->length != 0)
         {
            //If it is not, the server must abort the handshake
            error = ERROR_HANDSHAKE_FAILED;
         }
      }
      //Secure renegotiation?
      else
      {
         //Check the length of the renegotiated_connection field
         if(extensions->renegoInfo->length != context->clientVerifyDataLen)
         {
            //The server must abort the handshake
            error = ERROR_HANDSHAKE_FAILED;
         }
         else
         {
            //Verify that the value of the renegotiated_connection field is
            //equal to the saved client_verify_data value
            if(osMemcmp(extensions->renegoInfo->value,
               context->clientVerifyData, context->clientVerifyDataLen))
            {
               //If it is not, the server must abort the handshake
               error = ERROR_HANDSHAKE_FAILED;
            }
         }

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
         //ExtendedMasterSecret extension found?
         if(extensions->extendedMasterSecret != NULL)
         {
            //If the initial handshake did not use the ExtendedMasterSecret
            //extension but the new ClientHello contains the extension, the
            //server must abort the handshake
            if(!context->emsExtReceived)
            {
               error = ERROR_HANDSHAKE_FAILED;
            }
         }
         else
         {
            //If the initial handshake used the ExtendedMasterSecret extension
            //but the new ClientHello does not contain the extension, the
            //server must abort the handshake
            if(context->emsExtReceived)
            {
               error = ERROR_HANDSHAKE_FAILED;
            }
         }
#endif
      }
   }
   else
   {
      //Secure renegotiation?
      if(context->clientVerifyDataLen != 0 || context->serverVerifyDataLen != 0)
      {
         //The server must verify that the renegotiation_info extension is
         //present. If it is not, the server must abort the handshake
         error = ERROR_HANDSHAKE_FAILED;
      }
   }
#endif

   //Return status code
   return error;
}

#endif
