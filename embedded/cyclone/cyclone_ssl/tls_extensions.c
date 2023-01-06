/**
 * @file tls_extensions.c
 * @brief Parsing and checking of TLS extensions
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
#include "tls_extensions.h"
#include "tls_transcript_hash.h"
#include "tls_record.h"
#include "dtls_record.h"
#include "debug.h"

//Check TLS library configuration
#if (TLS_SUPPORT == ENABLED)


/**
 * @brief Parse Hello extensions
 * @param[in] msgType Handshake message type
 * @param[in] p Input stream where to read the list of extensions
 * @param[in] length Number of bytes available in the input stream
 * @param[out] extensions List of Hello extensions resulting from the parsing process
 * @return Error code
 **/

error_t tlsParseHelloExtensions(TlsMessageType msgType, const uint8_t *p,
   size_t length, TlsHelloExtensions *extensions)
{
   error_t error;
   size_t n;
   uint16_t type;
   const TlsExtension *extension;
   const TlsExtensionList *extensionList;

   //Initialize TLS extensions
   osMemset(extensions, 0, sizeof(TlsHelloExtensions));

   //Check message type
   if(msgType == TLS_TYPE_CLIENT_HELLO || msgType == TLS_TYPE_SERVER_HELLO)
   {
      //The implementation must accept messages both with and without the
      //extensions field
      if(length == 0)
      {
         //The extensions field is not present
         return NO_ERROR;
      }
   }

   //Point to the list of extensions
   extensionList = (TlsExtensionList *) p;

   //Malformed message?
   if(length < sizeof(TlsExtensionList))
      return ERROR_DECODING_FAILED;

   //If the amount of data in the message does not precisely match the format
   //of the message, then send a fatal alert
   if(length != (sizeof(TlsExtensionList) + ntohs(extensionList->length)))
      return ERROR_DECODING_FAILED;

   //Point to the first extension of the list
   p += sizeof(TlsExtensionList);
   //Retrieve the length of the list
   length -= sizeof(TlsExtensionList);

   //Parse the list of extensions offered by the peer
   while(length > 0)
   {
      //Point to the current extension
      extension = (TlsExtension *) p;

      //Check the length of the extension
      if(length < sizeof(TlsExtension))
         return ERROR_DECODING_FAILED;
      if(length < (sizeof(TlsExtension) + ntohs(extension->length)))
         return ERROR_DECODING_FAILED;

      //Get extension type
      type = ntohs(extension->type);
      //Retrieve the length of the extension
      n = ntohs(extension->length);

      //Jump to the next extension
      p += sizeof(TlsExtension) + n;
      //Number of bytes left to process
      length -= sizeof(TlsExtension) + n;

      //Test if the current extension is a duplicate
      error = tlsCheckDuplicateExtension(type, p, length);
      //Duplicate extension found?
      if(error)
         return error;

      //When multiple extensions of different types are present in the ClientHello
      //or ServerHello messages, the extensions may appear in any order
      if(type == TLS_EXT_SUPPORTED_VERSIONS)
      {
         //Check message type
         if(msgType == TLS_TYPE_CLIENT_HELLO)
         {
            const TlsSupportedVersionList *supportedVersionList;

            //Point to the SupportedVersions extension
            supportedVersionList = (TlsSupportedVersionList *) extension->value;

            //Malformed extension?
            if(n < sizeof(TlsSupportedVersionList))
               return ERROR_DECODING_FAILED;
            if(n != (sizeof(TlsSupportedVersionList) + supportedVersionList->length))
               return ERROR_DECODING_FAILED;

            //Check the length of the list
            if(supportedVersionList->length == 0)
               return ERROR_DECODING_FAILED;
            if((supportedVersionList->length % 2) != 0)
               return ERROR_DECODING_FAILED;

            //The SupportedVersions extension is valid
            extensions->supportedVersionList = supportedVersionList;
         }
         else if(msgType == TLS_TYPE_SERVER_HELLO ||
            msgType == TLS_TYPE_HELLO_RETRY_REQUEST)
         {
            //The extension contains the selected version value
            if(n != sizeof(uint16_t))
               return ERROR_DECODING_FAILED;

            //The SupportedVersions extension is valid
            extensions->selectedVersion = extension;
         }
         else
         {
            //The extension is not specified for the message in which it appears
            return ERROR_ILLEGAL_PARAMETER;
         }
      }
      else if(type == TLS_EXT_SERVER_NAME)
      {
         const TlsServerNameList *serverNameList;

         //Point to the ServerName extension
         serverNameList = (TlsServerNameList *) extension->value;

         //Empty extension?
         if(n == 0)
         {
            //When the server includes a ServerName extension, the data field
            //of this extension may be empty
            if(msgType == TLS_TYPE_CLIENT_HELLO)
               return ERROR_DECODING_FAILED;
         }
         else
         {
            //Malformed extension?
            if(n < sizeof(TlsServerNameList))
               return ERROR_DECODING_FAILED;
            if(n != (sizeof(TlsServerNameList) + ntohs(serverNameList->length)))
               return ERROR_DECODING_FAILED;

            //Check the length of the list
            if(ntohs(serverNameList->length) == 0)
               return ERROR_DECODING_FAILED;
         }

         //The ServerName extension is valid
         extensions->serverNameList = serverNameList;
      }
      else if(type == TLS_EXT_SUPPORTED_GROUPS)
      {
         const TlsSupportedGroupList *supportedGroupList;

         //Point to the SupportedGroups extension
         supportedGroupList = (TlsSupportedGroupList *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsSupportedGroupList))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsSupportedGroupList) + ntohs(supportedGroupList->length)))
            return ERROR_DECODING_FAILED;

         //Check the length of the list
         if(ntohs(supportedGroupList->length) == 0)
            return ERROR_DECODING_FAILED;
         if((ntohs(supportedGroupList->length) % 2) != 0)
            return ERROR_DECODING_FAILED;

         //The SupportedGroups extension is valid
         extensions->supportedGroupList = supportedGroupList;
      }
      else if(type == TLS_EXT_EC_POINT_FORMATS)
      {
         const TlsEcPointFormatList *ecPointFormatList;

         //Point to the EcPointFormats extension
         ecPointFormatList = (TlsEcPointFormatList *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsEcPointFormatList))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsEcPointFormatList) + ecPointFormatList->length))
            return ERROR_DECODING_FAILED;

         //Check the length of the list
         if(ntohs(ecPointFormatList->length) == 0)
            return ERROR_DECODING_FAILED;

         //The EcPointFormats extension is valid
         extensions->ecPointFormatList = ecPointFormatList;
      }
      else if(type == TLS_EXT_SIGNATURE_ALGORITHMS)
      {
         const TlsSignHashAlgos *signAlgoList;

         //Point to the SignatureAlgorithms extension
         signAlgoList = (TlsSignHashAlgos *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsSignHashAlgos))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsSignHashAlgos) + ntohs(signAlgoList->length)))
            return ERROR_DECODING_FAILED;

         //Check the length of the list
         if(ntohs(signAlgoList->length) == 0)
            return ERROR_DECODING_FAILED;
         if((ntohs(signAlgoList->length) % 2) != 0)
            return ERROR_DECODING_FAILED;

         //The SignatureAlgorithms extension is valid
         extensions->signAlgoList = signAlgoList;
      }
      else if(type == TLS_EXT_SIGNATURE_ALGORITHMS_CERT)
      {
         const TlsSignHashAlgos *certSignAlgoList;

         //Point to the SignatureAlgorithmsCert extension
         certSignAlgoList = (TlsSignHashAlgos *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsSignHashAlgos))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsSignHashAlgos) + ntohs(certSignAlgoList->length)))
            return ERROR_DECODING_FAILED;

         //Check the length of the list
         if(ntohs(certSignAlgoList->length) == 0)
            return ERROR_DECODING_FAILED;
         if((ntohs(certSignAlgoList->length) % 2) != 0)
            return ERROR_DECODING_FAILED;

         //The SignatureAlgorithmsCert extension is valid
         extensions->certSignAlgoList = certSignAlgoList;
      }
#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
      else if(type == TLS_EXT_MAX_FRAGMENT_LENGTH)
      {
         //Malformed extension?
         if(n != sizeof(uint8_t))
            return ERROR_DECODING_FAILED;

         //The MaxFragmentLength extension is valid
         extensions->maxFragLen = extension;
      }
#endif
#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
      else if(type == TLS_EXT_RECORD_SIZE_LIMIT)
      {
         //Malformed extension?
         if(n != sizeof(uint16_t))
            return ERROR_DECODING_FAILED;

         //The RecordSizeLimit extension is valid
         extensions->recordSizeLimit = extension;
      }
#endif
#if (TLS_ALPN_SUPPORT == ENABLED)
      else if(type == TLS_EXT_ALPN)
      {
         const TlsProtocolNameList *protocolNameList;

         //Point to the ALPN extension
         protocolNameList = (TlsProtocolNameList *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsProtocolNameList))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsProtocolNameList) + ntohs(protocolNameList->length)))
            return ERROR_DECODING_FAILED;

         //The ALPN extension is valid
         extensions->protocolNameList = protocolNameList;
      }
#endif
#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
      else if(type == TLS_EXT_CLIENT_CERT_TYPE)
      {
         //Check message type
         if(msgType == TLS_TYPE_CLIENT_HELLO)
         {
            const TlsCertTypeList *clientCertTypeList;

            //Point to the ClientCertType extension
            clientCertTypeList = (TlsCertTypeList *) extension->value;

            //Malformed extension?
            if(n < sizeof(TlsCertTypeList))
               return ERROR_DECODING_FAILED;
            if(n != (sizeof(TlsCertTypeList) + clientCertTypeList->length))
               return ERROR_DECODING_FAILED;

            //The ClientCertType extension is valid
            extensions->clientCertTypeList = clientCertTypeList;
         }
         else
         {
            //Only a single value is permitted in the ClientCertType extension
            //when carried in the ServerHello
            if(n != sizeof(uint8_t))
               return ERROR_DECODING_FAILED;

            //The ClientCertType extension is valid
            extensions->clientCertType = extension;
         }
      }
      else if(type == TLS_EXT_SERVER_CERT_TYPE)
      {
         //Check message type
         if(msgType == TLS_TYPE_CLIENT_HELLO)
         {
            const TlsCertTypeList *serverCertTypeList;

            //Point to the ServerCertType extension
            serverCertTypeList = (TlsCertTypeList *) extension->value;

            //Malformed extension?
            if(n < sizeof(TlsCertTypeList))
               return ERROR_DECODING_FAILED;
            if(n != (sizeof(TlsCertTypeList) + serverCertTypeList->length))
               return ERROR_DECODING_FAILED;

            //The ServerCertType extension is valid
            extensions->serverCertTypeList = serverCertTypeList;
         }
         else
         {
            //Only a single value is permitted in the ServerCertType extension
            //when carried in the ServerHello
            if(n != sizeof(uint8_t))
               return ERROR_DECODING_FAILED;

            //The ServerCertType extension is valid
            extensions->serverCertType = extension;
         }
      }
#endif
#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      else if(type == TLS_EXT_EXTENDED_MASTER_SECRET)
      {
         //Malformed extension?
         if(n != 0)
            return ERROR_DECODING_FAILED;

         //The ExtendedMasterSecret extension is valid
         extensions->extendedMasterSecret = extension;
      }
#endif
#if (TLS_TICKET_SUPPORT == ENABLED)
      else if(type == TLS_EXT_SESSION_TICKET)
      {
         //Check message type
         if(msgType == TLS_TYPE_SERVER_HELLO)
         {
            //The server uses a zero-length SessionTicket extension to indicate
            //to the client that it will send a new session ticket
            if(n != 0)
               return ERROR_DECODING_FAILED;
         }

         //The SessionTicket extension is valid
         extensions->sessionTicket = extension;
      }
#endif
#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      else if(type == TLS_EXT_RENEGOTIATION_INFO)
      {
         const TlsRenegoInfo *renegoInfo;

         //Point to the RenegotiationInfo extension
         renegoInfo = (TlsRenegoInfo *) extension->value;

         //Malformed extension?
         if(n < sizeof(TlsRenegoInfo))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(TlsRenegoInfo) + renegoInfo->length))
            return ERROR_DECODING_FAILED;

         //The RenegotiationInfo extension is valid
         extensions->renegoInfo = renegoInfo;
      }
#endif
#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
      else if(type == TLS_EXT_COOKIE)
      {
         const Tls13Cookie *cookie;

         //Point to the Cookie extension
         cookie = (Tls13Cookie *) extension->value;

         //Malformed extension?
         if(n < sizeof(Tls13Cookie))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(Tls13Cookie) + ntohs(cookie->length)))
            return ERROR_DECODING_FAILED;

         //Check the length of the cookie
         if(ntohs(cookie->length) == 0)
            return ERROR_DECODING_FAILED;

         //The Cookie extension is valid
         extensions->cookie = cookie;
      }
      else if(type == TLS_EXT_KEY_SHARE)
      {
         //Check message type
         if(msgType == TLS_TYPE_CLIENT_HELLO)
         {
            size_t k;
            size_t m;
            const Tls13KeyShareList *keyShareList;
            const Tls13KeyShareEntry *keyShareEntry;

            //The extension contains a list of offered KeyShareEntry values
            //in descending order of client preference
            keyShareList = (Tls13KeyShareList *) extension->value;

            //Malformed extension?
            if(n < sizeof(Tls13KeyShareList))
               return ERROR_DECODING_FAILED;
            if(n != (sizeof(Tls13KeyShareList) + ntohs(keyShareList->length)))
               return ERROR_DECODING_FAILED;

            //Point to the first KeyShareEntry of the list
            p = keyShareList->value;
            //Retrieve the length of the list
            m = ntohs(keyShareList->length);

            //Parse the list of key share entries offered by the peer
            while(m > 0)
            {
               //Malformed extension?
               if(m < sizeof(Tls13KeyShareEntry))
                  return ERROR_DECODING_FAILED;

               //Point to the current key share entry
               keyShareEntry = (Tls13KeyShareEntry *) p;
               //Retrieve the length of the key_exchange field
               k = ntohs(keyShareEntry->length);

               //Malformed extension?
               if(m < (sizeof(Tls13KeyShareEntry) + k))
                  return ERROR_DECODING_FAILED;

               //Point to the next entry
               p += sizeof(Tls13KeyShareEntry) + k;
               //Remaining bytes to process
               m -= sizeof(Tls13KeyShareEntry) + k;

               //Clients must not offer multiple KeyShareEntry values for the
               //same group. Servers may check for violations of this rule and
               //abort the handshake with an illegal_parameter alert
               error = tls13CheckDuplicateKeyShare(ntohs(keyShareEntry->group),
                  p, m);
               //Any error to report?
               if(error)
                  return ERROR_ILLEGAL_PARAMETER;
            }

            //The KeyShare extension is valid
            extensions->keyShareList = keyShareList;
         }
         else if(msgType == TLS_TYPE_HELLO_RETRY_REQUEST)
         {
            //The extension contains the mutually supported group the server
            //intends to negotiate
            if(n != sizeof(uint16_t))
               return ERROR_DECODING_FAILED;

            //The KeyShare extension is valid
            extensions->selectedGroup = extension;
         }
         else if(msgType == TLS_TYPE_SERVER_HELLO)
         {
            const Tls13KeyShareEntry *serverShare;

            //The extension contains a single KeyShareEntry value that is in
            //the same group as one of the client's shares
            serverShare = (Tls13KeyShareEntry *) extension->value;

            //Malformed extension?
            if(n < sizeof(Tls13KeyShareEntry))
               return ERROR_DECODING_FAILED;
            if(n != (sizeof(Tls13KeyShareEntry) + ntohs(serverShare->length)))
               return ERROR_DECODING_FAILED;

            //The KeyShare extension is valid
            extensions->serverShare = serverShare;
         }
         else
         {
            //The extension is not specified for the message in which it appears
#if (TLS_MAX_EMPTY_RECORDS > 0)
            return ERROR_UNSUPPORTED_EXTENSION;
#else
            return ERROR_ILLEGAL_PARAMETER;
#endif
         }
      }
      else if(type == TLS_EXT_PSK_KEY_EXCHANGE_MODES)
      {
         const Tls13PskKeModeList *pskKeModeList;

         //The extension contains the list of PSK key exchange modes that
         //are supported by the client
         pskKeModeList = (Tls13PskKeModeList *) extension->value;

         //Malformed extension?
         if(n < sizeof(Tls13PskKeModeList))
            return ERROR_DECODING_FAILED;
         if(n != (sizeof(Tls13PskKeModeList) + pskKeModeList->length))
            return ERROR_DECODING_FAILED;

         //The PskKeyExchangeModes extension is valid
         extensions->pskKeModeList = pskKeModeList;
      }
      else if(type == TLS_EXT_PRE_SHARED_KEY)
      {
         //Check message type
         if(msgType == TLS_TYPE_CLIENT_HELLO)
         {
            const Tls13PskIdentityList *identityList;
            const Tls13PskBinderList *binderList;

            //The PreSharedKey extension must be the last extension in the
            //ClientHello. Servers must check that it is the last extension and
            //otherwise fail the handshake with an illegal_parameter alert
            if(length != 0)
               return ERROR_ILLEGAL_PARAMETER;

            //The extension contains a list of the identities that the client
            //is willing to negotiate with the server
            identityList = (Tls13PskIdentityList *) extension->value;

            //Malformed extension?
            if(n < sizeof(Tls13PskIdentityList))
               return ERROR_DECODING_FAILED;
            if(n < (sizeof(Tls13PskIdentityList) + ntohs(identityList->length)))
               return ERROR_DECODING_FAILED;

            //Remaining bytes to process
            n -= sizeof(Tls13PskIdentityList) + ntohs(identityList->length);

            //The extension also contains a series of HMAC values, one for each
            //PSK offered in the PreSharedKey extension and in the same order
            binderList = (Tls13PskBinderList *) (extension->value +
               sizeof(Tls13PskIdentityList) + ntohs(identityList->length));

            //Malformed extension?
            if(n < sizeof(Tls13PskBinderList))
               return ERROR_DECODING_FAILED;
            if(n != (sizeof(Tls13PskBinderList) + ntohs(binderList->length)))
               return ERROR_DECODING_FAILED;

            //The PreSharedKey extension is valid
            extensions->identityList = identityList;
            extensions->binderList = binderList;
         }
         else if(msgType == TLS_TYPE_SERVER_HELLO)
         {
            //The extension contains the chosen identity expressed as a 0-based
            //index into the identities in the client's list
            if(n != sizeof(uint16_t))
               return ERROR_DECODING_FAILED;

            //The PreSharedKey extension is valid
            extensions->selectedIdentity = extension;
         }
         else
         {
            //The extension is not specified for the message in which it appears
            return ERROR_ILLEGAL_PARAMETER;
         }
      }
      else if(type == TLS_EXT_EARLY_DATA)
      {
         //Check message type
         if(msgType == TLS_TYPE_CLIENT_HELLO ||
            msgType == TLS_TYPE_ENCRYPTED_EXTENSIONS)
         {
            //The extension data field is empty
            if(n != 0)
               return ERROR_DECODING_FAILED;
         }
         else if(msgType == TLS_TYPE_NEW_SESSION_TICKET)
         {
            //The extension data field contains an unsigned 32-bit integer
            if(n != sizeof(uint32_t))
               return ERROR_DECODING_FAILED;
         }
         else
         {
            //The extension is not specified for the message in which it appears
            return ERROR_ILLEGAL_PARAMETER;
         }

         //The EarlyData extension is valid
         extensions->earlyDataIndication = extension;
      }
#endif
      else
      {
         //If a client receives an extension type in the ServerHello that it
         //did not request in the associated ClientHello, it must abort the
         //handshake with an unsupported_extension fatal alert
         if(msgType == TLS_TYPE_SERVER_HELLO ||
            msgType == TLS_TYPE_HELLO_RETRY_REQUEST ||
            msgType == TLS_TYPE_ENCRYPTED_EXTENSIONS)
         {
            //Report an error
            return ERROR_UNSUPPORTED_EXTENSION;
         }
      }
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Check Hello extensions
 * @param[in] msgType Handshake message type
 * @param[in] version TLS version
 * @param[in] extensions List of Hello extensions offered by the peer
 * @return Error code
 **/

error_t tlsCheckHelloExtensions(TlsMessageType msgType, uint16_t version,
   TlsHelloExtensions *extensions)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED && TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
   //A client must treat receipt of both MaxFragmentLength and RecordSizeLimit
   //extensions as a fatal error, and it should generate an illegal_parameter
   //alert (refer to RFC 8449, section 5)
   if(extensions->maxFragLen != NULL && extensions->recordSizeLimit != NULL)
   {
      //ServerHello or EncryptedExtensions message?
      if(msgType == TLS_TYPE_SERVER_HELLO ||
         msgType == TLS_TYPE_ENCRYPTED_EXTENSIONS)
      {
         error = ERROR_ILLEGAL_PARAMETER;
      }
   }
#endif

#if (TLS_MAX_VERSION >= TLS_VERSION_1_3 && TLS_MIN_VERSION <= TLS_VERSION_1_3)
   //If an implementation receives an extension which it recognizes and which
   //is not specified for the message in which it appears it must abort the
   //handshake with an illegal_parameter alert (refer to RFC 8446, section 4.2)
   if(version == TLS_VERSION_1_3)
   {
      //SupportedVersions extension found?
      if(extensions->supportedVersionList != NULL ||
         extensions->selectedVersion != NULL)
      {
         //The extension can only appear in CH, SH and HRR messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_SERVER_HELLO &&
            msgType != TLS_TYPE_HELLO_RETRY_REQUEST)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //ServerName extension found?
      if(extensions->serverNameList != NULL)
      {
         //The extension can only appear in CH and EE messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_ENCRYPTED_EXTENSIONS)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //SupportedGroups extension found?
      if(extensions->supportedGroupList != NULL)
      {
         //The extension can only appear in CH and EE messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_ENCRYPTED_EXTENSIONS)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //EcPointFormats extension found?
      if(extensions->ecPointFormatList != NULL)
      {
         //The extension can only appear in CH
         if(msgType != TLS_TYPE_CLIENT_HELLO)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //SignatureAlgorithms extension found?
      if(extensions->signAlgoList != NULL)
      {
         //The extension can only appear in CH and CR messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_CERTIFICATE_REQUEST)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //SignatureAlgorithmsCert extension found?
      if(extensions->certSignAlgoList != NULL)
      {
         //The extension can only appear in CH and CR messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_CERTIFICATE_REQUEST)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

#if (TLS_MAX_FRAG_LEN_SUPPORT == ENABLED)
      //MaxFragmentLength extension found?
      if(extensions->maxFragLen != NULL)
      {
         //The extension can only appear in CH and EE messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_ENCRYPTED_EXTENSIONS)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
#endif

#if (TLS_RECORD_SIZE_LIMIT_SUPPORT == ENABLED)
      //RecordSizeLimit extension found?
      if(extensions->recordSizeLimit != NULL)
      {
         //The extension can only appear in CH and EE messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_ENCRYPTED_EXTENSIONS)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
#endif

#if (TLS_ALPN_SUPPORT == ENABLED)
      //ALPN extension found?
      if(extensions->protocolNameList != NULL)
      {
         //The extension can only appear in CH and EE messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_ENCRYPTED_EXTENSIONS)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
#endif

#if (TLS_RAW_PUBLIC_KEY_SUPPORT == ENABLED)
      //ClientCertType extension found?
      if(extensions->clientCertTypeList != NULL ||
         extensions->clientCertType != NULL)
      {
         //The extension can only appear in CH and EE messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_ENCRYPTED_EXTENSIONS)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //ServerCertType extension found?
      if(extensions->serverCertTypeList != NULL ||
         extensions->serverCertType != NULL)
      {
         //The extension can only appear in CH and EE messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_ENCRYPTED_EXTENSIONS)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
#endif

#if (TLS_EXT_MASTER_SECRET_SUPPORT == ENABLED)
      //ExtendedMasterSecret extension found?
      if(extensions->extendedMasterSecret != NULL)
      {
         //The extension can only appear in CH
         if(msgType != TLS_TYPE_CLIENT_HELLO)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
#endif

#if (TLS_TICKET_SUPPORT == ENABLED)
      //SessionTicket extension found?
      if(extensions->sessionTicket != NULL)
      {
         //The extension can only appear in CH
         if(msgType != TLS_TYPE_CLIENT_HELLO)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
#endif

#if (TLS_SECURE_RENEGOTIATION_SUPPORT == ENABLED)
      //RenegotiationInfo extension found?
      if(extensions->renegoInfo != NULL)
      {
         //The extension can only appear in CH
         if(msgType != TLS_TYPE_CLIENT_HELLO)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
#endif

      //Cookie extension found?
      if(extensions->cookie != NULL)
      {
         //The extension can only appear in CH and HRR messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_HELLO_RETRY_REQUEST)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //KeyShare extension found?
      if(extensions->keyShareList != NULL ||
         extensions->serverShare != NULL ||
         extensions->selectedGroup != NULL)
      {
         //The extension can only appear in CH, SH and HRR messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_SERVER_HELLO &&
            msgType != TLS_TYPE_HELLO_RETRY_REQUEST)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //PskKeyExchangeModes extension found?
      if(extensions->pskKeModeList != NULL)
      {
         //The extension can only appear in CH message
         if(msgType != TLS_TYPE_CLIENT_HELLO)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //PreSharedKey extension found?
      if(extensions->identityList != NULL ||
         extensions->binderList != NULL ||
         extensions->selectedIdentity != NULL)
      {
         //The extension can only appear in CH and SH messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_SERVER_HELLO)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }

      //EarlyData extension found?
      if(extensions->earlyDataIndication != NULL)
      {
         //The extension can only appear in CH, EE and NST messages
         if(msgType != TLS_TYPE_CLIENT_HELLO &&
            msgType != TLS_TYPE_ENCRYPTED_EXTENSIONS &&
            msgType != TLS_TYPE_NEW_SESSION_TICKET)
         {
            error = ERROR_ILLEGAL_PARAMETER;
         }
      }
   }

   //Check mandatory-to-implement extensions
   if(msgType == TLS_TYPE_CLIENT_HELLO && version == TLS_VERSION_1_3)
   {
      //A client must provide a PskKeyExchangeModes extension if it offers a
      //PreSharedKey extension (refer to RFC 8446, section 4.2.9)
      if(extensions->identityList != NULL || extensions->binderList != NULL)
      {
         //If a client offers PreSharedKey without a PskKeyExchangeModes
         //extension, the servers must abort the handshake
         if(extensions->pskKeModeList == NULL)
         {
            error = ERROR_MISSING_EXTENSION;
         }
      }

      //If the ClientHello does not contain a PreSharedKey extension, it must
      //contain both a SignatureAlgorithms extension and a SupportedGroups
      //extension (refer to RFC 8446, section 9.2)
      if(extensions->identityList == NULL || extensions->binderList == NULL)
      {
         //Servers receiving a ClientHello which does not conform to these
         //requirements must abort the handshake with a missing_extension
         //alert
         if(extensions->signAlgoList == NULL ||
            extensions->supportedGroupList == NULL)
         {
            error = ERROR_MISSING_EXTENSION;
         }
      }

      //If the ClientHello contains a SupportedGroups extension, it must also
      //contain a KeyShare extension, and vice versa
      if(extensions->supportedGroupList != NULL &&
         extensions->keyShareList == NULL)
      {
         error = ERROR_MISSING_EXTENSION;
      }
      else if(extensions->keyShareList != NULL &&
         extensions->supportedGroupList == NULL)
      {
         error = ERROR_MISSING_EXTENSION;
      }
   }
#endif

   //Return status code
   return error;
}


/**
 * @brief Check whether the specified extension type is a duplicate
 * @param[in] type Extension type
 * @param[in] p Input stream where to read the list of extensions
 * @param[in] length Number of bytes available in the input stream
 * @return Error code
 **/

error_t tlsCheckDuplicateExtension(uint16_t type, const uint8_t *p,
   size_t length)
{
   size_t n;
   const TlsExtension *extension;

   //Parse the list of extensions offered by the peer
   while(length > 0)
   {
      //Point to the current extension
      extension = (TlsExtension *) p;

      //Check the length of the extension
      if(length < sizeof(TlsExtension))
         return ERROR_DECODING_FAILED;
      if(length < (sizeof(TlsExtension) + ntohs(extension->length)))
         return ERROR_DECODING_FAILED;

      //There must not be more than one extension of the same type (refer to
      //RFC 5246, section 7.4.1.4)
      if(ntohs(extension->type) == type)
      {
         if(type > TLS_EXT_RENEGOTIATION_INFO)
            return ERROR_DECODING_FAILED;
         else
            return ERROR_ILLEGAL_PARAMETER;
      }

      //Retrieve the length of the extension
      n = ntohs(extension->length);

      //Jump to the next extension
      p += sizeof(TlsExtension) + n;
      //Number of bytes left to process
      length -= sizeof(TlsExtension) + n;
   }

   //Successful verification
   return NO_ERROR;
}


/**
 * @brief Check whether the specified ALPN protocol is supported
 * @param[in] context Pointer to the TLS context
 * @param[in] protocol Pointer to the protocol name
 * @param[in] length Length of the protocol name, in bytes
 * @return TRUE if the specified protocol is supported, else FALSE
 **/

bool_t tlsIsAlpnProtocolSupported(TlsContext *context,
   const char_t *protocol, size_t length)
{
   bool_t supported;

   //Initialize flag
   supported = FALSE;

#if (TLS_ALPN_SUPPORT == ENABLED)
   //Sanity check
   if(context->protocolList != NULL)
   {
      size_t i;
      size_t j;

      //Move back to the beginning of the list
      i = 0;
      j = 0;

      //Parse the list of supported protocols
      do
      {
         //Delimiter character found?
         if(context->protocolList[i] == ',' || context->protocolList[i] == '\0')
         {
            //Check the length of the protocol name
            if(length == (i - j))
            {
               //Compare protocol names
               if(!osMemcmp(protocol, context->protocolList + j, i - j))
               {
                  //The specified protocol is supported
                  supported = TRUE;
                  //We are done
                  break;
               }
            }

            //Move to the next token
            j = i + 1;
         }

         //Loop until the NULL character is reached
      } while(context->protocolList[i++] != '\0');
   }
#endif

   //Return TRUE if the specified protocol is supported
   return supported;
}

#endif
