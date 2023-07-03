/**
 * @file acme_client_challenge.c
 * @brief Challenge object management
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
#include "acme/acme_client_challenge.h"
#include "acme/acme_client_jose.h"
#include "acme/acme_client_misc.h"
#include "pkix/pem_export.h"
#include "pkix/x509_cert_create.h"
#include "encoding/base64url.h"
#include "encoding/asn1.h"
#include "jansson.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (ACME_CLIENT_SUPPORT == ENABLED)

//id-pe-acmeIdentifier OID (1.3.6.1.5.5.7.1.31)
const uint8_t ACME_IDENTIFIER_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1F};


/**
 * @brief Send HTTP request (challenge URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] challenge Pointer to the challenge object
 * @return Error code
 **/

error_t acmeClientSendChallengeReadyRequest(AcmeClientContext *context,
   AcmeChallenge *challenge)
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
         TRACE_DEBUG("## CHALLENGE READY ############################################################\r\n");
         TRACE_DEBUG("###############################################################################\r\n");
         TRACE_DEBUG("\r\n");

         //Update HTTP request state
         context->requestState = ACME_REQ_STATE_FORMAT_BODY;
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_BODY)
      {
         //Format the body of the HTTP request
         error = acmeClientFormatChallengeReadyRequest(context, challenge);

         //Check status code
         if(!error)
         {
            //Update HTTP request state
            context->requestState = ACME_REQ_STATE_FORMAT_HEADER;
         }
      }
      else if(context->requestState == ACME_REQ_STATE_FORMAT_HEADER)
      {
         //The client indicates to the server that it is ready for the challenge
         //validation by sending an empty JSON body carried in a POST request to
         //the challenge URL (refer to RFC 8555, section 7.5.1)
         error = acmeClientFormatRequestHeader(context, "POST", challenge->url);

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
         error = acmeClientParseChallengeReadyResponse(context);

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
 * @brief Format HTTP request body (challenge URL)
 * @param[in] context Pointer to the ACME client context
 * @param[in] challenge Pointer to the challenge object
 * @return Error code
 **/

error_t acmeClientFormatChallengeReadyRequest(AcmeClientContext *context,
   AcmeChallenge *challenge)
{
   error_t error;
   size_t n;
   char_t *protected;
   const char_t *payload;

   //The client must send an empty JSON body (refer to RFC 8555, section 7.5.1)
   payload = "{}";

   //Point to the buffer where to format the JWS protected header
   protected = context->buffer;

   //Format JWS protected header
   error = acmeClientFormatJwsProtectedHeader(&context->accountKey,
      context->account.url, context->nonce, challenge->url,
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
 * @brief Parse HTTP response (challenge URL)
 * @param[in] context Pointer to the ACME client context
 * @return Error code
 **/

error_t acmeClientParseChallengeReadyResponse(AcmeClientContext *context)
{
   //Check HTTP status code
   if(!HTTP_STATUS_CODE_2YZ(context->statusCode))
      return ERROR_UNEXPECTED_STATUS;

   //The server must include a Replay-Nonce header field in every successful
   //response to a POST request (refer to RFC 8555, section 6.5)
   if(context->nonce[0] == '\0')
      return ERROR_INVALID_RESPONSE;

   //The response to a HEAD request does not contain a body
   return NO_ERROR;
}


/**
 * @brief Parse challenge status field
 * @param[in] label Textual representation of the status
 * @return Authorization status code
 **/

AcmeChallengeStatus acmeClientParseChallengeStatus(const char_t *label)
{
   AcmeChallengeStatus status;

   //Check the status of the challenge (refer to RFC 8555, section 7.1.6)
   if(!osStrcmp(label, "pending"))
   {
      //Challenge objects are created in the "pending" state
      status = ACME_CHALLENGE_STATUS_PENDING;
   }
   else if(!osStrcmp(label, "processing"))
   {
      //They transition to the "processing" state when the client responds to
      //the challenge
      status = ACME_CHALLENGE_STATUS_PROCESSING;
   }
   else if(!osStrcmp(label, "valid"))
   {
      //If validation is successful, the challenge moves to the "valid" state
      status = ACME_CHALLENGE_STATUS_VALID;
   }
   else if(!osStrcmp(label, "invalid"))
   {
      //If there is an error, the challenge moves to the "invalid" state
      status = ACME_CHALLENGE_STATUS_INVALID;
   }
   else
   {
      //Unknown status
      status = ACME_CHALLENGE_STATUS_INVALID;
   }

   //Return current status
   return status;
}


/**
 * @brief Parse challenge type field
 * @param[in] label Textual representation of the challenge type
 * @return Challenge type
 **/

AcmeChallengeType acmeClientParseChallengeType(const char_t *label)
{
   AcmeChallengeType type;

   //Check challenge type
   if(!osStrcmp(label, "http-01"))
   {
      //HTTP challenge
      type = ACME_CHALLENGE_TYPE_HTTP_01;
   }
   else if(!osStrcmp(label, "dns-01"))
   {
      //DNS challenge
      type = ACME_CHALLENGE_TYPE_DNS_01;
   }
   else if(!osStrcmp(label, "tls-alpn-01"))
   {
      //TLS ALPN challenge
      type = ACME_CHALLENGE_TYPE_TLS_ALPN_01;
   }
   else
   {
      //Unknown challenge
      type = ACME_CHALLENGE_TYPE_NONE;
   }

   //Return challenge type
   return type;
}


/**
 * @brief Retrieve the challenge type used for a given domain name
 * @param[in] context Pointer to the ACME client context
 * @param[in] identifier NULL-terminated string that contains a domain name
 * @param[in] wildcard Wildcard domain name
 * @return Challenge type
 **/

AcmeChallengeType acmeClientGetChallengeType(AcmeClientContext *context,
   const char_t *identifier, bool_t wildcard)
{
   uint_t i;
   AcmeChallengeType type;

   //Initialize challenge type
   type = ACME_CHALLENGE_TYPE_NONE;

   //Loop through the list of identifiers
   for(i = 0; i < context->numIdentifiers; i++)
   {
      //Any identifier of type "dns" may have a wildcard domain name
      //as its value
      if(wildcard)
      {
         //A wildcard domain name consists of a single asterisk character
         //followed by a single full stop character ("*.") followed by a
         //domain name
         if(!osStrncmp(context->identifiers[i].value, "*.", 2) &&
            !osStrcmp(context->identifiers[i].value + 2, identifier))
         {
            type = context->identifiers[i].challengeType;
            break;
         }
      }
      else
      {
         //Compare identifier values
         if(!osStrcmp(context->identifiers[i].value, identifier))
         {
            type = context->identifiers[i].challengeType;
            break;
         }
      }
   }

   //Return challenge type
   return type;
}


/**
 * @brief Generate key authorization
 * @param[in] context Pointer to the ACME client context
 * @param[in] challenge Pointer to the challenge object
 * @return Error code
 **/

error_t acmeClientGenerateKeyAuthorization(AcmeClientContext *context,
   AcmeChallenge *challenge)
{
   error_t error;
   size_t n;
   char_t *p;
   uint8_t digest[SHA256_DIGEST_SIZE];

   //Point to the buffer where to format the key authorization
   p = challenge->keyAuth;

   //A key authorization is a string that concatenates the token for the
   //challenge with a key fingerprint, separated by a "." character
   osStrcpy(p, challenge->token);
   osStrcat(p, ".");

   //Point to the buffer where to format the JWK thumbprint
   p += osStrlen(challenge->token) + 1;

   //Construct a JSON object containing only the required members of a JWK
   //representing the key and with no whitespace or line breaks before or
   //after any syntactic elements and with the required members ordered
   //lexicographically (refer to RFC 7638, section 3)
   error = acmeClientFormatJwk(&context->accountKey, context->buffer, &n, TRUE);

   //Check status code
   if(!error)
   {
      //Hash the octets of the UTF-8 representation of this JSON object using
      //SHA-256 (refer to RFC 8555, section 8.1)
      error = sha256Compute(context->buffer, n, digest);
   }

   //Check status code
   if(!error)
   {
      //Encode the resulting JWK thumbprint using Base64url
      base64urlEncode(digest, sizeof(digest), p, &n);
   }

   //Return status code
   return error;
}


/**
 * @brief Digest the key authorization (for DNS challenge only)
 * @param[in] context Pointer to the ACME client context
 * @param[in] challenge Pointer to the challenge object
 * @return Error code
 **/

error_t acmeClientDigestKeyAuthorization(AcmeClientContext *context,
   AcmeChallenge *challenge)
{
#if (ACME_CLIENT_DNS_CHALLENGE_SUPPORT == ENABLED)
   error_t error;

   //The client computes the SHA-256 digest of the key authorization
   error = sha256Compute(challenge->keyAuth, osStrlen(challenge->keyAuth),
      (uint8_t *) context->buffer);

   //Check status code
   if(!error)
   {
      //Encode the digest using Base64url
      base64urlEncode(context->buffer, SHA256_DIGEST_SIZE, challenge->keyAuth,
         NULL);
   }

   //Return status code
   return error;
#else
   //DNS challenge is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Generate a self-signed certificate (TLS-ALPN challenge only)
 * @param[in] context Pointer to the ACME client context
 * @param[in] challenge Pointer to the challenge object
 * @return Error code
 **/

error_t acmeClientGenerateTlsAlpnCert(AcmeClientContext *context,
   AcmeChallenge *challenge)
{
#if (ACME_CLIENT_TLS_ALPN_CHALLENGE_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   X509CertRequestInfo *certReqInfo;
   X509Extensions *extensions;
   X509Validity validity;
   X509SignatureAlgoId signatureAlgo;
   uint8_t digest[SHA256_DIGEST_SIZE + 2];

   //Allocate a memory buffer to hold the certificate request information
   certReqInfo = cryptoAllocMem(sizeof(X509CertRequestInfo));

   //Successful memory allocation?
   if(certReqInfo != NULL)
   {
      //Clear certificate request information
      osMemset(certReqInfo, 0, sizeof(X509CertRequestInfo));

      //The client prepares for validation by constructing a self-signed
      //certificate that must contain an acmeIdentifier extension and a
      //subjectAlternativeName extension
      certReqInfo->subject.commonName = challenge->identifier;
      certReqInfo->subject.commonNameLen = osStrlen(challenge->identifier);

      //Point to the certificate extensions
      extensions = &certReqInfo->attributes.extensionReq;

      //Set the basicConstraints extension
      extensions->basicConstraints.critical = TRUE;
      extensions->basicConstraints.cA = TRUE;
      extensions->basicConstraints.pathLenConstraint = -1;

      //The subjectAlternativeName extension must contain a single DNS name entry
      //where the value is the domain name being validated
      extensions->subjectAltName.numGeneralNames = 1;
      extensions->subjectAltName.generalNames[0].type = X509_GENERAL_NAME_TYPE_DNS;
      extensions->subjectAltName.generalNames[0].value = challenge->identifier;
      extensions->subjectAltName.generalNames[0].length = osStrlen(challenge->identifier);

      //The acmeIdentifier extension must contain the SHA-256 digest of the key
      //authorization for the challenge
      digest[0] = ASN1_TYPE_OCTET_STRING;
      digest[1] = SHA256_DIGEST_SIZE;

      //Compute the SHA-256 digest of the key authorization
      error = sha256Compute(challenge->keyAuth, osStrlen(challenge->keyAuth),
         digest + 2);

      //Check status code
      if(!error)
      {
         //The acmeIdentifier extension must be critical so that the certificate
         //cannot be inadvertently used by non-ACME software
         extensions->numCustomExtensions = 1;
         extensions->customExtensions[0].oid = ACME_IDENTIFIER_OID;
         extensions->customExtensions[0].oidLen = sizeof(ACME_IDENTIFIER_OID);
         extensions->customExtensions[0].critical = TRUE;
         extensions->customExtensions[0].value = digest;
         extensions->customExtensions[0].valueLen = sizeof(digest);

#if (ACME_CLIENT_RSA_SUPPORT == ENABLED)
         //RSA key pair?
         if(context->certKey.type == X509_KEY_TYPE_RSA)
         {
            //Set public key identifier
            certReqInfo->subjectPublicKeyInfo.oid = RSA_ENCRYPTION_OID;
            certReqInfo->subjectPublicKeyInfo.oidLen = sizeof(RSA_ENCRYPTION_OID);

            //Select the signature algorithm
            signatureAlgo.oid = SHA256_WITH_RSA_ENCRYPTION_OID;
            signatureAlgo.oidLen = sizeof(SHA256_WITH_RSA_ENCRYPTION_OID);
         }
         else
#endif
#if (ACME_CLIENT_ECDSA_SUPPORT == ENABLED)
         //EC key pair?
         if(context->certKey.type == X509_KEY_TYPE_EC)
         {
            X509EcParameters *ecParams;

            //Set public key identifier
            certReqInfo->subjectPublicKeyInfo.oid = EC_PUBLIC_KEY_OID;
            certReqInfo->subjectPublicKeyInfo.oidLen = sizeof(EC_PUBLIC_KEY_OID);

            //Point to the EC domain parameters
            ecParams = &certReqInfo->subjectPublicKeyInfo.ecParams;

            //Select the relevant elliptic curve
            if(!osStrcmp(context->certKey.ecParams.name, "secp256r1"))
            {
               ecParams->namedCurve = SECP256R1_OID;
               ecParams->namedCurveLen = sizeof(SECP256R1_OID);
            }
            else if(!osStrcmp(context->certKey.ecParams.name, "secp384r1"))
            {
               ecParams->namedCurve = SECP384R1_OID;
               ecParams->namedCurveLen = sizeof(SECP384R1_OID);
            }
            else if(!osStrcmp(context->certKey.ecParams.name, "secp521r1"))
            {
               ecParams->namedCurve = SECP521R1_OID;
               ecParams->namedCurveLen = sizeof(SECP521R1_OID);
            }
            else
            {
               //Report an error
               error = ERROR_INVALID_KEY;
            }

            //Select the signature algorithm
            signatureAlgo.oid = ECDSA_WITH_SHA256_OID;
            signatureAlgo.oidLen = sizeof(ECDSA_WITH_SHA256_OID);
         }
         else
#endif
#if (ACME_CLIENT_ED25519_SUPPORT == ENABLED)
         //Ed25519 key pair?
         if(context->certKey.type == X509_KEY_TYPE_ED25519)
         {
            //Set public key identifier
            certReqInfo->subjectPublicKeyInfo.oid = ED25519_OID;
            certReqInfo->subjectPublicKeyInfo.oidLen = sizeof(ED25519_OID);

            //Select the signature algorithm
            signatureAlgo.oid = ED25519_OID;
            signatureAlgo.oidLen = sizeof(ED25519_OID);
         }
         else
#endif
#if (ACME_CLIENT_ED448_SUPPORT == ENABLED)
         //Ed448 key pair?
         if(context->certKey.type == X509_KEY_TYPE_ED448)
         {
            //Set public key identifier
            certReqInfo->subjectPublicKeyInfo.oid = ED448_OID;
            certReqInfo->subjectPublicKeyInfo.oidLen = sizeof(ED448_OID);

            //Select the signature algorithm
            signatureAlgo.oid = ED448_OID;
            signatureAlgo.oidLen = sizeof(ED448_OID);
         }
         else
#endif
         //Invalid key pair?
         {
            //Report an error
            error = ERROR_INVALID_KEY;
         }
      }

      //Check status code
      if(!error)
      {
         //Validity period
         validity.notBefore.year = 2018;
         validity.notBefore.month = 1;
         validity.notBefore.day = 1;
         validity.notBefore.hours = 12;
         validity.notBefore.minutes = 0;
         validity.notBefore.seconds = 0;
         validity.notAfter.year = 2019;
         validity.notAfter.month = 1;
         validity.notAfter.day = 1;
         validity.notAfter.hours = 12;
         validity.notAfter.minutes = 0;
         validity.notAfter.seconds = 0;

         //Create a self-signed certificate
         error = x509CreateCertificate(context->prngAlgo, context->prngContext,
            certReqInfo, context->certKey.publicKey, NULL, NULL,
            &validity, &signatureAlgo, context->certKey.privateKey,
            (uint8_t *) context->buffer, &n);
      }

      //Check status code
      if(!error)
      {
         //Export the certificate to PEM format
         error = pemExportCertificate((uint8_t *) context->buffer, n,
            challenge->cert, &n);
      }

      //Release previously allocated memory
      cryptoFreeMem(certReqInfo);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
#else
   //TLS-ALPN challenge is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
