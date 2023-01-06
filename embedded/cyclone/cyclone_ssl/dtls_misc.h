/**
 * @file dtls_misc.h
 * @brief DTLS (Datagram Transport Layer Security)
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

#ifndef _DTLS_MISC_H
#define _DTLS_MISC_H

//DTLS version numbers
#define DTLS_VERSION_1_0 0xFEFF
#define DTLS_VERSION_1_2 0xFEFD
#define DTLS_VERSION_1_3 0xFEFC

//DTLS support
#ifndef DTLS_SUPPORT
   #define DTLS_SUPPORT DISABLED
#elif (DTLS_SUPPORT != ENABLED && DTLS_SUPPORT != DISABLED)
   #error DTLS_SUPPORT parameter is not valid
#endif

//Default PMTU value
#ifndef DTLS_DEFAULT_PMTU
   #define DTLS_DEFAULT_PMTU 1452
#elif (DTLS_DEFAULT_PMTU < 64)
   #error DTLS_DEFAULT_PMTU parameter is not valid
#endif

//Minimum PMTU value
#ifndef DTLS_MIN_PMTU
   #define DTLS_MIN_PMTU 528
#elif (DTLS_MIN_PMTU < 64)
   #error DTLS_MIN_PMTU parameter is not valid
#endif

//Replay protection
#ifndef DTLS_REPLAY_DETECTION_SUPPORT
   #define DTLS_REPLAY_DETECTION_SUPPORT ENABLED
#elif (DTLS_REPLAY_DETECTION_SUPPORT != ENABLED && DTLS_REPLAY_DETECTION_SUPPORT != DISABLED)
   #error DTLS_REPLAY_DETECTION_SUPPORT parameter is not valid
#endif

//Size of the sliding window for replay protection
#ifndef DTLS_REPLAY_WINDOW_SIZE
   #define DTLS_REPLAY_WINDOW_SIZE 64
#elif (DTLS_REPLAY_WINDOW_SIZE < 1)
   #error DTLS_REPLAY_WINDOW_SIZE parameter is not valid
#endif

//Maximum size for cookies
#ifndef DTLS_MAX_COOKIE_SIZE
   #define DTLS_MAX_COOKIE_SIZE 32
#elif (DTLS_MAX_COOKIE_SIZE < 32)
   #error DTLS_MAX_COOKIE_SIZE parameter is not valid
#endif

//Maximum number of retransmissions
#ifndef DTLS_MAX_RETRIES
   #define DTLS_MAX_RETRIES 5
#elif (DTLS_MAX_RETRIES < 1)
   #error DTLS_MAX_RETRIES parameter is not valid
#endif

//Initial retransmission timeout
#ifndef DTLS_INIT_TIMEOUT
   #define DTLS_INIT_TIMEOUT 1000
#elif (DTLS_INIT_TIMEOUT < 100)
   #error DTLS_INIT_TIMEOUT parameter is not valid
#endif

//Minimum retransmission timeout
#ifndef DTLS_MIN_TIMEOUT
   #define DTLS_MIN_TIMEOUT 500
#elif (DTLS_MIN_TIMEOUT < 100)
   #error DTLS_MIN_TIMEOUT parameter is not valid
#endif

//Maximum retransmission timeout
#ifndef DTLS_MAX_TIMEOUT
   #define DTLS_MAX_TIMEOUT 60000
#elif (DTLS_MAX_TIMEOUT < 1000)
   #error DTLS_MAX_TIMEOUT parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief DTLS retransmission states
 **/

typedef enum
{
   DTLS_RETRANSMIT_STATE_PREPARING = 0,
   DTLS_RETRANSMIT_STATE_SENDING   = 1,
   DTLS_RETRANSMIT_STATE_WAITING   = 2,
   DTLS_RETRANSMIT_STATE_FINISHED  = 3
} DtlsRetransmitState;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief Sequence number
 **/

typedef __start_packed struct
{
   uint8_t b[6];
} DtlsSequenceNumber;


/**
 * @brief Cookie
 **/

typedef __start_packed struct
{
   uint8_t length;  //0
   uint8_t value[]; //1
} __end_packed DtlsCookie;


/**
 * @brief List of supported versions
 **/

typedef __start_packed struct
{
   uint8_t length;   //0
   uint16_t value[]; //1
} __end_packed DtlsSupportedVersionList;


/**
 * @brief DTLS record
 **/

typedef __start_packed struct
{
   uint8_t type;              //0
   uint16_t version;          //1-2
   uint16_t epoch;            //3-4
   DtlsSequenceNumber seqNum; //5-10
   uint16_t length;           //11-12
   uint8_t data[];            //13
} __end_packed DtlsRecord;


/**
 * @brief DTLS handshake message
 **/

typedef __start_packed struct
{
   uint8_t msgType;       //0
   uint8_t length[3];     //1-3
   uint16_t msgSeq;       //4-5
   uint8_t fragOffset[3]; //6-8
   uint8_t fragLength[3]; //9-11
   uint8_t data[];        //12
} __end_packed DtlsHandshake;


/**
 * @brief HelloVerifyRequest message
 **/

typedef __start_packed struct
{
   uint16_t serverVersion; //0-1
   uint8_t cookieLength;   //2
   uint8_t cookie[];       //3
} __end_packed DtlsHelloVerifyRequest;


//CodeWarrior or Win32 compiler?
#if defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif


/**
 * @brief Client parameters
 **/

typedef struct
{
   uint16_t version;
   const uint8_t *random;
   size_t randomLen;
   const uint8_t *sessionId;
   size_t sessionIdLen;
   const uint8_t *cipherSuites;
   size_t cipherSuitesLen;
   const uint8_t *compressMethods;
   size_t compressMethodsLen;
} DtlsClientParameters;


/**
 * @brief DTLS cookie generation callback function
 **/

typedef error_t (*DtlsCookieGenerateCallback)(TlsContext *context,
   const DtlsClientParameters *clientParams, uint8_t *cookie,
   size_t *length, void *param);


/**
 * @brief DTLS cookie verification callback function
 **/

typedef error_t (*DtlsCookieVerifyCallback)(TlsContext *context,
   const DtlsClientParameters *clientParams, const uint8_t *cookie,
   size_t length, void *param);


//DTLS specific functions
error_t dtlsSelectVersion(TlsContext *context, uint16_t version);
uint16_t dtlsTranslateVersion(uint16_t version);

error_t dtlsFormatCookie(TlsContext *context, uint8_t *p, size_t *written);

error_t dtlsVerifyCookie(TlsContext *context, const DtlsCookie *cookie,
   const DtlsClientParameters *clientParams);

error_t dtlsSendHelloVerifyRequest(TlsContext *context);

error_t dtlsFormatHelloVerifyRequest(TlsContext *context,
   DtlsHelloVerifyRequest *message, size_t *length);

error_t dtlsParseHelloVerifyRequest(TlsContext *context,
   const DtlsHelloVerifyRequest *message, size_t length);

error_t dtlsParseClientSupportedVersionsExtension(TlsContext *context,
   const DtlsSupportedVersionList *supportedVersionList);

void dtlsInitReplayWindow(TlsContext *context);
error_t dtlsCheckReplayWindow(TlsContext *context, DtlsSequenceNumber *seqNum);
void dtlsUpdateReplayWindow(TlsContext *context, DtlsSequenceNumber *seqNum);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
