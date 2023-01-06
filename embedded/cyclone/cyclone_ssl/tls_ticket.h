/**
 * @file tls_ticket.h
 * @brief TLS session tickets
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

#ifndef _TLS_TICKET_H
#define _TLS_TICKET_H

//Dependencies
#include "tls.h"
#include "cipher/aes.h"
#include "aead/gcm.h"

//Size of ticket key names
#ifndef TLS_TICKET_KEY_NAME_SIZE
   #define TLS_TICKET_KEY_NAME_SIZE 16
#elif (TLS_TICKET_KEY_NAME_SIZE < 1)
   #error TLS_TICKET_KEY_NAME_SIZE parameter is not valid
#endif

//Size of ticket keys
#ifndef TLS_TICKET_KEY_SIZE
   #define TLS_TICKET_KEY_SIZE 32
#elif (TLS_TICKET_KEY_SIZE < 1)
   #error TLS_TICKET_KEY_SIZE parameter is not valid
#endif

//Size of ticket IVs
#ifndef TLS_TICKET_IV_SIZE
   #define TLS_TICKET_IV_SIZE 12
#elif (TLS_TICKET_IV_SIZE < 1)
   #error TLS_TICKET_IV_SIZE parameter is not valid
#endif

//Size of ticket authentication tags
#ifndef TLS_TICKET_TAG_SIZE
   #define TLS_TICKET_TAG_SIZE 16
#elif (TLS_TICKET_TAG_SIZE < 1)
   #error TLS_TICKET_TAG_SIZE parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Session ticket encryption state
 **/

typedef struct
{
   bool_t valid;                              ///<Valid set of keys
   systime_t timestamp;                       ///<Generation time
   uint8_t keyName[TLS_TICKET_KEY_NAME_SIZE]; ///<Key identifier
   uint8_t key[TLS_TICKET_KEY_SIZE];          ///<Encryption key
} TlsTicketEncryptionState;


/**
 * @brief Session ticket encryption context
 **/

typedef struct
{
   OsMutex mutex;                                ///<Mutex preventing simultaneous access to the context
   TlsTicketEncryptionState encryptionState;     ///<Current set of keys
   TlsTicketEncryptionState prevEncryptionState; ///<Previous set of keys
   AesContext aesContext;                        ///<AES context
   GcmContext gcmContext;                        ///<GCM context
} TlsTicketContext;


//TLS related functions
error_t tlsInitTicketContext(TlsTicketContext *ticketContext);

error_t tlsEncryptTicket(TlsContext *context, const uint8_t *plaintext,
   size_t plaintextLen, uint8_t *ciphertext, size_t *ciphertextLen, void *param);

error_t tlsDecryptTicket(TlsContext *context, const uint8_t *ciphertext,
   size_t ciphertextLen, uint8_t *plaintext, size_t *plaintextLen, void *param);

error_t tlsGenerateTicketKeys(TlsTicketContext *ticketContext,
   const PrngAlgo *prngAlgo, void *prngContext);

void tlsCheckTicketKeyLifetime(TlsTicketEncryptionState *state);

bool_t tlsCompareTicketKeyName(const uint8_t *ticket, size_t ticketLen,
   const TlsTicketEncryptionState *state);

void tlsFreeTicketContext(TlsTicketContext *ticketContext);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
