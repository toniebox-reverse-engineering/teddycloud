/**
 * @file acme_client_account.h
 * @brief Account object management
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

#ifndef _ACME_CLIENT_ACCOUNT_H
#define _ACME_CLIENT_ACCOUNT_H

//Dependencies
#include "acme/acme_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//ACME client related functions
error_t acmeClientCheckAccountParams(const AcmeAccountParams *params);

error_t acmeClientSendNewAccountRequest(AcmeClientContext *context,
   const AcmeAccountParams *params, bool_t onlyReturnExisting);

error_t acmeClientFormatNewAccountRequest(AcmeClientContext *context,
   const AcmeAccountParams *params, bool_t onlyReturnExisting);

error_t acmeClientParseNewAccountResponse(AcmeClientContext *context);

error_t acmeClientSendUpdateAccountRequest(AcmeClientContext *context,
   const AcmeAccountParams *params);

error_t acmeFormatUpdateAccountRequest(AcmeClientContext *context,
   const AcmeAccountParams *params);

error_t acmeClientParseUpdateAccountResponse(AcmeClientContext *context);

error_t acmeClientSendKeyChangeRequest(AcmeClientContext *context,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen);

error_t acmeClientFormatKeyChangeRequest(AcmeClientContext *context,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen);

error_t acmeClientParseKeyChangeResponse(AcmeClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
