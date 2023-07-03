/**
 * @file acme_client_order.h
 * @brief Order object management
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

#ifndef _ACME_CLIENT_ORDER_H
#define _ACME_CLIENT_ORDER_H

//Dependencies
#include "acme/acme_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//ACME client related functions
error_t acmeClientCheckOrderParams(const AcmeOrderParams *params);

error_t acmeClientInitOrder(AcmeClientContext *context,
   const AcmeOrderParams *params);

error_t acmeClientSendNewOrderRequest(AcmeClientContext *context,
   const AcmeOrderParams *params);

error_t acmeClientFormatNewOrderRequest(AcmeClientContext *context,
   const AcmeOrderParams *params);

error_t acmeClientParseNewOrderResponse(AcmeClientContext *context);

error_t acmeClientSendOrderStatusRequest(AcmeClientContext *context);
error_t acmeClientFormatOrderStatusRequest(AcmeClientContext *context);
error_t acmeClientParseOrderStatusResponse(AcmeClientContext *context);

error_t acmeClientSendFinalizeOrderRequest(AcmeClientContext *context);
error_t acmeClientFormatFinalizeOrderRequest(AcmeClientContext *context);
error_t acmeClientParseFinalizeOrderResponse(AcmeClientContext *context);

AcmeOrderStatus acmeClientParseOrderStatus(const char_t *label);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
