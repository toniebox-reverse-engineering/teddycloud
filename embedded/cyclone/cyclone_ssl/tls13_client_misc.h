/**
 * @file tls13_client_misc.h
 * @brief Helper functions for TLS 1.3 client
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

#ifndef _TLS13_CLIENT_MISC_H
#define _TLS13_CLIENT_MISC_H

//Dependencies
#include "tls.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//TLS 1.3 client specific functions
bool_t tls13IsHelloRetryRequest(const TlsServerHello *message, size_t length);

error_t tls13ComputePskBinders(TlsContext *context, const void *clientHello,
   size_t clientHelloLen, const Tls13PskIdentityList *identityList,
   Tls13PskBinderList *binderList);

error_t tls13SendEarlyData(TlsContext *context, const void *data,
   size_t length, size_t *written);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
