/**
 * @file acme_dns_client_misc.h
 * @brief Helper functions for ACME-DNS client
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

#ifndef _ACME_DNS_CLIENT_MISC_H
#define _ACME_DNS_CLIENT_MISC_H

//Dependencies
#include "dns_api/acme_dns_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//ACME-DNS client related functions
error_t acmeDnsClientFormatRegisterRequest(AcmeDnsClientContext *context);
error_t acmeDnsClientParseRegisterResponse(AcmeDnsClientContext *context);

error_t acmeDnsClientFormatUpdateRequest(AcmeDnsClientContext *context,
   const char_t *txt);

error_t acmeDnsClientParseUpdateResponse(AcmeDnsClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
