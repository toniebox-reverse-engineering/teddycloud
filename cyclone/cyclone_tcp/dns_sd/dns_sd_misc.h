/**
 * @file dns_sd_misc.h
 * @brief Helper functions for DNS-SD
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneTCP Open.
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

#ifndef _DNS_SD_MISC_H
#define _DNS_SD_MISC_H

//Dependencies
#include "core/net.h"
#include "dns_sd/dns_sd.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//DNS-SD related functions
void dnsSdChangeState(DnsSdContext *context, MdnsState newState,
   systime_t delay);

void dnsSdChangeInstanceName(DnsSdContext *context);

error_t dnsSdSendProbe(DnsSdContext *context);
error_t dnsSdSendAnnouncement(DnsSdContext *context);
error_t dnsSdSendGoodbye(DnsSdContext *context, const DnsSdService *service);

error_t dnsSdParseQuestion(NetInterface *interface, const MdnsMessage *query,
   size_t offset, const DnsQuestion *question, MdnsMessage *response);

void dnsSdParseNsRecord(NetInterface *interface, const MdnsMessage *query,
   size_t offset, const DnsResourceRecord *record);

void dnsSdParseAnRecord(NetInterface *interface, const MdnsMessage *response,
   size_t offset, const DnsResourceRecord *record);

void dnsSdGenerateAdditionalRecords(NetInterface *interface,
   MdnsMessage *response, bool_t legacyUnicast);

error_t dnsSdFormatServiceEnumPtrRecord(NetInterface *interface,
   MdnsMessage *message, const DnsSdService *service, uint32_t ttl);

error_t dnsSdFormatPtrRecord(NetInterface *interface,
   MdnsMessage *message, const DnsSdService *service, uint32_t ttl);

error_t dnsSdFormatSrvRecord(NetInterface *interface, MdnsMessage *message,
   const DnsSdService *service, bool_t cacheFlush, uint32_t ttl);

error_t dnsSdFormatTxtRecord(NetInterface *interface, MdnsMessage *message,
   const DnsSdService *service, bool_t cacheFlush, uint32_t ttl);

error_t dnsSdFormatNsecRecord(NetInterface *interface, MdnsMessage *message,
   const DnsSdService *service, bool_t cacheFlush, uint32_t ttl);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
