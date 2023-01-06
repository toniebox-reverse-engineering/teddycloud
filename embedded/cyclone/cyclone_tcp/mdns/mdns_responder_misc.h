/**
 * @file mdns_responder_misc.h
 * @brief Helper functions for mDNS responder
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

#ifndef _MDNS_RESPONDER_MISC_H
#define _MDNS_RESPONDER_MISC_H

//Dependencies
//Dependencies
#include "core/net.h"
#include "mdns/mdns_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//mDNS related functions
void mdnsResponderChangeState(MdnsResponderContext *context,
   MdnsState newState, systime_t delay);

void mdnsResponderChangeHostname(MdnsResponderContext *context);

error_t mdnsResponderSendProbe(MdnsResponderContext *context);
error_t mdnsResponderSendAnnouncement(MdnsResponderContext *context);
error_t mdnsResponderSendGoodbye(MdnsResponderContext *context);

void mdnsResponderProcessQuery(NetInterface *interface, MdnsMessage *query);

error_t mdnsResponderParseQuestion(NetInterface *interface,
   const MdnsMessage *query, size_t offset, const DnsQuestion *question,
   MdnsMessage *response);

void mdnsResponderParseKnownAnRecord(NetInterface *interface,
   const MdnsMessage *query, size_t queryOffset,
   const DnsResourceRecord *queryRecord, MdnsMessage *response);

void mdnsResponderParseAnRecord(NetInterface *interface,
   const MdnsMessage *response, size_t offset, const DnsResourceRecord *record);

void mdnsResponderParseNsRecords(MdnsResponderContext *context,
   const MdnsMessage *query, size_t offset);

void mdnsResponderGenerateAdditionalRecords(MdnsResponderContext *context,
   MdnsMessage *response, bool_t legacyUnicast);

error_t mdnsResponderGenerateIpv4AddrRecords(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl);

error_t mdnsResponderGenerateIpv6AddrRecords(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl);

error_t mdnsResponderGenerateIpv4PtrRecords(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl);

error_t mdnsResponderGenerateIpv6PtrRecords(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl);

error_t mdnsResponderFormatIpv4AddrRecord(MdnsResponderContext *context,
   MdnsMessage *message, const uint8_t *ipv4Addr, bool_t cacheFlush,
   uint32_t ttl);

error_t mdnsResponderFormatIpv6AddrRecord(MdnsResponderContext *context,
   MdnsMessage *message, const uint8_t *ipv6Addr, bool_t cacheFlush,
   uint32_t ttl);

error_t mdnsResponderFormatIpv4PtrRecord(MdnsResponderContext *context,
   MdnsMessage *message, const char_t *reverseName, bool_t cacheFlush,
   uint32_t ttl);

error_t mdnsResponderFormatIpv6PtrRecord(MdnsResponderContext *context,
   MdnsMessage *message, const char_t *reverseName, bool_t cacheFlush,
   uint32_t ttl);

error_t mdnsResponderFormatNsecRecord(MdnsResponderContext *context,
   MdnsMessage *message, bool_t cacheFlush, uint32_t ttl);

DnsResourceRecord *mdnsResponderGetNextHostRecord(MdnsResponderContext *context,
   DnsResourceRecord *record);

DnsResourceRecord *mdnsResponderGetNextTiebreakerRecord(MdnsResponderContext *context,
   const MdnsMessage *query, size_t offset, DnsResourceRecord *record);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
