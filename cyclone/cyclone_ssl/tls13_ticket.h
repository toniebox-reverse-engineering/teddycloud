/**
 * @file tls13_ticket.h
 * @brief TLS 1.3 session tickets
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

#ifndef _TLS13_TICKET_H
#define _TLS13_TICKET_H

//Dependencies
#include "tls.h"

//TLS related functions
bool_t tls13IsTicketValid(TlsContext *context);

error_t tls13SaveSessionTicket(const TlsContext *context,
   TlsSessionState *session);

error_t tls13RestoreSessionTicket(TlsContext *context,
   const TlsSessionState *session);

error_t tls13GenerateTicket(TlsContext *context,
   const Tls13NewSessionTicket *message, uint8_t *ticket, size_t *length);

error_t tls13VerifyTicket(TlsContext *context, const uint8_t *ticket,
   size_t length, uint32_t obfuscatedTicketAge);

#endif
