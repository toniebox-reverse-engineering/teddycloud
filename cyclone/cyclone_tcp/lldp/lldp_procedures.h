/**
 * @file lldp_procedures.h
 * @brief LLDP state machine procedures
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

#ifndef _LLDP_PROCEDURES_H
#define _LLDP_PROCEDURES_H

//Dependencies
#include "core/net.h"
#include "lldp/lldp.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//LLDP agent related functions
void lldpMibConstrInfoLldpdu(LldpPortEntry *port);
void lldpMibConstrShutdownLldpdu(LldpPortEntry *port);
void lldpTxFrame(LldpPortEntry *port);
void lldpTxInitializeLLDP(LldpPortEntry *port);
void lldpMibDeleteObjects(LldpPortEntry *port);
void lldpMibUpdateObjects(LldpPortEntry *port);
void lldpRxInitializeLLDP(LldpPortEntry *port);
void lldpRxProcessFrame(LldpPortEntry *port);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
