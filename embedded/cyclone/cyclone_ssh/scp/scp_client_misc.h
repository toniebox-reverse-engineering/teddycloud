/**
 * @file scp_client_misc.h
 * @brief Helper functions for SCP client
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSH Open.
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

#ifndef _SCP_CLIENT_MISC_H
#define _SCP_CLIENT_MISC_H

//Dependencies
#include "scp/scp_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SCP client related functions
void scpClientChangeState(ScpClientContext *context,
   ScpClientState newState);

error_t scpClientOpenConnection(ScpClientContext *context);
error_t scpClientEstablishConnection(ScpClientContext *context);
void scpClientCloseConnection(ScpClientContext *context);

error_t scpClientSendDirective(ScpClientContext *context,
   const ScpDirective *directive);

error_t scpClientReceiveDirective(ScpClientContext *context,
   ScpDirective *directive);

error_t scpClientProcessEvents(ScpClientContext *context);
error_t scpClientCheckTimeout(ScpClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
