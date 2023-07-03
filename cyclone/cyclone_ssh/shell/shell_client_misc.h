/**
 * @file shell_client_misc.h
 * @brief Helper functions for SSH secure shell client
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

#ifndef _SHELL_CLIENT_MISC_H
#define _SHELL_CLIENT_MISC_H

//Dependencies
#include "shell/shell_client.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Shell client related functions
void shellClientChangeState(ShellClientContext *context,
   ShellClientState newState);

error_t shellClientChannelRequestCallback(SshChannel *channel,
   const SshString *type, const uint8_t *data, size_t length,
   void *param);

error_t shellClientOpenConnection(ShellClientContext *context);
error_t shellClientEstablishConnection(ShellClientContext *context);
void shellClientCloseConnection(ShellClientContext *context);

error_t shellClientProcessEvents(ShellClientContext *context);
error_t shellClientCheckTimeout(ShellClientContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
