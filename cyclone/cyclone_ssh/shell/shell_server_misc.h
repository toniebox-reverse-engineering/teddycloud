/**
 * @file shell_server_misc.h
 * @brief Helper functions for SSH secure shell server
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

#ifndef _SHELL_SERVER_MISC_H
#define _SHELL_SERVER_MISC_H

//Dependencies
#include "shell/shell_server.h"
#include "ssh/ssh_request.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Shell server related functions
void shellServerTick(ShellServerContext *context);

error_t shellServerChannelRequestCallback(SshChannel *channel,
   const SshString *type, const uint8_t *data, size_t length,
   void *param);

ShellServerSession *shellServerFindSession(ShellServerContext *context,
   SshChannel *channel);

ShellServerSession *shellServerOpenSession(ShellServerContext *context,
   SshChannel *channel);

void shellServerCloseSession(ShellServerSession *session);

error_t shellServerParseTermModes(ShellServerSession *session,
   const uint8_t *termModes, size_t length);

error_t shellServerProcessCommandLine(ShellServerSession *session,
   char_t *commandLine);

void shellServerAddCommandLine(ShellServerSession *session,
   const char_t *commandLine);

error_t shellServerGetPrevCommandLine(ShellServerSession *session,
   const char_t **commandLine, size_t *length);

error_t shellServerGetNextCommandLine(ShellServerSession *session,
   const char_t **commandLine, size_t *length);

error_t shellServerGetFirstCommandLine(ShellServerSession *session,
   const char_t **commandLine, size_t *length);

error_t shellServerGetLastCommandLine(ShellServerSession *session,
   const char_t **commandLine, size_t *length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
