/**
 * @file scp_server_misc.h
 * @brief Helper functions for SCP server
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

#ifndef _SCP_SERVER_MISC_H
#define _SCP_SERVER_MISC_H

//Dependencies
#include "scp/scp_server.h"
#include "ssh/ssh_request.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SCP server related functions
void scpServerTick(ScpServerContext *context);

error_t scpServerChannelRequestCallback(SshChannel *channel,
   const SshString *type, const uint8_t *data, size_t length,
   void *param);

void scpServerParseCommandLine(ScpServerSession *session,
   const SshExecParams *requestParams);

ScpServerSession *scpServerFindSession(ScpServerContext *context,
   SshChannel *channel);

ScpServerSession *scpServerOpenSession(ScpServerContext *context,
   SshChannel *channel);

void scpServerCloseSession(ScpServerSession *session);

void scpServerRegisterSessionEvents(ScpServerSession *session,
   SshChannelEventDesc *eventDesc);

void scpServerProcessSessionEvents(ScpServerSession *session);

error_t scpServerSendDirective(ScpServerSession *session,
   const ScpDirective *directive);

error_t scpServerReceiveDirective(ScpServerSession *session,
   ScpDirective *directive);

void scpServerProcessDirective(ScpServerSession *session,
   const ScpDirective *directive);

uint_t scpServerGetFilePermissions(ScpServerSession *session,
   const char_t *path);

error_t scpServerGetPath(ScpServerSession *session, const SshString *path,
   char_t *fullPath, size_t maxLen);

const char_t *scpServerStripRootDir(ScpServerSession *session,
   const char_t *path);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
