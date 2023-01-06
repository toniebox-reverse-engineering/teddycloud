/**
 * @file ssh_auth.h
 * @brief SSH user authentication protocol
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

#ifndef _SSH_AUTH_H
#define _SSH_AUTH_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Authentication methods
 **/

typedef enum
{
   SSH_AUTH_METHOD_NONE       = 0,
   SSH_AUTH_METHOD_PASSWORD   = 1,
   SSH_AUTH_METHOD_PUBLIC_KEY = 2,
   SSH_AUTH_METHOD_HOST_BASED = 3
} SshAuthMethod;


//SSH related functions
error_t sshSendUserAuthBanner(SshConnection *connection,
   const char_t *banner);

error_t sshSendUserAuthRequest(SshConnection *connection);
error_t sshSendUserAuthSuccess(SshConnection *connection);
error_t sshSendUserAuthFailure(SshConnection *connection);

error_t sshAcceptAuthRequest(SshConnection *connection);
error_t sshRejectAuthRequest(SshConnection *connection);

error_t sshFormatUserAuthBanner(SshConnection *connection,
   const char_t *banner, uint8_t *p, size_t *length);

error_t sshFormatUserAuthRequest(SshConnection *connection, uint8_t *message,
   size_t *length);

error_t sshFormatNoneAuthParams(SshConnection *connection, uint8_t *p,
   size_t *written);

error_t sshFormatUserAuthSuccess(SshConnection *connection, uint8_t *p,
   size_t *length);

error_t sshFormatUserAuthFailure(SshConnection *connection, uint8_t *p,
   size_t *length);

error_t sshFormatUserAuthMethods(SshConnection *connection, uint8_t *p,
   size_t *written);

error_t sshParseUserAuthBanner(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseUserAuthRequest(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseNoneAuthParams(SshConnection *connection,
   const SshString *userName, const uint8_t *p, size_t length);

error_t sshParseUserAuthSuccess(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseUserAuthFailure(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseUserAuthMessage(SshConnection *connection, uint8_t type,
   const uint8_t *message, size_t length);

SshAuthMethod sshGetAuthMethod(SshConnection *connection);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
