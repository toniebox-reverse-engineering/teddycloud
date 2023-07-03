/**
 * @file ssh_legacy.h
 * @brief Legacy definitions
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

#ifndef _SSH_LEGACY_H
#define _SSH_LEGACY_H

//Deprecated definitions
#define SshClientConnection SshConnection
#define passwordCallback passwordAuthCallback
#define termWidthChar termWidthChars
#define termHeightChar termHeightRows
#define termWidthPixel termWidthPixels
#define termHeightPixel termHeightPixels

//Deprecated functions
#define sshServerSetTimeout sshSetChannelTimeout
#define sshServerWriteChannel sshWriteChannel
#define sshServerReadChannel sshReadChannel
#define sshServerTerminateChannel sshCloseChannel

#ifdef SSH_RC4_SUPPORT
   #define SSH_RC4_128_SUPPORT SSH_RC4_SUPPORT
   #define SSH_RC4_256_SUPPORT SSH_RC4_SUPPORT
#endif

#ifdef SSH_AES_SUPPORT
   #define SSH_AES_128_SUPPORT SSH_AES_SUPPORT
   #define SSH_AES_192_SUPPORT SSH_AES_SUPPORT
   #define SSH_AES_256_SUPPORT SSH_AES_SUPPORT
#endif

#ifdef SSH_CAMELLIA_SUPPORT
   #define SSH_CAMELLIA_128_SUPPORT SSH_CAMELLIA_SUPPORT
   #define SSH_CAMELLIA_192_SUPPORT SSH_CAMELLIA_SUPPORT
   #define SSH_CAMELLIA_256_SUPPORT SSH_CAMELLIA_SUPPORT
#endif

#define generateSignatureCallback signGenCallback

#ifdef SCP_SERVER_STACK_SIZE
   #define SCP_SERVER_TASK_STACK_SIZE SCP_SERVER_STACK_SIZE
#endif

#ifdef SCP_SERVER_PRIORITY
   #define SCP_SERVER_TASK_PRIORITY SCP_SERVER_PRIORITY
#endif

#ifdef SFTP_SERVER_STACK_SIZE
   #define SFTP_SERVER_TASK_STACK_SIZE SFTP_SERVER_STACK_SIZE
#endif

#ifdef SFTP_SERVER_PRIORITY
   #define SFTP_SERVER_TASK_PRIORITY SFTP_SERVER_PRIORITY
#endif

#ifdef SHELL_SERVER_STACK_SIZE
   #define SHELL_SERVER_TASK_STACK_SIZE SHELL_SERVER_STACK_SIZE
#endif

#ifdef SHELL_SERVER_PRIORITY
   #define SHELL_SERVER_TASK_PRIORITY SHELL_SERVER_PRIORITY
#endif

#ifdef SSH_SERVER_STACK_SIZE
   #define SSH_SERVER_TASK_STACK_SIZE SSH_SERVER_STACK_SIZE
#endif

#ifdef SSH_SERVER_PRIORITY
   #define SSH_SERVER_TASK_PRIORITY SSH_SERVER_PRIORITY
#endif

#define SshAccessStatus SshAuthStatus
#define SSH_ACCESS_DENIED SSH_AUTH_STATUS_FAILURE
#define SSH_ACCESS_ALLOWED SSH_AUTH_STATUS_SUCCESS

#define SshWindowChangeReqParams SshWindowChangeParams
#define sshParseWindowChangeReqParams sshParseWindowChangeParams

#ifdef SSH_DH_SUPPORT
   #define SSH_DH_KEX_SUPPORT SSH_DH_SUPPORT
#endif

#ifdef SSH_ECDH_SUPPORT
   #define SSH_ECDH_KEX_SUPPORT SSH_ECDH_SUPPORT
#endif

#ifdef SSH_RSA_SUPPORT
   #define SSH_RSA_SIGN_SUPPORT SSH_RSA_SUPPORT
#endif

#ifdef SSH_DSA_SUPPORT
   #define SSH_DSA_SIGN_SUPPORT SSH_DSA_SUPPORT
#endif

#ifdef SSH_ECDSA_SUPPORT
   #define SSH_ECDSA_SIGN_SUPPORT SSH_ECDSA_SUPPORT
#endif

#ifdef SSH_ED25519_SUPPORT
   #define SSH_ED25519_SIGN_SUPPORT SSH_ED25519_SUPPORT
#endif

#ifdef SSH_ED448_SUPPORT
   #define SSH_ED448_SIGN_SUPPORT SSH_ED448_SUPPORT
#endif

#endif
