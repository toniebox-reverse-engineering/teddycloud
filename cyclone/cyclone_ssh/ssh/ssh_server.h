/**
 * @file ssh_server.h
 * @brief SSH server
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

#ifndef _SSH_SERVER_H
#define _SSH_SERVER_H

//Dependencies
#include "ssh/ssh.h"

//Stack size required to run the SSH server
#ifndef SSH_SERVER_STACK_SIZE
   #define SSH_SERVER_STACK_SIZE 750
#elif (SSH_SERVER_STACK_SIZE < 1)
   #error SSH_SERVER_STACK_SIZE parameter is not valid
#endif

//Priority at which the SSH server should run
#ifndef SSH_SERVER_PRIORITY
   #define SSH_SERVER_PRIORITY OS_TASK_PRIORITY_NORMAL
#endif

//Idle connection timeout
#ifndef SSH_SERVER_TIMEOUT
   #define SSH_SERVER_TIMEOUT 60000
#elif (SSH_SERVER_TIMEOUT < 1000)
   #error SSH_SERVER_TIMEOUT parameter is not valid
#endif

//SSH server tick interval
#ifndef SSH_SERVER_TICK_INTERVAL
   #define SSH_SERVER_TICK_INTERVAL 1000
#elif (SSH_SERVER_TICK_INTERVAL < 100)
   #error SSH_SERVER_TICK_INTERVAL parameter is not valid
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SSH server settings
 **/

typedef struct
{
   NetInterface *interface;                                      ///<Underlying network interface
   uint16_t port;                                                ///<SSH port number
   systime_t timeout;                                            ///<Idle connection timeout
   uint_t numConnections;                                        ///<Maximum number of SSH connections
   SshConnection *connections;                                   ///<SSH connections
   uint_t numChannels;                                           ///<Maximum number of SSH channels
   SshChannel *channels;                                         ///<SSH channels
   const PrngAlgo *prngAlgo;                                     ///<Pseudo-random number generator to be used
   void *prngContext;                                            ///<Pseudo-random number generator context
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
   SshPublicKeyAuthCallback publicKeyAuthCallback;               ///<Public key authentication callback
#endif
#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)
   SshCertAuthCallback certAuthCallback;                         ///<Certificate authentication callback
   SshCaPublicKeyVerifyCallback caPublicKeyVerifyCallback;       ///<CA public key verification callback
#endif
#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
   SshPasswordAuthCallback passwordAuthCallback;                 ///<Password authentication callback
   SshPasswordChangeCallback passwordChangeCallback;             ///<Password change callback
#endif
#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
   SshSignGenCallback signGenCallback;                           ///<Signature generation callback
   SshSignVerifyCallback signVerifyCallback;                     ///<Signature verification callback
#endif
#if (SSH_ECDH_CALLBACK_SUPPORT == ENABLED)
   SshEcdhKeyPairGenCallback ecdhKeyPairGenCallback;             ///<ECDH key pair generation callback
   SshEcdhSharedSecretCalcCallback ecdhSharedSecretCalcCallback; ///<ECDH shared secret calculation callback
#endif
} SshServerSettings;


/**
 * @brief SSH server context
 **/

typedef struct
{
   bool_t running;                               ///<Operational state of the SSH server
   bool_t stop;                                  ///<Stop request
   OsTaskId taskId;                              ///<Task identifier
#if (OS_STATIC_TASK_SUPPORT == ENABLED)
   OsTaskTcb taskTcb;                            ///<Task control block
   OsStackType taskStack[SSH_SERVER_STACK_SIZE]; ///<Task stack
#endif
   NetInterface *interface;                      ///<Underlying network interface
   Socket *socket;                               ///<Listening socket
   uint16_t port;                                ///<SSH port number
   systime_t timeout;                            ///<Idle connection timeout
   SshContext sshContext;                        ///<SSH context
} SshServerContext;


//SSH server related functions
void sshServerGetDefaultSettings(SshServerSettings *settings);

error_t sshServerInit(SshServerContext *context,
   const SshServerSettings *settings);

error_t sshServerRegisterGlobalRequestCallback(SshServerContext *context,
   SshGlobalReqCallback callback, void *param);

error_t sshServerUnregisterGlobalRequestCallback(SshServerContext *context,
   SshGlobalReqCallback callback);

error_t sshServerRegisterChannelRequestCallback(SshServerContext *context,
   SshChannelReqCallback callback, void *param);

error_t sshServerUnregisterChannelRequestCallback(SshServerContext *context,
   SshChannelReqCallback callback);

error_t sshServerRegisterChannelOpenCallback(SshServerContext *context,
   SshChannelOpenCallback callback, void *param);

error_t sshServerUnregisterChannelOpenCallback(SshServerContext *context,
   SshChannelOpenCallback callback);

error_t sshServerRegisterConnectionOpenCallback(SshServerContext *context,
   SshConnectionOpenCallback callback, void *param);

error_t sshServerUnregisterConnectionOpenCallback(SshServerContext *context,
   SshConnectionOpenCallback callback);

error_t sshServerRegisterConnectionCloseCallback(SshServerContext *context,
   SshConnectionCloseCallback callback, void *param);

error_t sshServerUnregisterConnectionCloseCallback(SshServerContext *context,
   SshConnectionCloseCallback callback);

error_t sshServerLoadRsaKey(SshServerContext *context, uint_t index,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen);

error_t sshServerUnloadRsaKey(SshServerContext *context, uint_t index);

error_t sshServerLoadDhGexGroup(SshServerContext *context, uint_t index,
   const char_t *dhParams, size_t dhParamsLen);

error_t sshServerUnloadDhGexGroup(SshServerContext *context, uint_t index);

error_t sshServerLoadHostKey(SshServerContext *context, uint_t index,
   const char_t *publicKey, size_t publicKeyLen,
   const char_t *privateKey, size_t privateKeyLen);

error_t sshServerUnloadHostKey(SshServerContext *context, uint_t index);

error_t sshServerLoadCertificate(SshServerContext *context, uint_t index,
   const char_t *cert, size_t certLen, const char_t *privateKey,
   size_t privateKeyLen);

error_t sshServerUnloadCertificate(SshServerContext *context, uint_t index);

error_t sshServerStart(SshServerContext *context);
error_t sshServerStop(SshServerContext *context);

void sshServerTask(SshServerContext *context);

void sshServerDeinit(SshServerContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
