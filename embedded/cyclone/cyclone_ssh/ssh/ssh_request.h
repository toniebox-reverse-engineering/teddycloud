/**
 * @file ssh_request.h
 * @brief Global request and channel request handling
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

#ifndef _SSH_REQUEST_H
#define _SSH_REQUEST_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief "tcpip-forward" global request parameters
 **/

typedef struct
{
   SshString addrToBind;
   uint32_t portNumToBind;
} SshTcpIpFwdParams;


/**
 * @brief "cancel-tcpip-forward" global request parameters
 **/

typedef struct
{
   SshString addrToBind;
   uint32_t portNumToBind;
} SshCancelTcpIpFwdParams;


/**
 * @brief "elevation" global request parameters
 **/

typedef struct
{
   bool_t elevationPerformed;
} SshElevationParams;


/**
 * @brief "pty-req" channel request parameters
 **/

typedef struct
{
   SshString termEnvVar;
   uint32_t termWidthChars;
   uint32_t termHeightRows;
   uint32_t termWidthPixels;
   uint32_t termHeightPixels;
   SshBinaryString termModes;
} SshPtyReqParams;


/**
 * @brief "x11-req" channel request parameters
 **/

typedef struct
{
   bool_t singleConnection;
   SshString x11AuthProtocol;
   SshString x11AuthCookie;
   uint32_t x11ScreenNum;
} SshX11ReqParams;


/**
 * @brief "env" channel request parameters
 **/

typedef struct
{
   SshString varName;
   SshString varValue;
} SshEnvParams;


/**
 * @brief "exec" channel request parameters
 **/

typedef struct
{
   SshString command;
} SshExecParams;


/**
 * @brief "subsystem" channel request parameters
 **/

typedef struct
{
   SshString subsystemName;
} SshSubsystemParams;


/**
 * @brief "window-change" channel request parameters
 **/

typedef struct
{
   uint32_t termWidthChars;
   uint32_t termHeightRows;
   uint32_t termWidthPixels;
   uint32_t termHeightPixels;
} SshWindowChangeParams;


/**
 * @brief "xon-xoff" channel request parameters
 **/

typedef struct
{
   bool_t clientCanDo;
} SshXonXoffParams;


/**
 * @brief "signal" channel request parameters
 **/

typedef struct
{
   SshString signalName;
} SshSignalParams;


/**
 * @brief "exit-status" channel request parameters
 **/

typedef struct
{
   uint32_t exitStatus;
} SshExitStatusParams;


/**
 * @brief "exit-signal" channel request parameters
 **/

typedef struct
{
   SshString signalName;
   bool_t coreDumped;
   SshString errorMessage;
   SshString languageTag;
} SshExitSignalParams;


/**
 * @brief "break" channel request parameters
 **/

typedef struct
{
   uint32_t breakLen;
} SshBreakParams;


//SSH related functions
error_t sshSendGlobalRequest(SshConnection *connection,
   const char_t *requestName, const void *requestParams, bool_t wantReply);

error_t sshSendRequestSuccess(SshConnection *connection);
error_t sshSendRequestFailure(SshConnection *connection);

error_t sshSendChannelRequest(SshChannel *channel, const char_t *requestType,
   const void *requestParams, bool_t wantReply);

error_t sshSendChannelSuccess(SshChannel *channel);
error_t sshSendChannelFailure(SshChannel *channel);

error_t sshFormatGlobalRequest(SshConnection *connection,
   const char_t *requestName, const void *requestParams, bool_t wantReply,
   uint8_t *p, size_t *length);

error_t sshFormatTcpIpFwdParams(const SshTcpIpFwdParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatCancelTcpIpFwdParams(const SshCancelTcpIpFwdParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatElevationParams(const SshElevationParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatRequestSuccess(SshConnection *connection, uint8_t *p,
   size_t *length);

error_t sshFormatRequestFailure(SshConnection *connection, uint8_t *p,
   size_t *length);

error_t sshFormatChannelRequest(SshChannel *channel, const char_t *requestType,
   const void *requestParams, bool_t wantReply, uint8_t *p, size_t *length);

error_t sshFormatPtyReqParams(const SshPtyReqParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatExecParams(const SshExecParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatSubsystemParams(const SshSubsystemParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatWindowChangeParams(const SshWindowChangeParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatSignalParams(const SshSignalParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatExitStatusParams(const SshExitStatusParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatBreakParams(const SshBreakParams *params,
   uint8_t *p, size_t *written);

error_t sshFormatChannelSuccess(SshChannel *channel, uint8_t *p,
   size_t *length);

error_t sshFormatChannelFailure(SshChannel *channel, uint8_t *p,
   size_t *length);

error_t sshParseGlobalRequest(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseTcpIpFwdParams(const uint8_t *p, size_t length,
   SshTcpIpFwdParams *params);

error_t sshParseCancelTcpIpFwdParams(const uint8_t *p, size_t length,
   SshCancelTcpIpFwdParams *params);

error_t sshParseElevationParams(const uint8_t *p, size_t length,
   SshElevationParams *params);

error_t sshParseRequestSuccess(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseRequestFailure(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelRequest(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParsePtyReqParams(const uint8_t *p, size_t length,
   SshPtyReqParams *params);

error_t sshParseExecParams(const uint8_t *p, size_t length,
   SshExecParams *params);

bool_t sshGetExecArg(const SshExecParams *params, uint_t index, SshString *arg);

error_t sshParseSubsystemParams(const uint8_t *p, size_t length,
   SshSubsystemParams *params);

error_t sshParseWindowChangeParams(const uint8_t *p, size_t length,
   SshWindowChangeParams *params);

error_t sshParseSignalParams(const uint8_t *p, size_t length,
   SshSignalParams *params);

error_t sshParseExitStatusParams(const uint8_t *p, size_t length,
   SshExitStatusParams *params);

error_t sshParseBreakParams(const uint8_t *p, size_t length,
   SshBreakParams *params);

error_t sshParseChannelSuccess(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelFailure(SshConnection *connection,
   const uint8_t *message, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
