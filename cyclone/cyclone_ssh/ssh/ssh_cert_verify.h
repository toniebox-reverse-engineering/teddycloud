/**
 * @file ssh_cert_verify.h
 * @brief SSH certificate verification
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

#ifndef _SSH_CERT_VERIFY_H
#define _SSH_CERT_VERIFY_H

//Dependencies
#include "ssh.h"
#include "ssh_cert_import.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH certificate verification related functions
error_t sshVerifyClientCertificate(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *hostKey,
   bool_t flag);

error_t sshVerifyServerCertificate(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *hostKey);

error_t sshVerifyPrincipal(const SshCertificate *cert, const char_t *name);
error_t sshVerifyValidity(const SshCertificate *cert);

error_t sshVerifyCriticalOptions(SshConnection *connection,
   const SshCertificate *cert);

error_t sshVerifySrcAddrOption(SshConnection *connection,
   const SshBinaryString *optionData);

error_t sshVerifyCertSignature(SshConnection *connection,
   const SshCertificate *cert);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
