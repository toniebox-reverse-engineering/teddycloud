/**
 * @file ssh_cert_import.h
 * @brief SSH certificate import functions
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

#ifndef _SSH_CERT_IMPORT_H
#define _SSH_CERT_IMPORT_H

//Dependencies
#include "ssh_types.h"
#include "ssh_cert_parse.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ec.h"
#include "ecc/eddsa.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH certificate import functions
error_t sshImportCertificate(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen);

error_t sshImportRsaCertPublicKey(const SshCertificate *cert,
   RsaPublicKey *publicKey);

error_t sshImportDsaCertPublicKey(const SshCertificate *cert,
   DsaPublicKey *publicKey);

error_t sshImportEcdsaCertPublicKey(const SshCertificate *cert,
   EcDomainParameters *params, EcPublicKey *publicKey);

error_t sshImportEd25519CertPublicKey(const SshCertificate *cert,
   EddsaPublicKey *publicKey);

const char_t *sshGetCertType(const char_t *input, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
