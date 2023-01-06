/**
 * @file ssh_cert_export.c
 * @brief SSH certificate export functions
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_cert_export.h"
#include "ssh/ssh_cert_parse.h"
#include "ssh/ssh_misc.h"
#include "encoding/base64.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_CERT_SUPPORT == ENABLED)


/**
 * @brief Export SSH certificate (OpenSSH format)
 * @param[in] input Certificate structure to encode
 * @param[in] inputLen Length of the certificate structure to encode
 * @param[out] output Resulting certificate file (optional parameter)
 * @param[out] outputLen Length of the resulting certificate file
 **/

error_t sshExportCertificate(const void *input, size_t inputLen,
   char_t *output, size_t *outputLen)
{
   error_t error;
   size_t n;
   SshCertificate cert;
   uint8_t identifier[40];

   //Check parameters
   if(input == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Parse certificate structure
   error = sshParseCertificate(input, inputLen, &cert);
   //Any error to report?
   if(error)
      return error;

   //Sanity check
   if(cert.keyFormatId.length > sizeof(identifier))
      return ERROR_WRONG_IDENTIFIER;

   //Save key format identifier
   osMemcpy(identifier, cert.keyFormatId.value, cert.keyFormatId.length);

   //Encode the certificate structure using Base64
   base64Encode(input, inputLen, output, &n);

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting certificate file without copying any data
   if(output != NULL)
   {
      //Make room for the identifier string
      osMemmove(output + cert.keyFormatId.length + 1, output, n + 1);
      //Copy identifier string
      osMemcpy(output, identifier, cert.keyFormatId.length);
      //The identifier must be followed by a whitespace character
      output[cert.keyFormatId.length] = ' ';
   }

   //Consider the length of the identifier string
   n += cert.keyFormatId.length + 1;

   //Total number of bytes that have been written
   *outputLen = n;

   //Successful processing
   return NO_ERROR;
}

#endif
