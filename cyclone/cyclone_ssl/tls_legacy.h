/**
 * @file tls_legacy.h
 * @brief Legacy definitions
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSL Open.
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

#ifndef _TLS_LEGACY_H
#define _TLS_LEGACY_H

//Deprecated definitions
#define TlsIoHandle TlsSocketHandle

//Deprecated functions
#define tlsSetIoCallbacks(context, handle, sendCallback, receiveCallback) \
   tlsSetSocketCallbacks(context, sendCallback, receiveCallback, handle);

#ifdef TLS_RSA_SUPPORT
   #if (TLS_RSA_SUPPORT == ENABLED)
      #define TLS_RSA_KE_SUPPORT ENABLED
   #else
      #define TLS_RSA_KE_SUPPORT DISABLED
   #endif
   #undef TLS_RSA_SUPPORT
#endif

#ifdef TLS_DHE_RSA_SUPPORT
   #define TLS_DHE_RSA_KE_SUPPORT TLS_DHE_RSA_SUPPORT
#endif

#ifdef TLS_DHE_DSS_SUPPORT
   #define TLS_DHE_DSS_KE_SUPPORT TLS_DHE_DSS_SUPPORT
#endif

#ifdef TLS_DH_ANON_SUPPORT
   #define TLS_DH_ANON_KE_SUPPORT TLS_DH_ANON_SUPPORT
#endif

#ifdef TLS_ECDHE_RSA_SUPPORT
   #define TLS_ECDHE_RSA_KE_SUPPORT TLS_ECDHE_RSA_SUPPORT
#endif

#ifdef TLS_ECDHE_ECDSA_SUPPORT
   #define TLS_ECDHE_ECDSA_KE_SUPPORT TLS_ECDHE_ECDSA_SUPPORT
#endif

#ifdef TLS_ECDH_ANON_SUPPORT
   #define TLS_ECDH_ANON_KE_SUPPORT TLS_ECDH_ANON_SUPPORT
#endif

#ifdef TLS_PSK_SUPPORT
   #if (TLS_PSK_SUPPORT == ENABLED)
      #define TLS_PSK_KE_SUPPORT ENABLED
   #else
      #define TLS_PSK_KE_SUPPORT DISABLED
   #endif
   #undef TLS_PSK_SUPPORT
#endif

#ifdef TLS_RSA_PSK_SUPPORT
   #define TLS_RSA_PSK_KE_SUPPORT TLS_RSA_PSK_SUPPORT
#endif

#ifdef TLS_DHE_PSK_SUPPORT
   #define TLS_DHE_PSK_KE_SUPPORT TLS_DHE_PSK_SUPPORT
#endif

#ifdef TLS_ECDHE_PSK_SUPPORT
   #define TLS_ECDHE_PSK_KE_SUPPORT TLS_ECDHE_PSK_SUPPORT
#endif

#ifdef TLS_CURVE25519_SUPPORT
   #define TLS_X25519_SUPPORT TLS_CURVE25519_SUPPORT
#endif

#ifdef TLS_CURVE448_SUPPORT
   #define TLS_X448_SUPPORT TLS_CURVE448_SUPPORT
#endif

#define TlsSession TlsSessionState
#define tlsSaveSession tlsSaveSessionState
#define tlsRestoreSession tlsRestoreSessionState

#ifdef TLS_AES_SUPPORT
   #define TLS_AES_128_SUPPORT TLS_AES_SUPPORT
   #define TLS_AES_256_SUPPORT TLS_AES_SUPPORT
#endif

#ifdef TLS_CAMELLIA_SUPPORT
   #define TLS_CAMELLIA_128_SUPPORT TLS_CAMELLIA_SUPPORT
   #define TLS_CAMELLIA_256_SUPPORT TLS_CAMELLIA_SUPPORT
#endif

#ifdef TLS_ARIA_SUPPORT
   #define TLS_ARIA_128_SUPPORT TLS_ARIA_SUPPORT
   #define TLS_ARIA_256_SUPPORT TLS_ARIA_SUPPORT
#endif

#endif
