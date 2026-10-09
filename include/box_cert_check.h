#pragma once

#include <stdbool.h>

#include "settings.h"
#include "tls.h"

/* Checks the certificate of a box (core.boxCertAuth), pins it if needed and
 * keeps the result in internal.boxCertStatus. False: refuse the box. */
bool box_cert_accepted(const TlsContext *tls, settings_t *settings);
