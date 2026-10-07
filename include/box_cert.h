#pragma once

#include <stdbool.h>

#define BOX_CERT_ID_SIZE 13

/* Issuer or subject of a box certificate: Boxine/tonies or TeddyCloud. */
bool box_cert_issuer_known(const char *issuer, const char *subject);

/* The box id (MAC) from the certificate subject "b'<mac>'" or "<mac>". */
bool box_cert_id(const char *subject, char id[BOX_CERT_ID_SIZE]);
