#ifndef __TLS_ADAPTER_H__
#define __TLS_ADAPTER_H__

#include "error.h"
#include "rng/yarrow.h"

error_t tls_adapter_deinit();
error_t tls_adapter_init();

extern char_t *clientCert;
extern size_t clientCertLen;
extern char_t *clientPrivateKey;
extern size_t clientPrivateKeyLen;
extern char_t *trustedCaList;
extern size_t trustedCaListLen;
extern YarrowContext yarrowContext;

#endif
