#ifndef __TLS_ADAPTER_H__
#define __TLS_ADAPTER_H__

#include "error.h"
#include "tls.h"
#include "rng/yarrow.h"

error_t tls_adapter_deinit();
error_t tls_adapter_init();

extern char_t *clientCert;
extern size_t clientCertLen;
extern char_t *clientPrivateKey;
extern size_t clientPrivateKeyLen;
extern char_t *trustedCaList;
extern size_t trustedCaListLen;

extern char_t *caCert;
extern size_t caCertLen;
extern char_t *serverCert;
extern size_t serverCertLen;
extern char_t *serverKey;
extern size_t serverKeyLen;

extern TlsCache *tlsCache;

extern YarrowContext yarrowContext;

#endif
