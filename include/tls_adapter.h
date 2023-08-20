#ifndef __TLS_ADAPTER_H__
#define __TLS_ADAPTER_H__

#include "error.h"
#include "tls.h"
#include "rng/yarrow.h"

error_t tls_adapter_deinit();
error_t tls_adapter_init();

extern TlsCache *tlsCache;

extern YarrowContext yarrowContext;

void tls_context_key_log_init(TlsContext *context);
error_t load_cert(const char *dest_var, const char *src_file, const char *src_var, uint8_t settingsId);

#endif
