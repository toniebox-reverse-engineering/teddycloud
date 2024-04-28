#pragma once

#include "handler.h"

bool isSecMitIncident(HttpConnection *connection);
error_t checkSecMitHandlers(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleSecMitDomain(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleSecMitCrawler(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleSecMitRobotsTxt(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleSecMitLock(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleSecMitWarn(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);