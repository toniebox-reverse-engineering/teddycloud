#ifndef _HANDLER_WEB_AUTH_H
#define _HANDLER_WEB_AUTH_H

#include "handler.h"

#define WEB_USERS_JSON_FILE "web_users.json"
#define WEB_SESSION_COOKIE "tc_web_session"
#define WEB_BEARER_TOKEN_MAX 64

void web_auth_init(void);
bool web_auth_env_override(void);
bool web_auth_requires_login(void);
bool web_auth_is_public_request(const char_t *uri, const char_t *method);
bool web_auth_is_authenticated(HttpConnection *connection, char *username, size_t username_size);
error_t web_auth_unauthorized(HttpConnection *connection);

#endif
