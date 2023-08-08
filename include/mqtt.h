#pragma once

#include "error.h"
#include "handler.h"

void mqtt_init();
error_t mqtt_sendEvent(const char *eventname, const char *content, client_ctx_t *client_ctx);
error_t mqtt_sendBoxEvent(const char *eventname, const char *content, client_ctx_t *client_ctx);
bool mqtt_publish(const char *item_topic, const char *content);
bool mqtt_subscribe(const char *item_topic);
