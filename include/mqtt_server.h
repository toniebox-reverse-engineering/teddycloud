#pragma once

#include "error.h"
#include "handler.h"

void mqtt_server_init();
void mqtt_server_task();
void mqtt_server_deinit();
void mqtt_server_publish_fresh_tonies(client_ctx_t *client_ctx);
