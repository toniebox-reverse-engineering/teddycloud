#pragma once

#include "error.h"

void mqtt_init();
error_t mqtt_sendEvent(const char *eventname, const char *content);
error_t mqtt_sendBoxEvent(const char *box_id, const char *eventname, const char *content);
bool mqtt_publish(const char *item_topic, const char *content);
bool mqtt_subscribe(const char *item_topic);
