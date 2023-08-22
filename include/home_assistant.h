#pragma once

#include <stdint.h>
#include <stdbool.h>

#define MAX_LEN 128
#define MAX_ENTITIES (3 * 9 + 16 * 7 + 32)

/* https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery */
typedef enum
{
    ha_unused = 0,
    /* https://www.home-assistant.io/integrations/text.mqtt/ */
    ha_text,
    /* https://www.home-assistant.io/integrations/sensor.mqtt/ */
    ha_sensor,
    /* https://www.home-assistant.io/integrations/number.mqtt/ */
    ha_number,
    /* https://www.home-assistant.io/integrations/button.mqtt/ */
    ha_button,
    /* https://www.home-assistant.io/integrations/select.mqtt/ */
    ha_select,
    /* https://www.home-assistant.io/integrations/binary_sensor.mqtt/ */
    ha_binary_sensor,
    /* https://www.home-assistant.io/integrations/ha_light.mqtt/ */
    ha_light,
    /* https://www.home-assistant.io/integrations/switch.mqtt/ */
    ha_switch,
    /* https://www.home-assistant.io/integrations/event.mqtt/ */
    ha_event,
    /* https://www.home-assistant.io/integrations/device_trigger.mqtt/ */
    ha_device_trigger,
    /* https://www.home-assistant.io/integrations/image.mqtt/ */
    ha_image
} t_ha_device_type;

typedef struct s_ha_entity t_ha_entity;
typedef struct s_ha_info t_ha_info;

struct s_ha_entity
{
    t_ha_device_type type;

    const char *name;
    const char *id;

    /* used by: sensor */
    const char *unit_of_meas;
    /* used by: sensor */
    const char *val_tpl;
    /* used by: sensor */
    const char *dev_class;
    /* used by: sensor */
    const char *state_class;
    /* used by: button, number, text */
    const char *cmd_t;
    /* used by: sensor, binary_sensor, number, text */
    const char *stat_t;
    /* used by: light */
    const char *rgb_t;
    const char *rgbw_t;
    /* used by: switch, comma separated */
    const char *options;
    /* used by: number */
    float min;
    /* used by: number */
    float max;
    /* used by: number */
    const char *mode;
    /* icon */
    const char *ic;
    /* entity_category */
    const char *ent_cat;

    /* used by: light */
    const char *fx_cmd_t;
    /* used by: light */
    const char *fx_stat_t;
    /* used by: light, comma separated */
    const char *fx_list;
    /* used by: image */
    const char *url_t;
    /* used by: event, comma separated */
    const char *event_types;

    /* alternative client name */
    const char *alt_name;

    void (*received)(t_ha_info *ha_info, const t_ha_entity *, void *, const char *);
    void *received_ctx;
    void (*rgb_received)(t_ha_info *ha_info, const t_ha_entity *, void *, const char *);
    void *rgb_received_ctx;
    void (*fx_received)(t_ha_info *ha_info, const t_ha_entity *, void *, const char *);
    void *fx_received_ctx;
    void (*transmit)(t_ha_info *ha_info, const t_ha_entity *, void *);
    void *transmit_ctx;
};

struct s_ha_info
{
    bool initialized;
    char base_topic[MAX_LEN];
    char name[MAX_LEN];
    char id[MAX_LEN];
    char cu[MAX_LEN];
    char mf[MAX_LEN];
    char mdl[MAX_LEN];
    char sw[MAX_LEN];
    char hw[MAX_LEN];
    char via[MAX_LEN];
    t_ha_entity entities[MAX_ENTITIES];
    int entitiy_count;
};

void ha_setup(t_ha_info *ha_info);
void ha_connected(t_ha_info *ha_info);
bool ha_loop(t_ha_info *ha_info);
void ha_transmit_all(t_ha_info *ha_info);
void ha_publish(t_ha_info *ha_info);
void ha_add(t_ha_info *ha_info, t_ha_entity *entity);
void ha_addmqtt(t_ha_info *ha_info, char *json_str, const char *name, const char *value, t_ha_entity *entity, bool last);
void ha_received(t_ha_info *ha_info, char *topic, const char *payload);
void ha_transmit(t_ha_info *ha_info, const t_ha_entity *entity, const char *value);
void ha_transmit_topic(t_ha_info *ha_info, const char *stat_t, const char *value);
int ha_parse_index(t_ha_info *ha_info, const char *options, const char *message);
void ha_get_index(t_ha_info *ha_info, const char *options, int index, char *text);
