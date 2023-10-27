
#include <string.h>

#include "platform.h"
#include "debug.h"
#include "stats.h"
#include "home_assistant.h"
#include "macros.h"
#include "mqtt.h"

#include "cJSON.h"

void ha_addstrarray(cJSON *json_obj, const char *name, const char *value)
{
    if (value && strlen(value) > 0)
    {
        char *tmp_value = osAllocMem(osStrlen(value) + 1);
        osStrcpy(tmp_value, value);
        cJSON *json_arr = cJSON_AddArrayToObject(json_obj, name);

        char *token = strtok(tmp_value, ";");
        while (token != NULL)
        {
            cJSON_AddItemToArray(json_arr, cJSON_CreateString(token));
            token = strtok(NULL, ";");
        }

        osFreeMem(tmp_value);
    }
}

void ha_addstr(cJSON *json_obj, const char *name, const char *value)
{
    if (value)
    {
        cJSON_AddStringToObject(json_obj, name, value);
    }
}

void ha_addmqtt(t_ha_info *ha_info, cJSON *json_obj, const char *name, const char *value, t_ha_entity *entity)
{
    if (value && strlen(value) > 0)
    {
        char path_buffer[64];

        if (entity && entity->alt_name)
        {
            osSnprintf(path_buffer, sizeof(path_buffer), value, entity->alt_name);
        }
        else
        {
            osSnprintf(path_buffer, sizeof(path_buffer), value, ha_info->base_topic);
        }
        cJSON_AddStringToObject(json_obj, name, path_buffer);
    }
}

void ha_addfloat(cJSON *json_obj, const char *name, float value)
{
    cJSON_AddNumberToObject(json_obj, name, value);
}

void ha_addint(cJSON *json_obj, const char *name, int value)
{
    cJSON_AddNumberToObject(json_obj, name, value);
}

void ha_publish(t_ha_info *ha_info)
{
    char mqtt_path[2 * MAX_LEN + 1];
    char uniq_id[2 * MAX_LEN + 1];

    TRACE_DEBUG("[HA] Publish\n");

    for (int pos = 0; pos < ha_info->entitiy_count; pos++)
    {
        const char *type = NULL;

        switch (ha_info->entities[pos].type)
        {
        case ha_sensor:
            type = "sensor";
            break;
        case ha_text:
            type = "text";
            break;
        case ha_number:
            type = "number";
            break;
        case ha_button:
            type = "button";
            break;
        case ha_binary_sensor:
            type = "binary_sensor";
            break;
        case ha_select:
            type = "select";
            break;
        case ha_light:
            type = "light";
            break;
        case ha_switch:
            type = "switch";
            break;
        case ha_image:
            type = "image";
            break;
        case ha_event:
            type = "event";
            break;
        default:
            break;
        }

        if (!type)
        {
            break;
        }

        osSnprintf(uniq_id, sizeof(uniq_id), "%s_%s", ha_info->id, ha_info->entities[pos].id);

        // TRACE_INFO("[HA]   uniq_id %s\n", uniq_id);
        osSnprintf(mqtt_path, sizeof(mqtt_path), "homeassistant/%s/%s/%s/config", type, ha_info->id, ha_info->entities[pos].id);

        // TRACE_INFO("[HA]   mqtt_path %s\n", mqtt_path);

        cJSON *json_obj = cJSON_CreateObject();
        ha_addstr(json_obj, "name", ha_info->entities[pos].name);
        ha_addstr(json_obj, "uniq_id", uniq_id);
        ha_addstr(json_obj, "dev_cla", ha_info->entities[pos].dev_class);
        ha_addstr(json_obj, "stat_cla", ha_info->entities[pos].state_class);
        ha_addstr(json_obj, "ic", ha_info->entities[pos].ic);
        ha_addstr(json_obj, "mode", ha_info->entities[pos].mode);
        ha_addstr(json_obj, "ent_cat", ha_info->entities[pos].ent_cat);
        ha_addstr(json_obj, "avty_t", ha_info->availability_topic);
        ha_addmqtt(ha_info, json_obj, "cmd_t", ha_info->entities[pos].cmd_t, &ha_info->entities[pos]);
        ha_addmqtt(ha_info, json_obj, "stat_t", ha_info->entities[pos].stat_t, &ha_info->entities[pos]);
        ha_addmqtt(ha_info, json_obj, "rgbw_cmd_t", ha_info->entities[pos].rgbw_t, &ha_info->entities[pos]);
        ha_addmqtt(ha_info, json_obj, "rgb_cmd_t", ha_info->entities[pos].rgb_t, &ha_info->entities[pos]);
        ha_addmqtt(ha_info, json_obj, "fx_cmd_t", ha_info->entities[pos].fx_cmd_t, &ha_info->entities[pos]);
        ha_addmqtt(ha_info, json_obj, "fx_stat_t", ha_info->entities[pos].fx_stat_t, &ha_info->entities[pos]);
        ha_addmqtt(ha_info, json_obj, "url_t", ha_info->entities[pos].url_t, &ha_info->entities[pos]);
        ha_addstrarray(json_obj, "fx_list", ha_info->entities[pos].fx_list);
        ha_addstrarray(json_obj, "evt_typ", ha_info->entities[pos].event_types);
        ha_addmqtt(ha_info, json_obj, "val_tpl", ha_info->entities[pos].val_tpl, &ha_info->entities[pos]);
        ha_addstrarray(json_obj, "ops", ha_info->entities[pos].options);
        ha_addstr(json_obj, "unit_of_meas", ha_info->entities[pos].unit_of_meas);

        switch (ha_info->entities[pos].type)
        {
        case ha_number:
            ha_addint(json_obj, "min", ha_info->entities[pos].min);
            ha_addint(json_obj, "max", ha_info->entities[pos].max);
            break;
        case ha_switch:
            ha_addstr(json_obj, "pl_on", "TRUE");
            ha_addstr(json_obj, "pl_off", "FALSE");
            break;
        default:
            break;
        }

        cJSON *json_dev_obj = cJSON_AddObjectToObject(json_obj, "dev");
        ha_addstr(json_dev_obj, "name", ha_info->name);
        ha_addstr(json_dev_obj, "ids", ha_info->id);
        ha_addstr(json_dev_obj, "cu", ha_info->cu);
        ha_addstr(json_dev_obj, "mf", ha_info->mf);
        ha_addstr(json_dev_obj, "mdl", ha_info->mdl);
        if (osStrlen(ha_info->via))
        {
            ha_addstr(json_dev_obj, "via_device", ha_info->via);
        }
        ha_addstr(json_dev_obj, "sw", ha_info->sw);
        ha_addstr(json_dev_obj, "hw", ha_info->hw);

        // TRACE_INFO("[HA]    topic '%s'\n", mqtt_path);
        // TRACE_INFO("[HA]    content '%s'\n", json_str);

        char *json_str = cJSON_PrintUnformatted(json_obj);
        cJSON_Delete(json_obj);
        if (!mqtt_publish(mqtt_path, json_str))
        {
            TRACE_INFO("[HA] publish failed\n");
        }
        osFreeMem(json_str);
    }
}

void ha_received(t_ha_info *ha_info, char *topic, const char *payload)
{
    for (int pos = 0; pos < ha_info->entitiy_count; pos++)
    {
        char item_topic[128];

        if (ha_info->entities[pos].cmd_t && ha_info->entities[pos].received)
        {
            osSnprintf(item_topic, sizeof(item_topic), ha_info->entities[pos].cmd_t, ha_info->base_topic);
            if (!osStrcmp(topic, item_topic))
            {
                ha_info->entities[pos].received(ha_info, &ha_info->entities[pos], ha_info->entities[pos].received_ctx, payload);

                if (ha_info->entities[pos].transmit)
                {
                    ha_info->entities[pos].transmit(ha_info, &ha_info->entities[pos], ha_info->entities[pos].transmit_ctx);
                }
            }
        }

        if (ha_info->entities[pos].rgb_t && ha_info->entities[pos].rgb_received)
        {
            osSnprintf(item_topic, sizeof(item_topic), ha_info->entities[pos].rgb_t, ha_info->base_topic);
            if (!osStrcmp(topic, item_topic))
            {
                ha_info->entities[pos].rgb_received(ha_info, &ha_info->entities[pos], ha_info->entities[pos].rgb_received_ctx, payload);

                if (ha_info->entities[pos].transmit)
                {
                    ha_info->entities[pos].transmit(ha_info, &ha_info->entities[pos], ha_info->entities[pos].transmit_ctx);
                }
            }
        }

        if (ha_info->entities[pos].fx_cmd_t && ha_info->entities[pos].fx_received)
        {
            osSnprintf(item_topic, sizeof(item_topic), ha_info->entities[pos].fx_cmd_t, ha_info->base_topic);
            if (!osStrcmp(topic, item_topic))
            {
                ha_info->entities[pos].fx_received(ha_info, &ha_info->entities[pos], ha_info->entities[pos].fx_received_ctx, payload);

                if (ha_info->entities[pos].transmit)
                {
                    ha_info->entities[pos].transmit(ha_info, &ha_info->entities[pos], ha_info->entities[pos].transmit_ctx);
                }
            }
        }
    }
}

void ha_transmit(t_ha_info *ha_info, const t_ha_entity *entity, const char *value)
{
    if (!entity)
    {
        return;
    }

    if (!entity->stat_t)
    {
        return;
    }
    char item_topic[128];
    osSnprintf(item_topic, sizeof(item_topic), entity->stat_t, ha_info->base_topic);

    if (!mqtt_publish(item_topic, value))
    {
        TRACE_INFO("[HA] publish failed\n");
    }
}

void ha_transmit_topic(t_ha_info *ha_info, const char *stat_t, const char *value)
{
    if (!stat_t)
    {
        return;
    }

    char item_topic[128];
    osSnprintf(item_topic, sizeof(item_topic), stat_t, ha_info->base_topic);

    if (!mqtt_publish(item_topic, value))
    {
        TRACE_INFO("[HA] publish failed\n");
    }
}

void ha_transmit_all(t_ha_info *ha_info)
{
    for (int pos = 0; pos < ha_info->entitiy_count; pos++)
    {
        if (ha_info->entities[pos].transmit)
        {
            ha_info->entities[pos].transmit(ha_info, &ha_info->entities[pos], ha_info->entities[pos].transmit_ctx);
        }
    }
}

void ha_setup(t_ha_info *ha_info)
{
    osMemset(ha_info, 0x00, sizeof(t_ha_info));

    osSnprintf(ha_info->base_topic, sizeof(ha_info->base_topic), "teddyCloud");
    osSnprintf(ha_info->name, sizeof(ha_info->name), "%s", ha_info->base_topic);
    osSnprintf(ha_info->id, sizeof(ha_info->id), "teddyCloud");
    osSnprintf(ha_info->cu, sizeof(ha_info->cu), "%s", settings_get_string("core.host_url"));
    osSnprintf(ha_info->mf, sizeof(ha_info->mf), "Team RevvoX");
    osSnprintf(ha_info->mdl, sizeof(ha_info->mdl), "teddyCloud");
    osSnprintf(ha_info->sw, sizeof(ha_info->sw), "%s (%s)", get_settings()->internal.version.id, get_settings()->internal.version.git_sha_short);
    osSnprintf(ha_info->hw, sizeof(ha_info->hw), "%s %s", get_settings()->internal.version.platform, get_settings()->internal.version.architecture);

    ha_info->entitiy_count = 0;
    ha_info->initialized = true;
}

void ha_connected(t_ha_info *ha_info)
{
    for (int pos = 0; pos < ha_info->entitiy_count; pos++)
    {
        char item_topic[128];
        if (ha_info->entities[pos].cmd_t && ha_info->entities[pos].received)
        {
            osSnprintf(item_topic, sizeof(item_topic), ha_info->entities[pos].cmd_t, ha_info->base_topic);
            mqtt_subscribe(item_topic);
        }
        if (ha_info->entities[pos].rgb_t && ha_info->entities[pos].rgb_received)
        {
            osSnprintf(item_topic, sizeof(item_topic), ha_info->entities[pos].rgb_t, ha_info->base_topic);
            mqtt_subscribe(item_topic);
        }
        if (ha_info->entities[pos].fx_cmd_t && ha_info->entities[pos].fx_received)
        {
            osSnprintf(item_topic, sizeof(item_topic), ha_info->entities[pos].fx_cmd_t, ha_info->base_topic);
            mqtt_subscribe(item_topic);
        }
    }
    ha_publish(ha_info);
    ha_transmit_all(ha_info);
}

bool ha_loop(t_ha_info *ha_info)
{
    systime_t time = osGetSystemTime();
    static systime_t nextTime = 0;

    if (time >= nextTime)
    {
        ha_publish(ha_info);
        ha_transmit_all(ha_info);
        nextTime = time + 60000;
    }

    return false;
}

void ha_add(t_ha_info *ha_info, t_ha_entity *entity)
{
    if (!entity)
    {
        return;
    }

    if (ha_info->entitiy_count >= MAX_ENTITIES)
    {
        return;
    }
    osMemcpy(&ha_info->entities[ha_info->entitiy_count++], entity, sizeof(t_ha_entity));
}

int ha_parse_index(t_ha_info *ha_info, const char *options, const char *message)
{
    if (!options)
    {
        return -1;
    }

    int pos = 0;
    char tmp_buf[128];
    char *cur_elem = tmp_buf;

    osStrncpy(tmp_buf, options, sizeof(tmp_buf) - 1);

    while (true)
    {
        char *next_elem = strchr(cur_elem, ';');
        if (next_elem)
        {
            *next_elem = '\000';
        }
        if (!osStrcmp(cur_elem, message))
        {
            return pos;
        }

        if (!next_elem)
        {
            return -1;
        }

        cur_elem = next_elem + 1;
        pos++;
    }
}

void ha_get_index(t_ha_info *ha_info, const char *options, int index, char *text)
{
    if (!options || !text)
    {
        return;
    }

    int pos = 0;
    char tmp_buf[128];
    char *cur_elem = tmp_buf;

    osStrncpy(tmp_buf, options, sizeof(tmp_buf) - 1);

    while (true)
    {
        char *next_elem = strchr(cur_elem, ';');
        if (next_elem)
        {
            *next_elem = '\000';
        }
        if (pos == index)
        {
            osStrcpy(text, cur_elem);
            return;
        }

        if (!next_elem)
        {
            return;
        }

        cur_elem = next_elem + 1;
        pos++;
    }
}
