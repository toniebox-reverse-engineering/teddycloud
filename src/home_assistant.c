
#include <string.h>

#include "platform.h"
#include "debug.h"
#include "stats.h"
#include "home_assistant.h"
#include "macros.h"
#include "mqtt.h"

void ha_addstrarray(char *json_str, const char *name, const char *value, bool last)
{
    char tmp_buf[256];

    if (value && strlen(value) > 0)
    {
        int pos = 0;
        char values_buf[128];
        int out_pos = 0;

        values_buf[out_pos++] = '"';

        bool done = false;
        while (!done && out_pos < sizeof(values_buf))
        {
            switch (value[pos])
            {
            case ';':
                values_buf[out_pos++] = '"';
                if (value[pos + 1])
                {
                    values_buf[out_pos++] = ',';
                    values_buf[out_pos++] = '"';
                }
                break;

            case 0:
                values_buf[out_pos++] = '"';
                done = true;
                break;

            default:
                values_buf[out_pos++] = value[pos];
                break;
            }
            pos++;
        }
        values_buf[out_pos++] = '\000';

        osSnprintf(tmp_buf, sizeof(tmp_buf), "\"%s\": [%s]%c ", name, values_buf, (last ? ' ' : ','));
        osStrcat(json_str, tmp_buf);
    }
}

void ha_addstr(char *json_str, const char *name, const char *value, bool last)
{
    char tmp_buf[128];

    if (value && strlen(value) > 0)
    {
        osSnprintf(tmp_buf, sizeof(tmp_buf), "\"%s\": \"%s\"%c ", name, value, (last ? ' ' : ','));
        osStrcat(json_str, tmp_buf);
    }
}

void ha_addmqtt(t_ha_info *ha_info, char *json_str, const char *name, const char *value, t_ha_entity *entity, bool last)
{
    char tmp_buf[128];

    if (value && strlen(value) > 0)
    {
        char path_buffer[64];

        if (entity && entity->alt_name)
        {
            osSprintf(path_buffer, value, entity->alt_name);
        }
        else
        {
            osSprintf(path_buffer, value, ha_info->base_topic);
        }
        osSnprintf(tmp_buf, sizeof(tmp_buf), "\"%s\": \"%s\"%c ", name, path_buffer, (last ? ' ' : ','));
        osStrcat(json_str, tmp_buf);
    }
}

void ha_addfloat(char *json_str, const char *name, float value, bool last)
{
    char tmp_buf[64];

    osSnprintf(tmp_buf, sizeof(tmp_buf), "\"%s\": \"%f\"%c ", name, value, (last ? ' ' : ','));
    osStrcat(json_str, tmp_buf);
}

void ha_addint(char *json_str, const char *name, int value, bool last)
{
    char tmp_buf[64];

    osSnprintf(tmp_buf, sizeof(tmp_buf), "\"%s\": \"%d\"%c ", name, value, (last ? ' ' : ','));
    osStrcat(json_str, tmp_buf);
}

void ha_publish(t_ha_info *ha_info)
{
    char *json_str = (char *)osAllocMem(1024);
    char mqtt_path[2 * MAX_LEN + 1];
    char uniq_id[2 * MAX_LEN + 1];

    TRACE_INFO("[HA] Publish\n");

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

        osSprintf(uniq_id, "%s_%s", ha_info->id, ha_info->entities[pos].id);

        // TRACE_INFO("[HA]   uniq_id %s\n", uniq_id);
        osSprintf(mqtt_path, "homeassistant/%s/%s/%s/config", type, ha_info->id, ha_info->entities[pos].id);

        // TRACE_INFO("[HA]   mqtt_path %s\n", mqtt_path);

        osStrcpy(json_str, "{");
        ha_addstr(json_str, "name", ha_info->entities[pos].name, false);
        ha_addstr(json_str, "uniq_id", uniq_id, false);
        ha_addstr(json_str, "dev_cla", ha_info->entities[pos].dev_class, false);
        ha_addstr(json_str, "stat_cla", ha_info->entities[pos].state_class, false);
        ha_addstr(json_str, "ic", ha_info->entities[pos].ic, false);
        ha_addstr(json_str, "mode", ha_info->entities[pos].mode, false);
        ha_addstr(json_str, "ent_cat", ha_info->entities[pos].ent_cat, false);
        ha_addmqtt(ha_info, json_str, "cmd_t", ha_info->entities[pos].cmd_t, &ha_info->entities[pos], false);
        ha_addmqtt(ha_info, json_str, "stat_t", ha_info->entities[pos].stat_t, &ha_info->entities[pos], false);
        ha_addmqtt(ha_info, json_str, "rgbw_cmd_t", ha_info->entities[pos].rgbw_t, &ha_info->entities[pos], false);
        ha_addmqtt(ha_info, json_str, "rgb_cmd_t", ha_info->entities[pos].rgb_t, &ha_info->entities[pos], false);
        ha_addmqtt(ha_info, json_str, "fx_cmd_t", ha_info->entities[pos].fx_cmd_t, &ha_info->entities[pos], false);
        ha_addmqtt(ha_info, json_str, "fx_stat_t", ha_info->entities[pos].fx_stat_t, &ha_info->entities[pos], false);
        ha_addmqtt(ha_info, json_str, "url_topic", ha_info->entities[pos].url_t, &ha_info->entities[pos], false);
        ha_addstrarray(json_str, "fx_list", ha_info->entities[pos].fx_list, false);
        ha_addstrarray(json_str, "event_types", ha_info->entities[pos].event_types, false);
        ha_addmqtt(ha_info, json_str, "val_tpl", ha_info->entities[pos].val_tpl, &ha_info->entities[pos], false);
        ha_addstrarray(json_str, "options", ha_info->entities[pos].options, false);
        ha_addstr(json_str, "unit_of_meas", ha_info->entities[pos].unit_of_meas, false);

        switch (ha_info->entities[pos].type)
        {
        case ha_number:
            ha_addint(json_str, "min", ha_info->entities[pos].min, false);
            ha_addint(json_str, "max", ha_info->entities[pos].max, false);
            break;
        case ha_switch:
            ha_addstr(json_str, "payload_on", "TRUE", false);
            ha_addstr(json_str, "payload_off", "FALSE", false);
            ha_addstr(json_str, "state_on", "TRUE", false);
            ha_addstr(json_str, "state_off", "FALSE", false);
            break;
        default:
            break;
        }

        osStrcat(json_str, "\"dev\": {");
        ha_addstr(json_str, "name", ha_info->name, false);
        ha_addstr(json_str, "ids", ha_info->id, false);
        ha_addstr(json_str, "cu", ha_info->cu, false);
        ha_addstr(json_str, "mf", ha_info->mf, false);
        ha_addstr(json_str, "mdl", ha_info->mdl, false);
        ha_addstr(json_str, "sw", ha_info->sw, true);
        osStrcat(json_str, "}}");

        // TRACE_INFO("[HA]    topic '%s'\n", mqtt_path);
        // TRACE_INFO("[HA]    content '%s'\n", json_str);

        if (!mqtt_publish(mqtt_path, json_str))
        {
            TRACE_INFO("[HA] publish failed\n");
        }
    }

    osFreeMem(json_str);
}

void ha_received(t_ha_info *ha_info, char *topic, const char *payload)
{
    for (int pos = 0; pos < ha_info->entitiy_count; pos++)
    {
        char item_topic[128];

        if (ha_info->entities[pos].cmd_t && ha_info->entities[pos].received)
        {
            osSprintf(item_topic, ha_info->entities[pos].cmd_t, ha_info->base_topic);
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
            osSprintf(item_topic, ha_info->entities[pos].rgb_t, ha_info->base_topic);
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
            osSprintf(item_topic, ha_info->entities[pos].fx_cmd_t, ha_info->base_topic);
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
    osSprintf(item_topic, entity->stat_t, ha_info->base_topic);

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
    osSprintf(item_topic, stat_t, ha_info->base_topic);

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

    osSprintf(ha_info->base_topic, "%s", "teddyCloud");
    osSprintf(ha_info->name, "%s", ha_info->base_topic);
    osSprintf(ha_info->id, "%s", "teddyCloud");
    osSprintf(ha_info->cu, "%s", settings_get_string("core.host_url"));
    osSprintf(ha_info->mf, "RevvoX");
    osSprintf(ha_info->mdl, "%s", "teddyCloud");
    osSprintf(ha_info->sw, "" BUILD_GIT_TAG " (" BUILD_GIT_SHORT_SHA ")");
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
            osSprintf(item_topic, ha_info->entities[pos].cmd_t, ha_info->base_topic);
            mqtt_subscribe(item_topic);
        }
        if (ha_info->entities[pos].rgb_t && ha_info->entities[pos].rgb_received)
        {
            osSprintf(item_topic, ha_info->entities[pos].rgb_t, ha_info->base_topic);
            mqtt_subscribe(item_topic);
        }
        if (ha_info->entities[pos].fx_cmd_t && ha_info->entities[pos].fx_received)
        {
            osSprintf(item_topic, ha_info->entities[pos].fx_cmd_t, ha_info->base_topic);
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

    osStrncpy(tmp_buf, options, sizeof(tmp_buf));

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

    osStrncpy(tmp_buf, options, sizeof(tmp_buf));

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
