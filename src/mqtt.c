
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include "core/net.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "settings.h"
#include "platform.h"

#include "mqtt/mqtt_client.h"

#include "home_assistant.h"
#include "debug.h"
#include "mqtt.h"

OsMutex mqtt_tx_buffer_mutex;
OsMutex mqtt_box_mutex;

#define MQTT_BOX_INSTANCES 32
t_ha_info *mqtt_get_box(const char *box_id);
t_ha_info ha_box_instances[MQTT_BOX_INSTANCES];
t_ha_info ha_server_instance;

bool_t mqttConnected = FALSE;
error_t error;
MqttClientContext mqtt_context;
bool mqtt_fail = false;

#define MQTT_TOPIC_STRING_LENGTH 128

typedef struct
{
    bool used;
    char *topic;
    char *payload;
} mqtt_tx_buffer;

#define MQTT_TX_BUFFERS 512
mqtt_tx_buffer mqtt_tx_buffers[MQTT_TX_BUFFERS];

char *mqtt_sanitize_id(const char *input)
{
    char *new_str = osAllocMem(osStrlen(input) + 1);
    if (new_str == NULL)
    {
        return NULL;
    }

    char *dst = new_str;
    const char *src = input;
    while (*src)
    {
        if (isalnum((unsigned char)*src) || *src == '_' || *src == '-')
        {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0'; // null terminate the string

    return new_str;
}

char *mqtt_settingname_clean(const char *str)
{
    int length = osStrlen(str) + 1;

    char *new_str = osAllocMem(length);
    if (new_str == NULL)
    {
        return NULL;
    }
    osStrcpy(new_str, str);

    for (int pos = 0; pos < osStrlen(new_str); pos++)
    {
        if (new_str[pos] == '.')
        {
            new_str[pos] = '-';
        }
    }

    return new_str;
}

char *mqtt_fmt_create(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    // Calculate the length of the final string
    va_list tmp_args;
    va_copy(tmp_args, args);
    int length = osVsnprintf(NULL, 0, fmt, tmp_args);
    va_end(tmp_args);

    if (length < 0)
    {
        return NULL;
    }

    // Allocate memory for the new string
    char *new_str = osAllocMem(length + 1); // Add 1 for the null terminator
    if (new_str == NULL)
    {
        return NULL;
    }

    // Format the new string
    osVsnprintf(new_str, length + 1, fmt, args);

    va_end(args);

    return new_str;
}

char *mqtt_topic_str(const char *fmt, const char *param)
{
    char *first_s = osStrstr(fmt, "%s");
    if (first_s == NULL)
    {
        return "none";
    }

    int length = osStrlen(fmt) + osStrlen(param) - 2;

    char *new_str = osAllocMem(length + 1);
    if (new_str == NULL)
    {
        return NULL;
    }
    osStrcpy(new_str, "%s");

    osSprintf(&new_str[2], &fmt[2], param);

    return new_str;
}

char *mqtt_prefix(const char *path)
{
    static char buffer[MQTT_TOPIC_STRING_LENGTH];

    osSnprintf(buffer, sizeof(buffer), "%s/%s", settings_get_string("mqtt.topic"), path);

    return buffer;
}

error_t mqtt_sendEvent(const char *eventname, const char *content)
{
    char topic[MQTT_TOPIC_STRING_LENGTH];

    osSnprintf(topic, sizeof(topic), "%s/event/%s", settings_get_string("mqtt.topic"), eventname);
    mqttClientPublish(&mqtt_context, topic, content, osStrlen(content), MQTT_QOS_LEVEL_0, false, NULL);

    return NO_ERROR;
}

error_t mqtt_sendBoxEvent(const char *box_id, const char *eventname, const char *content)
{
    t_ha_info *ha_info = mqtt_get_box(box_id);
    if (!ha_info)
    {
        return ERROR_FAILURE;
    }
    char *topic = mqtt_fmt_create("%%s/%s", eventname);
    ha_transmit_topic(ha_info, topic, content);
    osFreeMem(topic);
    return NO_ERROR;
}

void mqttTestPublishCallback(MqttClientContext *context,
                             const char_t *topic, const uint8_t *message, size_t length,
                             bool_t dup, MqttQosLevel qos, bool_t retain, uint16_t packetId)
{
    // Debug message
    TRACE_INFO("packet received...\r\n");
    TRACE_INFO("  Dup: %u\r\n", dup);
    TRACE_INFO("  QoS: %u\r\n", qos);
    TRACE_INFO("  Retain: %u\r\n", retain);
    TRACE_INFO("  Packet Identifier: %u\r\n", packetId);
    TRACE_INFO("  Topic: %s\r\n", topic);
    TRACE_INFO("  Message (%" PRIuSIZE " bytes):  '%.*s'\r\n", length, (int)length, (char *)message);

    char *payload = osAllocMem(length + 1);
    osMemcpy(payload, message, length);
    payload[length] = 0;

    osAcquireMutex(&mqtt_box_mutex);
    for (int pos = 0; pos < MQTT_BOX_INSTANCES; pos++)
    {
        if (ha_box_instances[pos].initialized)
        {
            ha_received(&ha_box_instances[pos], (char *)topic, (const char *)payload);
        }
    }
    osReleaseMutex(&mqtt_box_mutex);
    ha_received(&ha_server_instance, (char *)topic, (const char *)payload);

    osFreeMem(payload);
}

bool mqtt_publish(const char *item_topic, const char *content)
{
    bool success = false;
    osAcquireMutex(&mqtt_tx_buffer_mutex);

    for (int pos = 0; pos < MQTT_TX_BUFFERS; pos++)
    {
        if (!mqtt_tx_buffers[pos].used)
        {
            mqtt_tx_buffers[pos].topic = strdup(item_topic);
            mqtt_tx_buffers[pos].payload = strdup(content);
            mqtt_tx_buffers[pos].used = true;
            success = true;
            break;
        }
    }
    osReleaseMutex(&mqtt_tx_buffer_mutex);

    return success;
}

bool mqtt_subscribe(const char *item_topic)
{
    mqttClientSubscribe(&mqtt_context, item_topic, MQTT_QOS_LEVEL_1, NULL);

    return true;
}

error_t mqttConnect(MqttClientContext *mqtt_context)
{
    error_t error;

    mqttClientInit(mqtt_context);
    mqttClientSetVersion(mqtt_context, MQTT_VERSION_3_1_1);
    mqttClientSetTransportProtocol(mqtt_context, MQTT_TRANSPORT_PROTOCOL_TCP);

    mqttClientRegisterPublishCallback(mqtt_context, mqttTestPublishCallback);

    mqttClientSetTimeout(mqtt_context, 20000);
    mqttClientSetKeepAlive(mqtt_context, 30);
    const char *server = settings_get_string("mqtt.hostname");
    uint32_t port = settings_get_unsigned("mqtt.port");

    mqttClientSetIdentifier(mqtt_context, settings_get_string("mqtt.identification"));
    mqttClientSetAuthInfo(mqtt_context, settings_get_string("mqtt.username"), settings_get_string("mqtt.password"));
    mqttClientSetWillMessage(mqtt_context, mqtt_prefix("status"), "offline", 7, MQTT_QOS_LEVEL_1, FALSE);

    do
    {
        TRACE_INFO("Connect to '%s'\r\n", server);
        void *resolve_ctx = resolve_host(server);
        if (!resolve_ctx)
        {
            TRACE_ERROR("Failed to resolve ipv4 address!\r\n");
            return ERROR_FAILURE;
        }

        int pos = 0;
        do
        {
            IpAddr mqttIp;
            if (!resolve_get_ip(resolve_ctx, pos, &mqttIp))
            {
                TRACE_ERROR("Failed to connect to MQTT server!\r\n");
                return ERROR_FAILURE;
            }
            char_t host[129];

            ipv4AddrToString(mqttIp.ipv4Addr, host);
            TRACE_INFO("  trying IP: %s\n", host);

            error = mqttClientConnect(mqtt_context, &mqttIp, port, TRUE);
        } while (0);

        if (error)
        {
            TRACE_ERROR("Failed to connect to MQTT: %d\r\n", error);
            break;
        }

        error = mqttClientSubscribe(mqtt_context, mqtt_prefix("*"), MQTT_QOS_LEVEL_1, NULL);
        if (error)
            break;

        error = mqttClientPublish(mqtt_context, mqtt_prefix("status"), "online", 6, MQTT_QOS_LEVEL_1, TRUE, NULL);
        if (error)
            break;

    } while (0);

    if (error)
    {
        mqttClientClose(mqtt_context);
    }

    return error;
}

void mqtt_thread()
{
    while (!settings_get_bool("internal.exit"))
    {
        if (!settings_get_bool("mqtt.enabled"))
        {
            osDelayTask(1000);
            continue;
        }

        if (!mqttConnected)
        {
            error = mqttConnect(&mqtt_context);
            if (!error)
            {
                TRACE_INFO("Connected\r\n");
                mqttConnected = TRUE;
                mqtt_fail = false;
                osAcquireMutex(&mqtt_box_mutex);
                for (int pos = 0; pos < MQTT_BOX_INSTANCES; pos++)
                {
                    if (ha_box_instances[pos].initialized)
                    {
                        ha_connected(&ha_box_instances[pos]);
                    }
                }
                osReleaseMutex(&mqtt_box_mutex);
                ha_connected(&ha_server_instance);
            }
            else
            {
                osDelayTask(10000);
            }
        }
        error = NO_ERROR;
        error = mqttClientTask(&mqtt_context, 500);

        if (error || mqtt_fail)
        {
            mqttClientClose(&mqtt_context);
            mqttConnected = FALSE;
            osDelayTask(2000);
        }

        /* process buffered Tx actions */
        osAcquireMutex(&mqtt_tx_buffer_mutex);
        for (int pos = 0; pos < MQTT_TX_BUFFERS; pos++)
        {
            if (mqtt_tx_buffers[pos].used)
            {
                mqttClientPublish(&mqtt_context, mqtt_tx_buffers[pos].topic, mqtt_tx_buffers[pos].payload, osStrlen(mqtt_tx_buffers[pos].payload), MQTT_QOS_LEVEL_0, false, NULL);
                osFreeMem(mqtt_tx_buffers[pos].topic);
                osFreeMem(mqtt_tx_buffers[pos].payload);
                mqtt_tx_buffers[pos].used = false;
            }
        }
        osReleaseMutex(&mqtt_tx_buffer_mutex);

        osAcquireMutex(&mqtt_box_mutex);
        for (int pos = 0; pos < MQTT_BOX_INSTANCES; pos++)
        {
            if (ha_box_instances[pos].initialized)
            {
                ha_loop(&ha_box_instances[pos]);
            }
        }
        osReleaseMutex(&mqtt_box_mutex);
        ha_loop(&ha_server_instance);
    }
}

void mqtt_publish_string(const char *name, const char *value)
{
    char path_buffer[128];

    sprintf(path_buffer, name, settings_get_string("mqtt.topic"));

    if (!mqtt_publish(path_buffer, value))
    {
        mqtt_fail = true;
    }
}

void mqtt_publish_float(const char *name, float value)
{
    char path_buffer[128];
    char buffer[32];

    sprintf(path_buffer, name, settings_get_string("mqtt.topic"));
    sprintf(buffer, "%0.4f", value);

    if (!mqtt_publish(path_buffer, buffer))
    {
        mqtt_fail = true;
    }
}

void mqtt_publish_int(const char *name, uint32_t value)
{
    char path_buffer[128];
    char buffer[32];

    if (value == 0x7FFFFFFF)
    {
        return;
    }
    sprintf(path_buffer, name, settings_get_string("mqtt.topic"));
    sprintf(buffer, "%d", value);

    if (!mqtt_publish(path_buffer, buffer))
    {
        mqtt_fail = true;
    }
}

void mqtt_publish_settings()
{
    int index = 0;
    do
    {
        setting_item_t *s = settings_get(index);
        if (!s)
        {
            break;
        }
        if (s->internal)
        {
            index++;
            continue;
        }

        char *name = mqtt_settingname_clean(s->option_name);
        char *status_topic = mqtt_topic_str("%s/%s/status", name);

        switch (s->type)
        {
        case TYPE_BOOL:
            mqtt_publish_string(status_topic, (*(bool *)s->ptr) ? "TRUE" : "FALSE");
            break;
        case TYPE_FLOAT:
            mqtt_publish_float(status_topic, *(float *)s->ptr);
            break;
        case TYPE_HEX:
        case TYPE_UNSIGNED:
            mqtt_publish_int(status_topic, *(uint32_t *)s->ptr);
            break;
        case TYPE_SIGNED:
            mqtt_publish_int(status_topic, *(uint32_t *)s->ptr);
            break;
        case TYPE_STRING:
            mqtt_publish_string(status_topic, *(char **)s->ptr);
            break;
        default:
            break;
        }
        index++;

        osFreeMem(name);
        osFreeMem(status_topic);
    } while (1);
}

void mqtt_settings_tx(t_ha_info *ha_info, const t_ha_entity *entity, void *ctx)
{
    setting_item_t *s = ctx;
    const char *status_topic = entity->stat_t;

    if (!s || !status_topic)
    {
        return;
    }

    switch (s->type)
    {
    case TYPE_BOOL:
        mqtt_publish_string(status_topic, (*(bool *)s->ptr) ? "TRUE" : "FALSE");
        break;
    case TYPE_FLOAT:
        mqtt_publish_float(status_topic, *(float *)s->ptr);
        break;
    case TYPE_HEX:
    case TYPE_UNSIGNED:
        mqtt_publish_int(status_topic, *(uint32_t *)s->ptr);
        break;
    case TYPE_SIGNED:
        mqtt_publish_int(status_topic, *(uint32_t *)s->ptr);
        break;
    case TYPE_STRING:
        mqtt_publish_string(status_topic, *(char **)s->ptr);
        break;
    default:
        break;
    }
}

void mqtt_settings_rx(t_ha_info *ha_info, const t_ha_entity *entity, void *ctx, const char *payload)
{
    setting_item_t *s = ctx;
    if (!s)
    {
        return;
    }

    switch (s->type)
    {
    case TYPE_BOOL:
        settings_set_bool(s->option_name, !osStrcasecmp(payload, "TRUE"));
        break;
    case TYPE_FLOAT:
    {
        float val;
        sscanf(payload, "%f", &val);
        settings_set_float(s->option_name, val);
        break;
    }
    case TYPE_HEX:
    {
        uint32_t val = strtoul(payload, NULL, 16);
        settings_set_unsigned(s->option_name, val);
        break;
    }
    case TYPE_UNSIGNED:
    {
        uint32_t val;
        sscanf(payload, "%u", &val);
        settings_set_unsigned(s->option_name, val);
        break;
    }
    case TYPE_SIGNED:
    {
        int32_t val;
        sscanf(payload, "%d", &val);
        settings_set_signed(s->option_name, val);
        break;
    }
    case TYPE_STRING:
    {
        settings_set_string(s->option_name, payload);
        break;
    }
    default:
        break;
    }
}

void mqtt_init_box(const char *box_id_in, t_ha_info *ha_box_instance)
{
    t_ha_entity entity;
    char *box_id = mqtt_sanitize_id(box_id_in);

    ha_setup(ha_box_instance);
    osSprintf(ha_box_instance->name, "Toniebox: '%s'", box_id_in);
    osSprintf(ha_box_instance->id, "teddyCloud_Box_%s", box_id);
    osSprintf(ha_box_instance->base_topic, "%s/box/%s", settings_get_string("mqtt.topic"), box_id);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TagInvalid";
    entity.name = "Tag Invalid";
    entity.type = ha_sensor;
    entity.stat_t = "%s/TagInvalid";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TagValid";
    entity.name = "Tag Valid";
    entity.type = ha_sensor;
    entity.stat_t = "%s/TagValid";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "VolUp";
    entity.name = "Volume Up";
    entity.type = ha_binary_sensor;
    entity.stat_t = "%s/VolUp";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "VolDown";
    entity.name = "Volume Down";
    entity.type = ha_binary_sensor;
    entity.stat_t = "%s/VolDown";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "CloudRequest";
    entity.name = "Cloud Request";
    entity.type = ha_sensor;
    entity.stat_t = "%s/CloudRequest";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "BoxTilt";
    entity.name = "Box Tilt";
    entity.type = ha_sensor;
    entity.stat_t = "%s/BoxTilt";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TiltForward";
    entity.name = "Tilt Forward";
    entity.type = ha_sensor;
    entity.stat_t = "%s/TiltForward";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TiltBackward";
    entity.name = "Tilt Backward";
    entity.type = ha_sensor;
    entity.stat_t = "%s/TiltBackward";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "Playback";
    entity.name = "Playback";
    entity.type = ha_sensor;
    entity.stat_t = "%s/Playback";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "VolumeLevel";
    entity.name = "Volume Level";
    entity.type = ha_sensor;
    entity.stat_t = "%s/VolumeLevel";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "VolumedB";
    entity.name = "Volume dB";
    entity.type = ha_sensor;
    entity.stat_t = "%s/VolumedB";
    entity.unit_of_meas = "dB";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "Charger";
    entity.name = "Charger";
    entity.type = ha_binary_sensor;
    entity.stat_t = "%s/Charger";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "LastSeen";
    entity.name = "LastSeen";
    entity.type = ha_sensor;
    entity.stat_t = "%s/LastSeen";
    entity.dev_class = "timestamp";
    ha_add(ha_box_instance, &entity);

    osFreeMem(box_id);
}

t_ha_info *mqtt_get_box(const char *box_id)
{
    if (!box_id)
    {
        return NULL;
    }
    t_ha_info *ret = NULL;
    char *name = mqtt_fmt_create("teddyCloud_Box_%s", box_id);

    osAcquireMutex(&mqtt_box_mutex);
    for (int pos = 0; pos < MQTT_BOX_INSTANCES; pos++)
    {
        if (ha_box_instances[pos].initialized && !osStrcasecmp(name, ha_box_instances[pos].id))
        {
            ret = &ha_box_instances[pos];
            break;
        }
    }
    if (!ret)
    {
        for (int pos = 0; pos < MQTT_BOX_INSTANCES; pos++)
        {
            if (!ha_box_instances[pos].initialized)
            {
                ret = &ha_box_instances[pos];
                mqtt_init_box(box_id, ret);
                ha_connected(ret);
                break;
            }
        }
    }
    osReleaseMutex(&mqtt_box_mutex);
    osFreeMem(name);
    return ret;
}

void mqtt_init()
{
    osCreateMutex(&mqtt_tx_buffer_mutex);
    osCreateMutex(&mqtt_box_mutex);

    osCreateTask("MQTT", &mqtt_thread, NULL, 1024, 0);

    t_ha_entity entity;

    ha_setup(&ha_server_instance);
    osSprintf(ha_server_instance.name, "%s - Server", settings_get_string("mqtt.topic"));
    osStrcpy(ha_server_instance.id, "teddyCloudSettings");
    osStrcpy(ha_server_instance.base_topic, settings_get_string("mqtt.topic"));

    int index = 0;
    do
    {
        setting_item_t *s = settings_get(index);
        if (!s)
        {
            break;
        }
        if (s->internal)
        {
            index++;
            continue;
        }
        memset(&entity, 0x00, sizeof(entity));

        char *name = mqtt_settingname_clean(s->option_name);
        entity.id = name;
        entity.name = mqtt_fmt_create("%s - %s", s->option_name, s->description);
        entity.stat_t = mqtt_topic_str("%s/%s/status", name);
        entity.cmd_t = mqtt_topic_str("%s/%s/command", name);
        entity.transmit = &mqtt_settings_tx;
        entity.transmit_ctx = s;
        entity.received = &mqtt_settings_rx;
        entity.received_ctx = s;

        entity.type = ha_unused;
        switch (s->type)
        {
        case TYPE_BOOL:
            entity.type = ha_switch;
            break;
        case TYPE_FLOAT:
            entity.type = ha_number;
            entity.min = s->min.float_value;
            entity.max = s->max.float_value;
            break;
        case TYPE_HEX:
        case TYPE_UNSIGNED:
            entity.type = ha_number;
            entity.min = s->min.unsigned_value;
            entity.max = s->max.unsigned_value;
            break;
        case TYPE_SIGNED:
            entity.type = ha_number;
            entity.min = s->min.signed_value;
            entity.max = s->max.signed_value;
            break;
        case TYPE_STRING:
            entity.type = ha_text;
            break;
        default:
            break;
        }
        if (entity.type != ha_unused)
        {
            ha_add(&ha_server_instance, &entity);
        }
        index++;
    } while (1);
}
