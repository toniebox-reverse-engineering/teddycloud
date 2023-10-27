#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include "core/net.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "settings.h"
#include "platform.h"
#include "server_helpers.h"

typedef struct
{
    char *hostname;
    char *identification;
    char *username;
    char *password;
    char *topic;

} mqtt_ctx_t;

#define MQTT_CLIENT_PRIVATE_CONTEXT mqtt_ctx_t *mqtt_ctx;

#include "mqtt/mqtt_client.h"

#include "home_assistant.h"
#include "debug.h"
#include "mutex_manager.h"
#include "mqtt.h"

#define MQTT_BOX_INSTANCES 32
t_ha_info *mqtt_get_box(client_ctx_t *client_ctx);
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

char *mqtt_prefix(const char *path, char *topic)
{
    static char buffer[MQTT_TOPIC_STRING_LENGTH];

    osSnprintf(buffer, sizeof(buffer), "%s/%s", topic, path);

    return buffer;
}

error_t mqtt_sendEvent(const char *eventname, const char *content, client_ctx_t *client_ctx)
{
    char topic[MQTT_TOPIC_STRING_LENGTH];

    osSnprintf(topic, sizeof(topic), "%s/event/%s", settings_get_string("mqtt.topic"), eventname);
    mqttClientPublish(&mqtt_context, topic, content, osStrlen(content), client_ctx->settings->mqtt.qosLevel, false, NULL);

    return NO_ERROR;
}

error_t mqtt_sendBoxEvent(const char *eventname, const char *content, client_ctx_t *client_ctx)
{
    t_ha_info *ha_box = mqtt_get_box(client_ctx);
    if (!ha_box)
    {
        return ERROR_FAILURE;
    }

    bool_t updated = false;
    settings_box_type boxIC = client_ctx->settings->internal.toniebox_firmware.boxIC;
    char hw[7 + 1];
    hw[0] = '\0';

    switch (boxIC)
    {
    case BOX_CC3200:
        osSnprintf(hw, sizeof(hw), "CC3200");
        break;
    case BOX_CC3235:
        osSnprintf(hw, sizeof(hw), "CC3235");
        break;
    case BOX_ESP32:
        osSnprintf(hw, sizeof(hw), "ESP32");
        break;
    case BOX_UNKNOWN:
        break;
    }
    if (osStrcmp(hw, ha_box->hw) != 0 && osStrlen(ha_box->hw) == 0)
    {
        osSnprintf(ha_box->hw, sizeof(ha_box->hw), "%s", hw);
        updated = true;
    }
    char *version = client_ctx->settings->internal.toniebox_firmware.rtnlFullVersion;
    time_t swUa = client_ctx->settings->internal.toniebox_firmware.uaVersionFirmware;
    char *swEsp = client_ctx->settings->internal.toniebox_firmware.uaEsp32Firmware;

    if (osStrlen(version) > 0 && osStrcmp(version, ha_box->sw) != 0 && osStrlen(ha_box->sw) == 0)
    {
        osSnprintf(ha_box->sw, sizeof(ha_box->sw), "%s", version);
        updated = true;
    }
    else if (osStrlen(version) == 0 && swUa > 0)
    {
        char sw[MAX_LEN];
        osSnprintf(sw, sizeof(sw), "%" PRIuTIME, swUa);
        if (osStrcmp(sw, ha_box->sw) != 0 && osStrlen(ha_box->sw) == 0)
        {
            osSnprintf(ha_box->sw, sizeof(ha_box->sw), "%s", sw);
            updated = true;
        }
    }
    else if (client_ctx->settings->internal.toniebox_firmware.uaEsp32Firmware != NULL)
    {
        if (osStrcmp(swEsp, ha_box->sw) != 0 && osStrlen(ha_box->sw) == 0)
        {
            osSnprintf(ha_box->sw, sizeof(ha_box->sw), "%s", swEsp);
            updated = true;
        }
    }

    if (updated)
    {
        ha_publish(ha_box);
        ha_transmit_all(ha_box);
    }

    char *topic = custom_asprintf("%%s/%s", eventname);
    ha_transmit_topic(ha_box, topic, content);
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

    mutex_lock(MUTEX_MQTT_BOX);
    for (int pos = 0; pos < MQTT_BOX_INSTANCES; pos++)
    {
        if (ha_box_instances[pos].initialized)
        {
            ha_received(&ha_box_instances[pos], (char *)topic, (const char *)payload);
        }
    }
    mutex_unlock(MUTEX_MQTT_BOX);
    ha_received(&ha_server_instance, (char *)topic, (const char *)payload);

    osFreeMem(payload);
}

/**
 * @brief Publishes an MQTT message by placing it into a transmission buffer.
 *
 * This function attempts to queue an MQTT message for transmission based on the topic and content provided.
 * The function looks for an available slot in the transmission buffer or tries to find an existing message
 * with the same topic. If a message with the same topic is found:
 *  - If the content matches and it is the last message in queue, the message is considered already queued.
 *  - If the content does not match and the topic has been seen more than twice, the existing message's content
 *    is replaced to reduce traffic.
 *
 * Note: The function ensures thread-safety by acquiring and releasing a mutex during the buffer operations.
 *
 * @param item_topic The topic of the MQTT message.
 * @param content The content (payload) of the MQTT message.
 * @return Returns true if the message was successfully queued or is already in the queue, otherwise false.
 */
bool mqtt_publish(const char *item_topic, const char *content)
{
    int entries = 0;
    bool success = false;

    mutex_lock(MUTEX_MQTT_TX_BUFFER);
    for (int pos = 0; pos < MQTT_TX_BUFFERS; pos++)
    {
        if (!mqtt_tx_buffers[pos].used)
        {
            /* found the first empty slot */
            if (success)
            {
                /* was the content already queued before? */
                break;
            }
            /* new content to send */
            mqtt_tx_buffers[pos].topic = strdup(item_topic);
            mqtt_tx_buffers[pos].payload = strdup(content);
            mqtt_tx_buffers[pos].used = true;
            success = true;
            break;
        }
        else if (!osStrcmp(mqtt_tx_buffers[pos].topic, item_topic))
        {
            /* topic matches, assume content differs */
            success = false;

            if (!osStrcmp(mqtt_tx_buffers[pos].payload, content))
            {
                /* content matched */
                success = true;
            }
            else if (++entries > 2)
            {
                /* when seen more than twice, replace the last one to reduce traffic */
                osFreeMem(mqtt_tx_buffers[pos].payload);
                mqtt_tx_buffers[pos].payload = strdup(content);
                mqtt_tx_buffers[pos].used = true;
                success = true;
                break;
            }
        }
    }
    mutex_unlock(MUTEX_MQTT_TX_BUFFER);

    return success;
}

bool mqtt_subscribe(const char *item_topic)
{
    mqttClientSubscribe(&mqtt_context, item_topic, MQTT_QOS_LEVEL_2, NULL);

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
    const char *server = mqtt_context->mqtt_ctx->hostname;
    uint32_t port = settings_get_unsigned("mqtt.port");

    mqttClientSetIdentifier(mqtt_context, mqtt_context->mqtt_ctx->identification);
    mqttClientSetAuthInfo(mqtt_context, mqtt_context->mqtt_ctx->username, mqtt_context->mqtt_ctx->password);
    mqttClientSetWillMessage(mqtt_context, mqtt_prefix("status", mqtt_context->mqtt_ctx->topic), "offline", 7, MQTT_QOS_LEVEL_2, TRUE);

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

        error = mqttClientSubscribe(mqtt_context, mqtt_prefix("*", mqtt_context->mqtt_ctx->topic), MQTT_QOS_LEVEL_2, NULL);
        if (error)
            break;

        error = mqttClientPublish(mqtt_context, mqtt_prefix("status", mqtt_context->mqtt_ctx->topic), "online", 6, MQTT_QOS_LEVEL_2, TRUE, NULL);
        if (error)
            break;

    } while (0);

    if (error)
    {
        mqttClientClose(mqtt_context);
    }

    return error;
}

void mqtt_free_settings(mqtt_ctx_t *mqtt_ctx)
{
    if (mqtt_ctx->hostname)
    {
        osFreeMem(mqtt_ctx->hostname);
    }
    if (mqtt_ctx->identification)
    {
        osFreeMem(mqtt_ctx->identification);
    }
    if (mqtt_ctx->username)
    {
        osFreeMem(mqtt_ctx->username);
    }
    if (mqtt_ctx->password)
    {
        osFreeMem(mqtt_ctx->password);
    }
    if (mqtt_ctx->topic)
    {
        osFreeMem(mqtt_ctx->topic);
    }
    osMemset(&mqtt_ctx, 0x00, sizeof(mqtt_ctx));
}

void mqtt_get_settings(mqtt_ctx_t *mqtt_ctx)
{
    mqtt_free_settings(mqtt_ctx);

    mqtt_ctx->hostname = strdup(settings_get_string("mqtt.hostname"));
    mqtt_ctx->identification = strdup(settings_get_string("mqtt.identification"));
    mqtt_ctx->username = strdup(settings_get_string("mqtt.username"));
    mqtt_ctx->password = strdup(settings_get_string("mqtt.password"));
    mqtt_ctx->topic = strdup(settings_get_string("mqtt.topic"));
}

void mqtt_thread()
{
    uint32_t errors = 0;
    mqtt_ctx_t mqtt_ctx;
    osMemset(&mqtt_ctx, 0x00, sizeof(mqtt_ctx));

    mqtt_context.mqtt_ctx = &mqtt_ctx;

    while (!settings_get_bool("internal.exit"))
    {
        if (!settings_get_bool("mqtt.enabled"))
        {
            if (mqttConnected)
            {
                TRACE_INFO("Disconnecting\r\n");
                mqttClientClose(&mqtt_context);
                mqttConnected = FALSE;
            }

            osDelayTask(MQTT_CLIENT_DEFAULT_TIMEOUT);
            continue;
        }

        if (!mqttConnected)
        {
            mqtt_get_settings(mqtt_context.mqtt_ctx);

            error = mqttConnect(&mqtt_context);
            if (error)
            {
                osDelayTask(MQTT_CLIENT_DEFAULT_TIMEOUT);
                if (++errors > 10)
                {
                    TRACE_INFO("Too many errors, disabling MQTT\r\n");
                    errors = 0;
                    settings_set_bool("mqtt.enabled", false);
                }
                continue;
            }

            TRACE_INFO("Connected\r\n");
            mqttConnected = TRUE;
            mqtt_fail = false;
            mutex_lock(MUTEX_MQTT_BOX);
            for (int pos = 0; pos < MQTT_BOX_INSTANCES; pos++)
            {
                if (ha_box_instances[pos].initialized)
                {
                    ha_connected(&ha_box_instances[pos]);
                }
            }
            mutex_unlock(MUTEX_MQTT_BOX);
            ha_connected(&ha_server_instance);
        }
        error = NO_ERROR;
        error = mqttClientTask(&mqtt_context, 500);

        if (error || mqtt_fail)
        {
            mqttClientClose(&mqtt_context);
            mqttConnected = FALSE;
            osDelayTask(MQTT_CLIENT_DEFAULT_TIMEOUT);
        }

        /* process buffered Tx actions */
        mutex_lock(MUTEX_MQTT_TX_BUFFER);
        for (int pos = 0; pos < MQTT_TX_BUFFERS; pos++)
        {
            if (mqtt_tx_buffers[pos].used)
            {
                mqttClientPublish(&mqtt_context, mqtt_tx_buffers[pos].topic, mqtt_tx_buffers[pos].payload, osStrlen(mqtt_tx_buffers[pos].payload), settings_get_unsigned("mqtt.qosLevel"), false, NULL);
                osFreeMem(mqtt_tx_buffers[pos].topic);
                osFreeMem(mqtt_tx_buffers[pos].payload);
                mqtt_tx_buffers[pos].used = false;
            }
        }
        mutex_unlock(MUTEX_MQTT_TX_BUFFER);

        mutex_lock(MUTEX_MQTT_BOX);
        for (int pos = 0; pos < MQTT_BOX_INSTANCES; pos++)
        {
            if (ha_box_instances[pos].initialized)
            {
                ha_loop(&ha_box_instances[pos]);
            }
        }
        mutex_unlock(MUTEX_MQTT_BOX);
        ha_loop(&ha_server_instance);
    }

    mqtt_free_settings(mqtt_context.mqtt_ctx);
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

    // TODO allow overlays
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

    // TODO allow overlays
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

error_t mqtt_init_box(t_ha_info *ha_box_instance, client_ctx_t *client_ctx)
{
    t_ha_entity entity;
    const char *box_id = client_ctx->state->box.id;
    const char *box_name = client_ctx->state->box.name;

    if (!box_id)
    {
        box_id = "NULL";
    }
    if (!box_name)
    {
        box_name = "NULL";
    }

    if (client_ctx->settings->internal.overlayNumber == 0)
    {
        TRACE_INFO("Skipping client '%s' (cn: '%s')\r\n", box_name, box_id);
        return ERROR_ABORTED; // Skip clients without an overlay / box
    }

    ha_setup(ha_box_instance);
    osSprintf(ha_box_instance->name, "%s", box_name);
    osSprintf(ha_box_instance->id, "%s_Box_%s", settings_get_string("mqtt.topic"), box_id);
    osSprintf(ha_box_instance->base_topic, "%s/box/%s", settings_get_string("mqtt.topic"), box_id);
    osSprintf(ha_box_instance->mf, "%s", "tonies");
    osSprintf(ha_box_instance->mdl, "%s", "Toniebox");
    osStrcpy(ha_box_instance->via, ha_server_instance.id);
    osStrcpy(ha_box_instance->hw, "");
    osStrcpy(ha_box_instance->sw, "");
    osStrcpy(ha_box_instance->availability_topic, ha_server_instance.availability_topic); // TODO for each box individually
    TRACE_INFO("Registered new box '%s' (cn: '%s')\r\n", box_name, box_id);
    TRACE_INFO("Using base path '%s' and id '%s'\r\n", ha_box_instance->base_topic, ha_box_instance->id);

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
    entity.type = ha_event;
    entity.event_types = "pressed;double-pressed;triple-pressed";
    entity.stat_t = "%s/VolUp";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "VolDown";
    entity.name = "Volume Down";
    entity.type = ha_event;
    entity.event_types = "pressed;double-pressed;triple-pressed";
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
    entity.id = "KnockForward";
    entity.name = "Knock Forward";
    entity.type = ha_event;
    entity.event_types = "triggered";
    entity.stat_t = "%s/KnockForward";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "KnockBackward";
    entity.name = "Knock Backward";
    entity.type = ha_event;
    entity.event_types = "triggered";
    entity.stat_t = "%s/KnockBackward";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TiltForward";
    entity.name = "Tilt Forward";
    entity.type = ha_event;
    entity.event_types = "triggered";
    entity.stat_t = "%s/TiltForward";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TiltBackward";
    entity.name = "Tilt Backward";
    entity.type = ha_event;
    entity.event_types = "triggered";
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

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "LastCloudTime";
    entity.name = "LastCloudTime";
    entity.type = ha_sensor;
    entity.stat_t = "%s/LastCloudTime";
    entity.dev_class = "timestamp";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "LastCloudOtaTime";
    entity.name = "LastCloudOtaTime";
    entity.type = ha_sensor;
    entity.stat_t = "%s/LastCloudOtaTime";
    entity.dev_class = "timestamp";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "LastCloudClaimTime";
    entity.name = "LastCloudClaimTime";
    entity.type = ha_sensor;
    entity.stat_t = "%s/LastCloudClaimTime";
    entity.dev_class = "timestamp";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "LastCloudContentTime";
    entity.name = "LastCloudContentTime";
    entity.type = ha_sensor;
    entity.stat_t = "%s/LastCloudContentTime";
    entity.dev_class = "timestamp";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "LastCloudFreshnessCheckTime";
    entity.name = "LastCloudFreshnessCheckTime";
    entity.type = ha_sensor;
    entity.stat_t = "%s/LastCloudFreshnessCheckTime";
    entity.dev_class = "timestamp";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "LastCloudResetTime";
    entity.name = "LastCloudResetTime";
    entity.type = ha_sensor;
    entity.stat_t = "%s/LastCloudResetTime";
    entity.dev_class = "timestamp";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "ContentAudioId";
    entity.name = "Content Audio Id";
    entity.type = ha_sensor;
    entity.stat_t = "%s/ContentAudioId";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "ContentTitle";
    entity.name = "Content Title";
    entity.type = ha_sensor;
    entity.stat_t = "%s/ContentTitle";
    ha_add(ha_box_instance, &entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "ContentPicture";
    entity.name = "Content Picture";
    entity.type = ha_image;
    entity.url_t = "%s/ContentPicture";
    ha_add(ha_box_instance, &entity);

    return NO_ERROR;
}

t_ha_info *mqtt_get_box(client_ctx_t *client_ctx)
{
    t_ha_info *ret = NULL;

    const char *box_id = client_ctx->state->box.id;

    char *name = custom_asprintf("%s_Box_%s", settings_get_string("mqtt.topic"), box_id);

    mutex_lock(MUTEX_MQTT_BOX);
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
                if (mqtt_init_box(&ha_box_instances[pos], client_ctx) == NO_ERROR)
                {
                    ret = &ha_box_instances[pos];
                    ha_connected(ret);
                }
                break;
            }
        }
    }
    mutex_unlock(MUTEX_MQTT_BOX);
    osFreeMem(name);
    return ret;
}

void mqtt_init()
{
    osCreateTask("MQTT", &mqtt_thread, NULL, 1024, 0);

    t_ha_entity entity;

    ha_setup(&ha_server_instance);
    osStrcpy(ha_server_instance.name, settings_get_string("hass.name"));
    osStrcpy(ha_server_instance.id, settings_get_string("hass.id"));
    osStrcpy(ha_server_instance.base_topic, settings_get_string("mqtt.topic"));
    osStrcpy(ha_server_instance.availability_topic, (const char *)mqtt_prefix("status", ha_server_instance.base_topic));

    for (size_t index = 0; index < settings_get_size(); index++)
    {
        setting_item_t *s = settings_get(index);
        if (s->internal)
        {
            index++;
            continue;
        }
        memset(&entity, 0x00, sizeof(entity));

        char *name = mqtt_settingname_clean(s->option_name);
        entity.id = name;
        entity.name = custom_asprintf("%s - %s", s->option_name, s->description);
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
    };
}