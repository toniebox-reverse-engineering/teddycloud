
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include "core/net.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "settings.h"
#include "platform.h"

#include "mqtt/mqtt_client.h"

#include "home_assistant.h"
#include "debug.h"

bool_t mqttConnected = FALSE;
error_t error;
MqttClientContext mqtt_context;
static const char *mqtt_client = "teddyCloud";
bool mqtt_fail = false;

void mqttTestPublishCallback(MqttClientContext *context,
                             const char_t *topic, const uint8_t *message, size_t length,
                             bool_t dup, MqttQosLevel qos, bool_t retain, uint16_t packetId)
{
    // Debug message
    TRACE_INFO("PUBLISH packet received...\r\n");
    TRACE_INFO("  Dup: %u\r\n", dup);
    TRACE_INFO("  QoS: %u\r\n", qos);
    TRACE_INFO("  Retain: %u\r\n", retain);
    TRACE_INFO("  Packet Identifier: %u\r\n", packetId);
    TRACE_INFO("  Topic: %s\r\n", topic);
    TRACE_INFO("  Message (%" PRIuSIZE " bytes):\r\n", length);
    TRACE_INFO_ARRAY("    ", message, length);

    ha_received((char *)topic, (const char *)message);
}

error_t mqtt_sendEvent(const char *eventname, const char *content)
{
    char topic[128];

    osSnprintf(topic, sizeof(topic), "%s/event/%s", mqtt_client, eventname);
    mqttClientPublish(&mqtt_context, topic, content, osStrlen(content), MQTT_QOS_LEVEL_0, false, NULL);

    return NO_ERROR;
}

bool mqtt_publish(const char *item_topic, const char *content)
{
    mqttClientPublish(&mqtt_context, item_topic, content, osStrlen(content), MQTT_QOS_LEVEL_0, false, NULL);

    return true;
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
    mqttClientSetWillMessage(mqtt_context, "teddyCloud/status",
                             "offline", 7, MQTT_QOS_LEVEL_1, FALSE);

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
            TRACE_ERROR("Failed to connect to ipv4 address %d\r\n", error);
            break;
        }

        error = mqttClientSubscribe(mqtt_context,
                                    "teddyCloud/*", MQTT_QOS_LEVEL_1, NULL);
        if (error)
            break;

        error = mqttClientPublish(mqtt_context, "teddyCloud/status",
                                  "online", 6, MQTT_QOS_LEVEL_1, TRUE, NULL);
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
                ha_connected();
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
        ha_loop();
    }
}

void mqtt_publish_string(const char *name, const char *value)
{
    char path_buffer[128];

    sprintf(path_buffer, name, mqtt_client);

    if (!mqtt_publish(path_buffer, value))
    {
        mqtt_fail = true;
    }
}

void mqtt_publish_float(const char *name, float value)
{
    char path_buffer[128];
    char buffer[32];

    sprintf(path_buffer, name, mqtt_client);
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
    sprintf(path_buffer, name, mqtt_client);
    sprintf(buffer, "%d", value);

    if (!mqtt_publish(path_buffer, buffer))
    {
        mqtt_fail = true;
    }
}

void mqtt_init()
{
    osCreateTask("MQTT", &mqtt_thread, NULL, 1024, 0);

    ha_setup();

    t_ha_entity entity;

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "status";
    entity.name = "Status message";
    entity.type = ha_sensor;
    entity.stat_t = "%s/status";
    ha_add(&entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TagInvalid";
    entity.name = "Tag Invalid";
    entity.type = ha_sensor;
    entity.stat_t = "%s/event/TagInvalid";
    ha_add(&entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TagValid";
    entity.name = "Tag Valid";
    entity.type = ha_sensor;
    entity.stat_t = "%s/event/TagValid";
    ha_add(&entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "VolUp";
    entity.name = "Volume Up";
    entity.type = ha_binary_sensor;
    entity.stat_t = "%s/event/VolUp";
    ha_add(&entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "VolDown";
    entity.name = "Volume Down";
    entity.type = ha_binary_sensor;
    entity.stat_t = "%s/event/VolDown";
    ha_add(&entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "CloudRequest";
    entity.name = "Cloud Request";
    entity.type = ha_sensor;
    entity.stat_t = "%s/event/CloudRequest";
    ha_add(&entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "BoxTilt";
    entity.name = "Box Tilt";
    entity.type = ha_sensor;
    entity.stat_t = "%s/event/BoxTilt";
    ha_add(&entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TiltForward";
    entity.name = "Tilt Forward";
    entity.type = ha_sensor;
    entity.stat_t = "%s/event/TiltForward";
    ha_add(&entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "TiltBackward";
    entity.name = "Tilt Backward";
    entity.type = ha_sensor;
    entity.stat_t = "%s/event/TiltBackward";
    ha_add(&entity);

    memset(&entity, 0x00, sizeof(entity));
    entity.id = "Playback";
    entity.name = "Playback";
    entity.type = ha_sensor;
    entity.stat_t = "%s/event/Playback";
    ha_add(&entity);
}
