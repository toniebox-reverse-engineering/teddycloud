
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "core/net.h"
#include "core/ip.h"
#include "core/tcp.h"
#include "settings.h"

#include "mqtt/mqtt_client.h"

#include "debug.h"

#if 0
bool_t mqttConnected = FALSE;
error_t error;
MqttClientContext mqtt_context;

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

    // Check topic name
    if (!strcmp(topic, "teddybench/pong"))
    {
        if (length == 2 && !strncasecmp((char_t *)message, "on", 2))
        {
        }
    }
}

error_t mqttConnect(MqttClientContext *mqtt_context)
{
    error_t error;
    IpAddr mqttIp;
    mqttClientInit(mqtt_context);
    mqttClientSetVersion(mqtt_context, MQTT_VERSION_3_1_1);
    mqttClientSetTransportProtocol(mqtt_context, MQTT_TRANSPORT_PROTOCOL_TCP);
    // Register publish callback function
    mqttClientRegisterPublishCallback(mqtt_context, mqttTestPublishCallback);

    mqttClientSetTimeout(mqtt_context, 20000);
    mqttClientSetKeepAlive(mqtt_context, 30);
    mqttClientSetIdentifier(mqtt_context, "teddycloud");
    mqttClientSetAuthInfo(mqtt_context, "username", "password");
    mqttClientSetWillMessage(mqtt_context, "teddycloud/status",
                             "offline", 7, MQTT_QOS_LEVEL_1, FALSE);

    do
    {
        // Establish connection with the MQTT server
        error = mqttClientConnect(mqtt_context,
                                  &mqttIp, 1883, TRUE);
        // Any error to report?
        if (error)
            break;

        // Subscribe to the desired topics
        error = mqttClientSubscribe(mqtt_context,
                                    "teddycloud/*", MQTT_QOS_LEVEL_1, NULL);
        // Any error to report?
        if (error)
            break;

        // Send PUBLISH packet
        error = mqttClientPublish(mqtt_context, "teddycloud/status",
                                  "online", 6, MQTT_QOS_LEVEL_1, TRUE, NULL);
        // Any error to report?
        if (error)
            break;

        // End of exception handling block
    } while (0);

    // Check status code
    if (error)
    {
        // Close connection
        mqttClientClose(mqtt_context);
    }

    // Return status code
    return error;
}

void mqtt_thread()
{
    while (!settings_get_bool("internal.exit"))
    {
        if (!mqttConnected)
        {
            error = mqttConnect(&mqtt_context);
            if (!error)
            {
                mqttConnected = TRUE;
            }
        }
        error = NO_ERROR;
        error = mqttClientPublish(&mqtt_context, "teddycloud/ping",
                                  "pong", 4, MQTT_QOS_LEVEL_1, TRUE, NULL);
        if (!error)
        {
            // Process events
            error = mqttClientTask(&mqtt_context, 100);
        }
        if (error)
        {
            // Close connection
            mqttClientClose(&mqtt_context);
            // Update connection state
            mqttConnected = FALSE;
            // Recovery delay
            osDelayTask(2000);
        }
    }
}

#endif
