# TeddyCloud MQTT Control Entities

## Overview

TeddyCloud exposes per-box control entities via MQTT with Home Assistant Discovery.
These entities allow changing Toniebox settings that are applied during the next
**freshness check** (the periodic check-in the box makes with the server).

### Architecture Limitation

The Toniebox communicates with TeddyCloud via HTTPS. The RTNL protocol is a
**one-way** notification channel (box → server). There is **no real-time command
channel** from server to box. Settings are pushed to the box only via the freshness
check response.

This means:
- Setting changes (volume limits, LED, slap) take effect on the **next freshness check**, not immediately.
- **Actual volume level** (0–16) reported by the box is **read-only** — there is no protocol field to set it.
- **Playback pause/resume** is **not possible** — no command channel exists.
- **Stream stop** interrupts server-side content delivery immediately, but the box may continue playing buffered content.

## Per-Box Entities

When a Toniebox connects, the following HA entities are created automatically.

### Read-Only Sensors (from RTNL)

| Entity ID        | HA Type         | Description                        |
|------------------|-----------------|------------------------------------|
| Playback         | sensor          | "ON" / "OFF"                       |
| VolumeLevel      | sensor          | Current volume level (integer)     |
| VolumedB         | sensor          | Current volume in dB               |
| Charger          | binary_sensor   | Charger connected                  |
| TagValid         | sensor          | Valid tag placed                   |
| TagInvalid       | sensor          | Invalid tag placed                 |
| ContentAudioId   | sensor          | Audio ID of current content        |
| ContentTitle     | sensor          | Title of current content           |
| ContentPicture   | image           | Cover image of current content     |
| LastSeen         | sensor          | Last box check-in timestamp        |

### Command Entities (bidirectional via freshness check)

| Entity ID        | HA Type  | Range / Values       | Description                          |
|------------------|----------|----------------------|--------------------------------------|
| CmdStop          | button   | (press)              | Stop server-side audio stream        |
| CmdVolLimitSpk   | number   | 0–3                  | Speaker volume limit (0=25%…3=100%)  |
| CmdVolLimitHdp   | number   | 0–3                  | Headphone volume limit (0=25%…3=100%)|
| CmdLed           | number   | 0–2                  | LED mode (0=on, 1=off, 2=dimmed)     |
| CmdSlapEnabled   | switch   | TRUE / FALSE         | Enable slap-to-skip gesture          |
| CmdSlapDirection | switch   | TRUE / FALSE         | Slap direction (TRUE=back-left)      |

### Event Entities

| Entity ID      | HA Type | Events                                    |
|----------------|---------|-------------------------------------------|
| VolUp          | event   | pressed, double-pressed, triple-pressed   |
| VolDown        | event   | pressed, double-pressed, triple-pressed   |
| KnockForward   | event   | triggered                                 |
| KnockBackward  | event   | triggered                                 |
| TiltForward    | event   | triggered                                 |
| TiltBackward   | event   | triggered                                 |

## MQTT Topic Structure

Topics follow the pattern:
```
{mqtt.topic}/box/{box_cn}/{EntityId}         # state topic
{mqtt.topic}/box/{box_cn}/{EntityId}/set     # command topic
```

Example with `mqtt.topic = teddyCloud` and box CN `deadbeef`:
```
teddyCloud/box/deadbeef/CmdVolLimitSpk       # current value
teddyCloud/box/deadbeef/CmdVolLimitSpk/set   # set new value
```

HA Discovery config topics:
```
homeassistant/{type}/{mqtt.topic}_Box_{box_cn}/{EntityId}/config
```

## REST API

All commands are also available via the REST API:
```
GET /api/box/cmd?boxId={commonName}&cmd={command}&value={value}
```

Available commands: `stop`, `volLimitSpk`, `volLimitHdp`, `led`, `slapEnabled`, `slapDir`

## Test Plan (mosquitto)

Replace `TOPIC` with your `mqtt.topic` setting (default: `teddyCloud`) and
`BOX_CN` with your box's common name.

### Subscribe to all box state topics
```bash
mosquitto_sub -h BROKER -t "TOPIC/box/BOX_CN/#" -v
```

### Set speaker volume limit to 50% (value 1)
```bash
mosquitto_pub -h BROKER -t "TOPIC/box/BOX_CN/CmdVolLimitSpk/set" -m "1"
```

### Set headphone volume limit to 100% (value 3)
```bash
mosquitto_pub -h BROKER -t "TOPIC/box/BOX_CN/CmdVolLimitHdp/set" -m "3"
```

### Stop server-side stream
```bash
mosquitto_pub -h BROKER -t "TOPIC/box/BOX_CN/CmdStop/set" -m "PRESS"
```

### Set LED to dimmed (value 2)
```bash
mosquitto_pub -h BROKER -t "TOPIC/box/BOX_CN/CmdLed/set" -m "2"
```

### Enable slap-to-skip
```bash
mosquitto_pub -h BROKER -t "TOPIC/box/BOX_CN/CmdSlapEnabled/set" -m "TRUE"
```

### Set slap direction
```bash
mosquitto_pub -h BROKER -t "TOPIC/box/BOX_CN/CmdSlapDirection/set" -m "FALSE"
```

### Out-of-range values
```bash
# Volume limit out of range (>3) — tbs_cmd_set_vol_limit_spk returns false
mosquitto_pub -h BROKER -t "TOPIC/box/BOX_CN/CmdVolLimitSpk/set" -m "5"
# LED out of range (>2) — tbs_cmd_set_led returns false
mosquitto_pub -h BROKER -t "TOPIC/box/BOX_CN/CmdLed/set" -m "9"
```

### Expected behavior
- After a valid command, the state topic is immediately updated with the new value.
- The setting is persisted in the overlay config.
- The box applies the setting on its next freshness check.
- Invalid values are silently rejected (logged server-side, no crash).

## Limitations

1. **No real-time volume control**: Only volume *limits* (0–3) can be set, not the actual playback volume (0–16).
2. **No pause/resume**: The Toniebox protocol has no command channel for playback control.
3. **Stream stop only**: CmdStop stops server-side stream delivery; the box may continue playing already-buffered audio.
4. **Deferred application**: All setting changes take effect on the box's next freshness check, not immediately.
