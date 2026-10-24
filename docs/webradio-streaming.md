# Web radio streaming

A tag becomes a stream when its `content.json` carries a `source` that is a URL
(anything containing `://`) or an existing file that is neither a TAF nor a TAP.
TeddyCloud then forces `live` and `nocloud` on for that tag.

## How a stream is served

A content request for such a tag starts two things that run concurrently:

- `ffmpeg_stream_task` pipes the source through ffmpeg to raw PCM (48 kHz,
  stereo, s16le), encodes it to Opus (60 ms frames, `encode.bitrate`) and appends
  4096 byte TAF blocks to `<content>.stream`. `skip_seconds` from the
  `content.json` is passed to ffmpeg as `-ss`.
- The HTTP connection thread serves that same file to the box while it is still
  being written, and waits whenever it catches up with the encoder.

The response announces `encode.stream_max_size` as its content length instead of
the current file size, so the box keeps downloading as the file grows. When the
box reports playback stop over RTNL, `stream_ctx.active` is cleared, ffmpeg is
stopped and the file is closed. One stream can be active per box.

## Why playback is not live

The box downloads content to its SD card and plays it from the beginning, and
teddyCloud has no way to point it at the live edge of a running stream. Two
consequences follow, and most of the tuning below is about them.

**Delivery runs at 1x.** Icecast-style servers send several seconds from their
buffer immediately on connect; after that burst, audio arrives no faster than it
is broadcast. Whatever the box wants buffered beyond what is already in the file
therefore costs the same amount of real time.

**A returning tag replays its cache.** The box still holds the prefix it
downloaded earlier, plays it from the start and resumes the download with a range
request. `encode.ffmpeg_stream_restart` exists to prevent that: it answers the
range request with the real file size instead of `stream_max_size`, so the box
discards its cache and requests the stream again from offset 0.

## Settings

All of these live under `encode` and are expert level.

| Setting | Default | Effect |
|---|---|---|
| `bitrate` | `96` | Opus bitrate in kb/s. Higher means larger TAF blocks per second of audio. |
| `ffmpeg_sweep_startup_buffer` | `true` | Discard everything decoded during the first `ffmpeg_sweep_delay_ms` instead of encoding it, so playback starts near the live edge. |
| `ffmpeg_sweep_delay_ms` | `2000` | How long to discard for. |
| `ffmpeg_stream_buffer_ms` | `2000` | How long to keep encoding before the response starts, so the box has something to read. |
| `ffmpeg_stream_restart` | `false` | Force a returning box to start over instead of replaying its cached prefix. |
| `stream_max_size` | `251658239` | Announced content length, about 240 MB or 6 h. Must not be a multiple of 4096. |

Sweeping is worth understanding before changing it, because it costs twice.
Besides the explicit `ffmpeg_sweep_delay_ms` wait, discarding the burst leaves the
file holding only `ffmpeg_stream_buffer_ms` of audio, and everything the box
needs on top of that arrives at 1x. Turning sweeping off puts the whole burst in
the file within a fraction of a second, so the box can fill its buffer at network
speed and `ffmpeg_stream_buffer_ms` can be lowered as well. The price is that
playback then stays behind the live signal by the length of the burst, for as
long as the stream runs. Whether that matters depends on the station.

`stream_max_size` is what the box may reserve per streaming tag, so several
streaming tags can occupy several times that much on the SD card. Once the
announced length is reached the box stops and the tag has to be placed again.

## Startup latency

Most of the time between placing the tag and hearing audio is the box waking up —
WiFi association, DHCP, TLS — and cannot be tuned from the server. TeddyCloud's
own share is `ffmpeg_sweep_delay_ms` plus `ffmpeg_stream_buffer_ms`, and after
that whatever the box still wants buffered beyond what the file already holds.

A box that holds a cached prefix sends a range request first. With
`ffmpeg_stream_restart` enabled that request only sends it back to offset 0, so a
second round trip happens before playback starts.
