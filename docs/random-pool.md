# Random pool

A tag plays a random pool when its `content.json` has a `source` that is a `.tap`
file of type `random`. Each time the box requests the content, teddyCloud picks one
TAF of the pool at random and serves it as it is, without encoding.

```json
{
  "type": "random",
  "name": "Bedtime stories",
  "directory": "lib://stories/",
  "files": [
    { "filepath": "lib://other/one-more.taf" }
  ]
}
```

- `directory`: every TAF directly in this folder belongs to the pool. Subfolders are
  not searched, and other files (covers, notes) are never picked. A TAF added to the
  folder joins the pool without editing the `.tap`.
- `files`: TAFs anywhere else, as a list. A file both in the folder and in the list
  counts once. The list holds at most 99 entries.

Either may be left out. Paths take the same prefixes as a `source` (`lib://`,
`content://`, ...). Files outside the data directory are never picked.

## What the box gets

- teddyCloud forces `live` and `nocloud` on for the tag. `live` makes the
  freshness check mark the tag, so the box drops its copy and fetches a new pick
  the next time the tag is placed, and it stops the box from resuming a position
  inside a TAF it will not get again. `nocloud` keeps the tonie's cloud content
  out, as for a stream.
- The box runs the freshness check when it wakes up or reconnects, not each time
  a tag is placed. Placing the tag again while the box is awake plays the copy it
  already has; the next pick comes after the box has slept. Tested with an ESP32
  box (firmware 5.237.0).
- A TAF still being written (its file shorter than its header says) is never
  picked. A pool with no TAF to pick answers 404.
- A resumed download (`Range` with the TAF's audio id in `If-Range`) gets the same
  TAF again. If that TAF has left the pool, or two TAFs of the pool share its audio
  id, the box gets a new pick as a whole download. So does a range request without
  `If-Range`, such as a seek in the web player.
- For V3 content (TB2), the content meta announces one pick; its chapter names carry
  the first bytes of that TAF's SHA1, so every chapter request gets the same file,
  even when another TAF of the pool has the same audio id. A chapter of a TAF that
  has left the pool answers 404.
- The freshness check marks the tag at every check and leaves its `tonie_model` as
  it is, rather than taking the model of whatever TAF the box got last.

Everywhere else (web UI, API) the tag shows the `.tap` file itself.
