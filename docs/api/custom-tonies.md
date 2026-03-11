# Custom Tonies API

This document describes the custom tonies API endpoints:

- `POST /api/toniesCustomJsonUpsert`
- `POST /api/toniesCustomJsonDelete`
- `POST /api/toniesCustomJsonRename`
- `GET /api/toniesCustomJson`

All requests and responses use UTF-8 JSON unless stated otherwise.

## Data model

Each custom tonie entry is an object with at least:

- `model` (string, required, unique key)
- `series` (string, required)

Common optional fields:

- `title` (string)
- `tracks` (array of strings)
- `audio_id` (array of numeric strings or numbers; stored as strings)
- `hash` (array of 40-char hex strings; stored uppercase)

`audio_id` and `hash` must have the same length when present.

## GET /api/toniesCustomJson

Returns the current full custom tonies list.

### Example

```bash
curl -sS "http://127.0.0.1:80/api/toniesCustomJson"
```

## POST /api/toniesCustomJsonUpsert

Adds new entries or updates existing entries by `model`.

Payload may be:

- one object, or
- an array of objects

### Example: upsert one

```bash
curl -sS -X POST "http://127.0.0.1:80/api/toniesCustomJsonUpsert" \
  -H "Content-Type: application/json" \
  -d '{
    "model":"CUSTOM_001",
    "series":"Custom Series",
    "audio_id":[123456],
    "hash":["0123456789abcdef0123456789abcdef01234567"],
    "title":"My Title",
    "tracks":["A","B"]
  }'
```

### Example: upsert multiple

```bash
curl -sS -X POST "http://127.0.0.1:80/api/toniesCustomJsonUpsert" \
  -H "Content-Type: application/json" \
  -d '[
    {"model":"CUSTOM_001","series":"Series A","audio_id":[111111],"hash":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},
    {"model":"CUSTOM_002","series":"Series B","audio_id":[222222],"hash":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}
  ]'
```

### Success response

- Status: `200`
- Body: `OK`

### Validation errors

- Status: `400`
- Body: plain text error message (for example missing `model`, invalid hash format, duplicate `(audio_id,hash)` pair)

## POST /api/toniesCustomJsonDelete

Removes one or more entries by model name.

### Payload

```json
{
  "models": ["CUSTOM_001", "CUSTOM_002"]
}
```

### Example

```bash
curl -sS -X POST "http://127.0.0.1:80/api/toniesCustomJsonDelete" \
  -H "Content-Type: application/json" \
  -d '{"models":["CUSTOM_001","CUSTOM_002"]}'
```

### Success response

- Status: `200`
- Body: `OK`

## POST /api/toniesCustomJsonRename

Renames one entry key from `fromModel` to `toModel`.

### Payload

```json
{
  "fromModel": "OLD_MODEL",
  "toModel": "NEW_MODEL"
}
```

### Example

```bash
curl -sS -X POST "http://127.0.0.1:80/api/toniesCustomJsonRename" \
  -H "Content-Type: application/json" \
  -d '{"fromModel":"OLD_MODEL","toModel":"NEW_MODEL"}'
```

### Success response

- Status: `200`
- Body: `OK`

### Error responses

- `400`: invalid payload or target model already exists
- `404`: source model not found

## Notes

- Endpoints write to `tonies.custom.json` atomically via temp file + move.
- Successful writes trigger a reload of in-memory tonies data.
- Backup rotation keeps timestamped backup files (`*.bak`) in the config directory.
- Number of backups is configurable via setting `tonie_json.custom_backup_keep` (default `10`).
