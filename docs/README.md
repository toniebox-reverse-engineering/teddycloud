# Documentation

- [Architecture](./architecture.md) — how the server is put together: startup,
  HTTP(S) listeners and routing, the Tonie/TAF content model, the Toniebox
  protocol, MQTT/Home Assistant, settings, and directory layout.
- [Box HTTPS certificate selection](./box-https-sni.md) — how the box-facing
  HTTPS listener picks a TB1 vs. TB2 certificate.
- [Web radio streaming](./webradio-streaming.md) — how a stream tag is served
  and its tuning settings.
- [Custom Tonies API](./api/custom-tonies.md) — the `/api/toniesCustomJson*`
  endpoints.

For end-user setup instructions, see the
[project documentation site](https://toniebox-reverse-engineering.github.io/docs/tools/teddycloud/)
linked from the main [README](../README.md).
