# Box HTTPS certificate selection

The box-facing HTTPS port selects its server identity from the SNI hostname
parsed by Cyclone:

- no SNI hostname receives the TB1 certificate;
- an SNI hostname receives the TB2 certificate.

This behaviour is always active on the box HTTPS listener. It does not apply to
the Web HTTPS listener or MQTT, and it has no setting or box-generation side
effect. Cyclone parses the ClientHello and invokes its stock ALPN callback before
certificate selection. TeddyCloud uses the hostname exposed by Cyclone to load
exactly one certificate. No custom ClientHello parser or Cyclone modification is
required.
