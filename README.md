# gp-protocol

The versioned wire protocol between the [GP Client](https://github.com/techneut92/GlobalProtect-openconnect-dw)
GUI and its privileged backend (`gpservice`), for GlobalProtect-compatible VPN
setups.

This crate is the single source of truth for every message the two sides
exchange (loopback WebSocket or D-Bus system service). Both ends depend on it,
so the wire format cannot drift silently — a `wire_format` snapshot test pins
the serialized shape, and a negotiated protocol version (`PROTOCOL_MIN..=MAX`)
turns real incompatibilities into a clear "update the GUI / backend" message.

It is deliberately dependency-light (serde types plus formatting helpers) so a
GUI can depend on it without inheriting the backend's HTTP/TLS/PKCS#11 stack.

## Scope

- `WsRequest` / `WsEvent` — the request/push envelopes
- `ConnectRequest` / `ConnectArgs` — everything a tunnel needs to come up
- `VpnState` / `ConnectInfo` / `ConnectedInfo` — the connection state machine
- `SessionInfo` / `SessionWarning` — session lifetime metadata
- `Gateway`, `ClientOs`, `VpnEnv` — supporting wire types

This crate is primarily useful to the GP Client project itself; it is published
so the protocol contract is public, versioned, and reusable.

## Provenance & license

Authored by Dylan Westra. Wire field names and value vocabularies are protocol
facts (the observed GlobalProtect service behavior and the GP Client IPC
contract); the code expressing them here was written for this crate.

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option. Copyright © 2026 Dylan Westra.
