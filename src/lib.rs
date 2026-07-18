// Copyright (c) 2026 Dylan Westra
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `gp-protocol` — the versioned wire contract between a GP client GUI and its
//! privileged backend (`gpservice`).
//!
//! This crate is the single source of truth for every message the two sides
//! exchange, whether the transport is the loopback WebSocket or the D-Bus
//! system service. Both ends depend on this one crate, which makes silent
//! drift impossible by construction.
//!
//! It is deliberately dependency-light (serde types plus a couple of
//! formatting helpers — no HTTP stack, no TLS, no PKCS#11), so a GUI can pull
//! it in without inheriting the backend's world.
//!
//! ## Wire versioning
//! [`PROTOCOL_MIN`]`..=`[`PROTOCOL_MAX`] is the range of wire versions a build
//! can speak. The two sides exchange their ranges at handshake and settle on
//! the highest common version; disjoint ranges surface a clear "update the
//! GUI / update the backend" message instead of a cryptic parse failure. The
//! wire version is **independent** of any package release version.

/// Oldest wire-protocol version this build still understands. Raise only when
/// deliberately dropping compatibility with an old peer.
///
/// v2 raised MIN as well: `VpnState::Reconnecting` is emitted unconditionally
/// (there is no speak-down path that could hide it from a v1 peer), so
/// claiming v1 support would feed old GUIs a state they cannot parse. GUI and
/// backend ship in lockstep in every distribution channel, so a hard break
/// here simply shows the designed "update" prompt.
pub const PROTOCOL_MIN: u32 = 2;

/// Newest wire-protocol version this build speaks. Bump on any message-type
/// change; the handshake negotiates downward within `MIN..=MAX`.
///
/// v2: added `VpnState::Reconnecting(ConnectedInfo)`.
/// v3: added the auth handoff — `WsRequest::{Probe,ConnectAuth}` and
/// `WsEvent::ProbeResult` (see [`auth`]). MIN stays 2: the additions are
/// backward-compatible request/response types an older backend simply never
/// receives, so a v2 peer keeps working.
/// v4: the first post-v3 bump — prod ships v3, so everything added on the
/// (unreleased) feature branches is bundled into a single new version rather
/// than one bump each: `ConnectArgs::dns_domains` (scoped tunnel DNS),
/// `as_gateway` on `ProbeRequest`/`ConnectAuthRequest` (portal vs direct
/// gateway), and `VpnState::MfaChallenge` + the `submit_mfa`/`resend_mfa`
/// transport methods (interactive MFA). MIN stays 2: all are serde-default /
/// handshake-gated, so a v3 peer keeps working. (The interim crates 1.2.0/1.3.0/
/// 1.4.0 that split these across v4/v5/v6 were never released and are yanked.)
pub const PROTOCOL_MAX: u32 = 4;

/// The current protocol version — alias for [`PROTOCOL_MAX`].
pub const PROTOCOL_VERSION: u32 = PROTOCOL_MAX;

/// serde default for peers that predate the handshake fields: they speak the
/// original wire format, i.e. protocol 1.
pub(crate) fn protocol_baseline() -> u32 {
  1
}

pub mod auth;
pub mod env;
pub mod event;
pub mod gateway;
pub mod os;
pub mod request;
pub mod session;
pub mod state;

pub use auth::{AuthCredential, ConnectAuthRequest, ProbeReply, ProbeRequest};
pub use env::VpnEnv;
pub use event::WsEvent;
pub use gateway::{Gateway, PriorityRule};
pub use os::ClientOs;
pub use request::{ConnectArgs, ConnectRequest, DisconnectRequest, UpdateLogLevelRequest, WsRequest};
pub use session::{format_duration_secs, SessionInfo, SessionWarning};
pub use state::{ConnectInfo, ConnectedInfo, MfaChallengeInfo, VpnState};
