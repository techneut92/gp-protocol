// Copyright (c) 2026 Dylan Westra
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unsolicited messages the backend pushes to connected clients.

use serde::{Deserialize, Serialize};

use crate::auth::ProbeReply;
use crate::env::VpnEnv;
use crate::state::VpnState;

/// Backend → client push messages.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum WsEvent {
  /// The connect-time greeting (environment + handshake). See [`VpnEnv`].
  VpnEnv(VpnEnv),
  /// The VPN state changed.
  VpnState(VpnState),
  /// Another GUI instance took over; this client should yield.
  ActiveGui,
  /// The backend asks the client to re-establish the previous connection
  /// (e.g. after a SIGUSR2-style external trigger).
  ResumeConnection,
  /// v3: the result of a [`WsRequest::Probe`](crate::request::WsRequest).
  ProbeResult(ProbeReply),
}
