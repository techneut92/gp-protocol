// Copyright (c) 2026 Dylan Westra
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The backend's greeting: environment + handshake data pushed to a client
//! the moment it connects.

use serde::{Deserialize, Serialize};

use crate::state::VpnState;

/// First message a client receives after connecting: the backend's protocol
/// range, current VPN state, and the paths the client may need to assemble a
/// connect request.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpnEnv {
  /// Wire-protocol range the backend speaks (see [`crate::PROTOCOL_MIN`] /
  /// [`crate::PROTOCOL_MAX`]). Absent on backends that predate the handshake,
  /// in which case both default to the baseline `1`.
  #[serde(default = "crate::protocol_baseline")]
  pub protocol_min: u32,
  #[serde(default = "crate::protocol_baseline")]
  pub protocol_max: u32,

  /// The VPN connection state at the time the client attached.
  pub vpn_state: VpnState,

  /// Default vpnc-script path on the backend host, if one was found.
  pub vpnc_script: Option<String>,

  /// Default CSD (HIP) wrapper script path, if one was found.
  pub csd_wrapper: Option<String>,

  /// Path to the `gpauth` executable, for clients that delegate SAML to it.
  pub auth_executable: String,
}
