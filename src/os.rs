// Copyright (c) 2026 Dylan Westra
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The operating system a client reports to the GlobalProtect portal/gateway.
//!
//! The string values here are **protocol constants** observed from the
//! GlobalProtect service: the portal endpoints expect `Linux` / `Windows` /
//! `Mac` in the `clientos` parameter, while the openconnect engine's
//! `--os` vocabulary is `linux` / `win` / `mac-intel`.

use serde::{Deserialize, Serialize};
use specta::Type;

/// Client OS reported to the portal/gateway and carried in connect requests.
#[derive(Debug, Serialize, Deserialize, Clone, Type, Default)]
pub enum ClientOs {
  #[cfg_attr(not(target_os = "macos"), default)]
  Linux,
  Windows,
  #[cfg_attr(target_os = "macos", default)]
  Mac,
}

impl ClientOs {
  /// The portal-side `clientos` value (a GlobalProtect protocol constant).
  pub fn as_str(&self) -> &str {
    match self {
      Self::Linux => "Linux",
      Self::Windows => "Windows",
      Self::Mac => "Mac",
    }
  }

  /// The equivalent value in openconnect's `--os` vocabulary.
  pub fn to_openconnect_os(&self) -> &str {
    match self {
      Self::Linux => "linux",
      Self::Windows => "win",
      Self::Mac => "mac-intel",
    }
  }
}

impl From<&str> for ClientOs {
  /// Parses the portal-side name; anything unrecognised falls back to Linux
  /// (the only platform the client suite actually ships on today).
  fn from(name: &str) -> Self {
    match name {
      "Windows" => Self::Windows,
      "Mac" => Self::Mac,
      _ => Self::Linux,
    }
  }
}
