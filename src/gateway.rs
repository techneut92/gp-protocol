// Copyright (c) 2026 Dylan Westra
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A GlobalProtect gateway as presented in the portal's configuration.
//!
//! Field names mirror the portal's gateway-list response (protocol facts):
//! each gateway has a display name, an address, a priority, and optional
//! per-region priority rules used for sorting.

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use specta::Type;

/// A region-based priority override from the portal's gateway list.
#[derive(Debug, Serialize, Deserialize, Type, Clone)]
pub struct PriorityRule {
  pub name: String,
  pub priority: u32,
}

/// One gateway entry from the portal configuration.
#[derive(Debug, Serialize, Deserialize, Type, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Gateway {
  pub name: String,
  pub address: String,
  pub priority: u32,
  pub priority_rules: Vec<PriorityRule>,
}

impl Gateway {
  /// A gateway known only by name and address (no priority data) — the shape
  /// used when connecting directly to a gateway without a portal config.
  pub fn new(name: String, address: String) -> Self {
    Self {
      name,
      address,
      priority: 0,
      priority_rules: Vec::new(),
    }
  }

  pub fn name(&self) -> &str {
    &self.name
  }

  /// The address to actually connect to.
  pub fn server(&self) -> &str {
    &self.address
  }
}

impl Display for Gateway {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{} ({})", self.name, self.address)
  }
}
