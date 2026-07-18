// Copyright (c) 2026 Dylan Westra
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authentication handoff (wire-protocol v3).
//!
//! The GUI never talks HTTP to the GlobalProtect service itself: it asks the
//! backend to *probe* a server (prelogin — including the mTLS client-cert
//! step, which the backend performs with its PKCS#11 stack), shows the right
//! credential UI, and then hands the credential back. The backend performs
//! the gateway login and starts the tunnel in one go; progress arrives as the
//! usual [`crate::VpnState`] events.

use serde::{Deserialize, Serialize};
use specta::Type;

use crate::os::ClientOs;
use crate::request::ConnectArgs;

/// serde default for `as_gateway`: absent on the wire (a pre-v5 peer) means
/// the original direct-gateway behavior, so it must default to `true`.
fn default_as_gateway() -> bool {
  true
}

/// Ask the backend to run prelogin against a portal/gateway and report which
/// kind of authentication the server wants.
#[derive(Debug, Serialize, Deserialize, Type, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRequest {
  /// Server to probe.
  pub server: String,
  /// v5: whether `server` is a gateway (direct-gateway flow, the default) or a
  /// portal (portal prelogin, then a gateway list). Absent on the wire ⇒ true,
  /// so pre-v5 peers keep the gateway behavior.
  #[serde(default = "default_as_gateway")]
  pub as_gateway: bool,
  /// Client certificate for the prelogin mTLS: a `pkcs11:` URI (with
  /// `?pin-value=…`) or a path to a PEM/PKCS#12 file readable by the backend.
  pub certificate: Option<String>,
  pub sslkey: Option<String>,
  pub key_password: Option<String>,
  pub ignore_tls_errors: bool,
  pub os: Option<ClientOs>,
  pub os_version: Option<String>,
  pub user_agent: Option<String>,
}

/// What the server's prelogin asked for.
#[derive(Debug, Serialize, Deserialize, Type, Clone)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ProbeReply {
  /// SAML SSO: the GUI must run the request through a webview/browser and
  /// return the resulting cookie as [`AuthCredential::Saml`].
  Saml { saml_request: String, supports_browser: bool },
  /// Username/password form (labels come from the server).
  Standard { username_label: String, password_label: String },
  /// Prelogin failed. `cert_needed` hints that the server demanded a client
  /// certificate the request didn't (successfully) present.
  Error { message: String, cert_needed: bool },
}

/// The credential obtained by the GUI after a probe.
#[derive(Debug, Serialize, Deserialize, Type, Clone)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum AuthCredential {
  /// Plain username/password (the `Standard` prelogin answer).
  Password { username: String, password: String },
  /// SAML result captured by the GUI's webview/browser flow.
  Saml {
    username: String,
    prelogin_cookie: Option<String>,
    portal_userauthcookie: Option<String>,
  },
  /// Cert-only servers: no interactive credential beyond the client cert that
  /// already authenticated the prelogin. The backend logs in with the same
  /// certificate identity.
  CertOnly,
}

/// Authenticate against the gateway and bring the tunnel up, in one request.
/// The backend performs the gateway login (it already owns the HTTP + PKCS#11
/// stack), fills the auth cookie into `args`, and starts the tunnel; state
/// flows back as [`crate::VpnState`] events. `args.cookie` is ignored.
#[derive(Debug, Serialize, Deserialize, Type, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConnectAuthRequest {
  pub server: String,
  pub credential: AuthCredential,
  /// v5: whether `server` is a gateway (default) or a portal. When false the
  /// backend runs the portal flow — retrieve the gateway list with the
  /// credential, pick a gateway, and log in with the portal cookie. Absent on
  /// the wire ⇒ true (pre-v5 peers keep the gateway behavior).
  #[serde(default = "default_as_gateway")]
  pub as_gateway: bool,
  /// Prelogin/mTLS context — the same fields the probe used.
  pub certificate: Option<String>,
  pub sslkey: Option<String>,
  pub key_password: Option<String>,
  pub ignore_tls_errors: bool,
  pub os: Option<ClientOs>,
  pub os_version: Option<String>,
  pub user_agent: Option<String>,
  /// Tunnel options. `cookie` is replaced by the backend after login.
  pub args: ConnectArgs,
}
