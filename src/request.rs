// Copyright (c) 2026 Dylan Westra
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client → backend requests, chiefly the connect request.
//!
//! [`ConnectArgs`] carries everything the backend's openconnect engine needs
//! to bring the tunnel up. Field names are wire facts (pinned by the
//! `wire_format` snapshot test); the accessors and the builder are generated
//! by small local macros.

use std::fmt;

use serde::{Deserialize, Serialize};
use specta::Type;
use zeroize::Zeroize;

use crate::gateway::Gateway;
use crate::os::ClientOs;
use crate::auth::{ConnectAuthRequest, ProbeRequest};
use crate::state::ConnectInfo;

/// Generates `pub fn field(&self) -> Type` accessors that clone the field.
macro_rules! cloned_accessors {
  ($( $(#[$doc:meta])* $field:ident: $ty:ty ),* $(,)?) => {
    $( $(#[$doc])* pub fn $field(&self) -> $ty { self.$field.clone() } )*
  };
}

/// Generates `with_x(value)` builder methods on [`ConnectRequest`] that set
/// the corresponding [`ConnectArgs`] field. Optional fields go through
/// `Into<Option<_>>` so both `Some(x)` and plain values read naturally;
/// scalar fields take their exact type.
macro_rules! arg_setters {
  ($( $setter:ident => $field:ident: into $ty:ty ),* $(,)?) => {
    $( pub fn $setter<T: Into<$ty>>(mut self, value: T) -> Self {
      self.args.$field = value.into();
      self
    } )*
  };
  ($( $setter:ident => $field:ident: $ty:ty ),* $(,)?) => {
    $( pub fn $setter(mut self, value: $ty) -> Self {
      self.args.$field = value;
      self
    } )*
  };
}

/// Tunnel parameters for a connect request. Constructed through
/// [`ConnectRequest`]'s `with_*` builder methods; read by the backend.
///
/// Carries secrets (the gateway auth `cookie`, and `key_password`): its
/// `Debug` redacts them, and dropping it zeroizes them (see the impls below).
#[derive(Deserialize, Serialize, Type, Clone)]
pub struct ConnectArgs {
  cookie: String,
  vpnc_script: Option<String>,

  user_agent: Option<String>,
  os: Option<ClientOs>,
  os_version: Option<String>,
  client_version: Option<String>,

  certificate: Option<String>,
  sslkey: Option<String>,
  key_password: Option<String>,

  hip: bool,
  csd_uid: u32,
  csd_wrapper: Option<String>,

  reconnect_timeout: u32,
  mtu: u32,
  disable_ipv6: bool,
  no_dtls: bool,
  local_hostname: Option<String>,
  force_dpd: u32,
  no_xmlpost: bool,
  #[serde(rename = "allowExtendSession")]
  allow_extend_session: bool,
  /// v4: domains to scope the tunnel's DNS to (systemd-resolved routing
  /// domains). Empty means the backend's default behavior (all DNS through
  /// the tunnel when the gateway sends no split-DNS config). Absent on the
  /// wire when empty, so older backends never see it.
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  dns_domains: Vec<String>,
}

impl ConnectArgs {
  pub fn new(cookie: String) -> Self {
    Self {
      cookie,
      vpnc_script: None,
      user_agent: None,
      os: None,
      os_version: None,
      client_version: None,
      certificate: None,
      sslkey: None,
      key_password: None,
      hip: false,
      csd_uid: 0,
      csd_wrapper: None,
      reconnect_timeout: 300,
      mtu: 0,
      disable_ipv6: false,
      no_dtls: false,
      local_hostname: None,
      force_dpd: 0,
      no_xmlpost: false,
      allow_extend_session: false,
      dns_domains: Vec::new(),
    }
  }

  /// The gateway auth cookie the tunnel authenticates with.
  pub fn cookie(&self) -> &str {
    &self.cookie
  }

  /// The `os` value translated to openconnect's `--os` vocabulary.
  pub fn openconnect_os(&self) -> Option<String> {
    self.os.as_ref().map(|os| os.to_openconnect_os().to_string())
  }

  cloned_accessors! {
    vpnc_script: Option<String>,
    user_agent: Option<String>,
    os: Option<ClientOs>,
    os_version: Option<String>,
    client_version: Option<String>,
    certificate: Option<String>,
    sslkey: Option<String>,
    key_password: Option<String>,
    hip: bool,
    csd_uid: u32,
    csd_wrapper: Option<String>,
    reconnect_timeout: u32,
    mtu: u32,
    disable_ipv6: bool,
    no_dtls: bool,
    local_hostname: Option<String>,
    force_dpd: u32,
    no_xmlpost: bool,
    allow_extend_session: bool,
    dns_domains: Vec<String>,
  }
}

/// Redacts the secrets so a `{:?}` of a request (or anything embedding it,
/// e.g. [`ConnectAuthRequest`]) can't leak the auth cookie or key password.
impl fmt::Debug for ConnectArgs {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ConnectArgs")
      .field("cookie", &"<redacted>")
      .field("key_password", &self.key_password.as_ref().map(|_| "<redacted>"))
      .field("vpnc_script", &self.vpnc_script)
      .field("user_agent", &self.user_agent)
      .field("os", &self.os)
      .field("os_version", &self.os_version)
      .field("client_version", &self.client_version)
      .field("certificate", &self.certificate)
      .field("sslkey", &self.sslkey)
      .field("hip", &self.hip)
      .field("csd_uid", &self.csd_uid)
      .field("csd_wrapper", &self.csd_wrapper)
      .field("reconnect_timeout", &self.reconnect_timeout)
      .field("mtu", &self.mtu)
      .field("disable_ipv6", &self.disable_ipv6)
      .field("no_dtls", &self.no_dtls)
      .field("local_hostname", &self.local_hostname)
      .field("force_dpd", &self.force_dpd)
      .field("no_xmlpost", &self.no_xmlpost)
      .field("allow_extend_session", &self.allow_extend_session)
      .field("dns_domains", &self.dns_domains)
      .finish()
  }
}

/// Best-effort scrub of the secret fields when the args are dropped, so a
/// backend that holds them for the life of a tunnel doesn't leave the cookie /
/// key password lingering in freed memory.
impl Drop for ConnectArgs {
  fn drop(&mut self) {
    self.cookie.zeroize();
    if let Some(key_password) = self.key_password.as_mut() {
      key_password.zeroize();
    }
  }
}

/// The connect request: which gateway to join ([`ConnectInfo`]) plus the
/// tunnel parameters ([`ConnectArgs`]).
#[derive(Debug, Deserialize, Serialize, Type, Clone)]
pub struct ConnectRequest {
  info: ConnectInfo,
  args: ConnectArgs,
}

impl ConnectRequest {
  pub fn new(info: ConnectInfo, cookie: String) -> Self {
    Self {
      args: ConnectArgs::new(cookie),
      info,
    }
  }

  /// The GP client version to emulate towards the server.
  pub fn with_client_version(mut self, client_version: &str) -> Self {
    self.args.client_version = Some(client_version.to_string());
    self
  }

  arg_setters! {
    with_vpnc_script => vpnc_script: into Option<String>,
    with_csd_wrapper => csd_wrapper: into Option<String>,
    with_user_agent => user_agent: into Option<String>,
    with_os => os: into Option<ClientOs>,
    with_os_version => os_version: into Option<String>,
    with_certificate => certificate: into Option<String>,
    with_sslkey => sslkey: into Option<String>,
    with_key_password => key_password: into Option<String>,
    with_local_hostname => local_hostname: into Option<String>,
  }

  arg_setters! {
    with_hip => hip: bool,
    with_csd_uid => csd_uid: u32,
    with_reconnect_timeout => reconnect_timeout: u32,
    with_mtu => mtu: u32,
    with_disable_ipv6 => disable_ipv6: bool,
    with_no_dtls => no_dtls: bool,
    with_force_dpd => force_dpd: u32,
    with_no_xmlpost => no_xmlpost: bool,
    with_allow_extend_session => allow_extend_session: bool,
    with_dns_domains => dns_domains: Vec<String>,
  }

  pub fn gateway(&self) -> &Gateway {
    self.info.gateway()
  }

  pub fn info(&self) -> &ConnectInfo {
    &self.info
  }

  pub fn args(&self) -> &ConnectArgs {
    &self.args
  }
}

/// Ask the backend to tear the tunnel down.
#[derive(Debug, Deserialize, Serialize, Type)]
pub struct DisconnectRequest;

/// Ask the backend to switch its log level (the payload is the level name).
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateLogLevelRequest(pub String);

/// Client → backend request envelope.
#[derive(Debug, Deserialize, Serialize)]
pub enum WsRequest {
  Connect(Box<ConnectRequest>),
  Disconnect(DisconnectRequest),
  UpdateLogLevel(UpdateLogLevelRequest),
  /// v3: run prelogin and report the required auth (see [`crate::auth`]).
  Probe(Box<ProbeRequest>),
  /// v3: authenticate with a captured credential and start the tunnel.
  ConnectAuth(Box<ConnectAuthRequest>),
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;

  #[test]
  fn connect_request_serializes_allow_extend_session() {
    let gateway = Gateway::new("Gateway".to_string(), "vpn.example.com".to_string());
    let info = ConnectInfo::new("portal.example.com".to_string(), gateway.clone(), vec![gateway]);
    let req = ConnectRequest::new(info, "authcookie=AUTH".to_string()).with_allow_extend_session(true);
    let value = serde_json::to_value(req).unwrap();

    assert_eq!(value["args"]["allowExtendSession"], json!(true));
  }

  #[test]
  fn debug_redacts_the_secrets() {
    let gateway = Gateway::new("gw".to_string(), "vpn.example.com".to_string());
    let info = ConnectInfo::new("portal.example.com".to_string(), gateway.clone(), vec![gateway]);
    let req = ConnectRequest::new(info, "authcookie=SUPERSECRET".to_string()).with_key_password("hunter2".to_string());
    let dbg = format!("{:?}", req.args());
    assert!(!dbg.contains("SUPERSECRET"), "cookie leaked in Debug: {dbg}");
    assert!(!dbg.contains("hunter2"), "key_password leaked in Debug: {dbg}");
    assert!(dbg.contains("<redacted>"));
    // Serialization must still carry the real value (Debug redaction only).
    let json = serde_json::to_value(req.args()).unwrap();
    assert_eq!(json["cookie"], "authcookie=SUPERSECRET");
  }

  #[test]
  fn dns_domains_absent_on_the_wire_defaults_to_empty() {
    // A v3 peer never sends the field; it must deserialize to an empty list.
    // The field is also skipped when empty, so a v4 sender with no domains
    // produces byte-identical JSON to a v3 sender.
    let gateway = Gateway::new("gw".to_string(), "vpn.example.com".to_string());
    let info = ConnectInfo::new("portal.example.com".to_string(), gateway.clone(), vec![gateway]);
    let value = serde_json::to_value(ConnectRequest::new(info, "authcookie=AUTH".to_string())).unwrap();

    assert!(value["args"].get("dns_domains").is_none());
    let req: ConnectRequest = serde_json::from_value(value).unwrap();
    assert!(req.args().dns_domains().is_empty());
  }

  #[test]
  fn dns_domains_roundtrip() {
    let gateway = Gateway::new("gw".to_string(), "vpn.example.com".to_string());
    let info = ConnectInfo::new("portal.example.com".to_string(), gateway.clone(), vec![gateway]);
    let req = ConnectRequest::new(info, "authcookie=AUTH".to_string())
      .with_dns_domains(vec!["corp.acme.example".to_string()]);
    let value = serde_json::to_value(&req).unwrap();

    assert_eq!(value["args"]["dns_domains"], json!(["corp.acme.example"]));
    let back: ConnectRequest = serde_json::from_value(value).unwrap();
    assert_eq!(back.args().dns_domains(), vec!["corp.acme.example".to_string()]);
  }

  #[test]
  fn builder_accepts_plain_and_option_values() {
    let gateway = Gateway::new("gw".to_string(), "vpn.example.com".to_string());
    let info = ConnectInfo::new("portal.example.com".to_string(), gateway.clone(), vec![gateway]);
    let req = ConnectRequest::new(info, "authcookie=AUTH".to_string())
      .with_mtu(1400)
      .with_vpnc_script(Some("/usr/libexec/vpnc-script".to_string()))
      .with_os(ClientOs::Linux);

    assert_eq!(req.args().mtu(), 1400);
    assert_eq!(req.args().vpnc_script().as_deref(), Some("/usr/libexec/vpnc-script"));
    assert_eq!(req.args().openconnect_os().as_deref(), Some("linux"));
  }
}
