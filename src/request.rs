// Copyright (c) 2026 Dylan Westra
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client → backend requests, chiefly the connect request.
//!
//! [`ConnectArgs`] carries everything the backend's openconnect engine needs
//! to bring the tunnel up. Field names are wire facts (pinned by the
//! `wire_format` snapshot test); the accessors and the builder are generated
//! by small local macros.

use serde::{Deserialize, Serialize};
use specta::Type;

use crate::gateway::Gateway;
use crate::os::ClientOs;
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
#[derive(Debug, Deserialize, Serialize, Type, Clone)]
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
