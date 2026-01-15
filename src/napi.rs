use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::{Autoproxy, Sysproxy};

#[napi(object)]
pub struct JsSysproxy {
    pub host: String,
    pub port: u32,
    pub bypass: String,
    pub enable: bool,
}

#[napi(object)]
pub struct JsAutoproxy {
    pub url: String,
    pub enable: bool,
}

impl From<Sysproxy> for JsSysproxy {
    fn from(p: Sysproxy) -> Self {
        Self {
            host: p.host,
            port: p.port as u32,
            bypass: p.bypass,
            enable: p.enable,
        }
    }
}

impl From<JsSysproxy> for Sysproxy {
    fn from(p: JsSysproxy) -> Self {
        Self {
            host: p.host,
            port: p.port as u16,
            bypass: p.bypass,
            enable: p.enable,
        }
    }
}

impl From<Autoproxy> for JsAutoproxy {
    fn from(p: Autoproxy) -> Self {
        Self {
            url: p.url,
            enable: p.enable,
        }
    }
}

impl From<JsAutoproxy> for Autoproxy {
    fn from(p: JsAutoproxy) -> Self {
        Self {
            url: p.url,
            enable: p.enable,
        }
    }
}

#[napi]
pub fn get_system_proxy() -> Result<JsSysproxy> {
    Sysproxy::get_system_proxy()
        .map(JsSysproxy::from)
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn set_system_proxy(proxy: JsSysproxy) -> Result<()> {
    let p: Sysproxy = proxy.into();
    p.set_system_proxy()
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn get_auto_proxy() -> Result<JsAutoproxy> {
    Autoproxy::get_auto_proxy()
        .map(JsAutoproxy::from)
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn set_auto_proxy(proxy: JsAutoproxy) -> Result<()> {
    let p: Autoproxy = proxy.into();
    p.set_auto_proxy()
        .map_err(|e| Error::from_reason(e.to_string()))
}

// Compatibility API for clash-party
#[napi]
pub fn trigger_manual_proxy(enable: bool, host: String, port: u32, bypass: String) -> Result<()> {
    let p = Sysproxy {
        enable,
        host,
        port: port as u16,
        bypass,
    };
    p.set_system_proxy()
        .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn trigger_auto_proxy(enable: bool, url: String) -> Result<()> {
    let p = Autoproxy { enable, url };
    p.set_auto_proxy()
        .map_err(|e| Error::from_reason(e.to_string()))
}
