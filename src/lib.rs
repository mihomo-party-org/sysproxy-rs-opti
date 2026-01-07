//! Get/Set system proxy. Supports Windows, macOS and linux (via gsettings).

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

// #[cfg(feature = "utils")]
pub mod utils;

#[cfg(feature = "guard")]
pub mod guard;

#[cfg(feature = "guard")]
pub use guard::{GuardMonitor, GuardType};

#[cfg(feature = "napi")]
#[macro_use]
extern crate napi_derive;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Sysproxy {
    pub host: String,
    pub bypass: String,
    pub port: u16,
    pub enable: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Autoproxy {
    pub url: String,
    pub enable: bool,
}

#[cfg(feature = "napi")]
#[napi(object)]
pub struct SysproxyInfo {
    pub enable: bool,
    pub host: String,
    pub port: u16,
    pub bypass: String,
}

#[cfg(feature = "napi")]
#[napi(object)]
pub struct AutoproxyInfo {
    pub enable: bool,
    pub url: String,
}

#[cfg(feature = "napi")]
impl From<Sysproxy> for SysproxyInfo {
    fn from(p: Sysproxy) -> Self {
        Self {
            enable: p.enable,
            host: p.host,
            port: p.port,
            bypass: p.bypass,
        }
    }
}

#[cfg(feature = "napi")]
impl From<Autoproxy> for AutoproxyInfo {
    fn from(p: Autoproxy) -> Self {
        Self {
            enable: p.enable,
            url: p.url,
        }
    }
}

#[cfg(feature = "napi")]
#[napi]
pub fn trigger_manual_proxy(
    enable: bool,
    host: String,
    port: u16,
    bypass: String,
) -> napi::Result<()> {
    let proxy = Sysproxy {
        enable,
        host,
        port,
        bypass,
    };
    proxy
        .set_system_proxy()
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[cfg(feature = "napi")]
#[napi]
pub fn trigger_auto_proxy(enable: bool, url: String) -> napi::Result<()> {
    let proxy = Autoproxy { enable, url };
    proxy
        .set_auto_proxy()
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[cfg(feature = "napi")]
#[napi]
pub fn get_system_proxy() -> napi::Result<SysproxyInfo> {
    Sysproxy::get_system_proxy()
        .map(Into::into)
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[cfg(feature = "napi")]
#[napi]
pub fn get_auto_proxy() -> napi::Result<AutoproxyInfo> {
    Autoproxy::get_auto_proxy()
        .map(Into::into)
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to parse string `{0}`")]
    ParseStr(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("failed to get default network interface")]
    NetworkInterface,

    #[error("failed to set proxy for this environment")]
    NotSupport,

    #[error("admin privileges required to modify system proxy")]
    RequiresAdminPrivileges,

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Xdg(#[from] xdg::BaseDirectoriesError),

    #[cfg(target_os = "windows")]
    #[error("system call failed")]
    SystemCall(#[from] windows::Win32Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Sysproxy {
    pub const fn is_support() -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
        ))
    }
}

impl Autoproxy {
    pub const fn is_support() -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
        ))
    }
}
