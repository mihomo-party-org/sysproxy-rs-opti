use crate::{Autoproxy, Error, Result, Sysproxy};
use log::debug;
use std::{
    borrow::Cow,
    process::{Command, Stdio},
    str::from_utf8,
};
use system_configuration::{
    core_foundation::dictionary::CFDictionary, dynamic_store::SCDynamicStore,
    preferences::SCPreferences,
};
use system_configuration::{
    core_foundation::{array::CFArray, base::TCFType},
    network_configuration::SCNetworkService,
    sys::network_configuration::{
        SCNetworkProtocolGetConfiguration, SCNetworkServiceCopy, SCNetworkServiceCopyProtocol,
    },
};
use system_configuration::{
    core_foundation::{
        base::{CFRelease, CFType, ItemRef},
        number::CFNumber,
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};

#[derive(Debug)]
enum ProxyType {
    Http,
    Https,
    Socks,
}

impl ProxyType {
    #[inline]
    const fn as_enable(&self) -> &'static str {
        match self {
            Self::Http => "HTTPEnable",
            Self::Https => "HTTPSEnable",
            Self::Socks => "SOCKSEnable",
        }
    }
    #[inline]
    const fn as_host(&self) -> &'static str {
        match self {
            Self::Http => "HTTPProxy",
            Self::Https => "HTTPSProxy",
            Self::Socks => "SOCKSProxy",
        }
    }
    #[inline]
    const fn as_port(&self) -> &'static str {
        match self {
            Self::Http => "HTTPPort",
            Self::Https => "HTTPSPort",
            Self::Socks => "SOCKSPort",
        }
    }
}

impl ProxyType {
    #[inline]
    const fn as_set_str(&self) -> &'static str {
        match self {
            Self::Http => "-setwebproxy",
            Self::Https => "-setsecurewebproxy",
            Self::Socks => "-setsocksfirewallproxy",
        }
    }
    #[inline]
    const fn as_state_cmd(&self) -> &'static str {
        match self {
            Self::Http => "-setwebproxystate",
            Self::Https => "-setsecurewebproxystate",
            Self::Socks => "-setsocksfirewallproxystate",
        }
    }
}

impl Sysproxy {
    #[inline]
    pub fn get_system_proxy() -> Result<Sysproxy> {
        let service = get_active_network_service()?;
        let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
        let service_id =
            get_service_id_by_display_name(&scp, &service).ok_or(Error::NetworkInterface)?;
        let proxies_dict = get_proxies_by_service_uuid(&scp, &service_id)?;

        let mut socks = Sysproxy::get_socks(&service, Some(&proxies_dict))?;
        debug!("Getting SOCKS proxy: {:?}", socks);

        let http = Sysproxy::get_http(&service, Some(&proxies_dict))?;
        debug!("Getting HTTP proxy: {:?}", http);

        let https = Sysproxy::get_https(&service, Some(&proxies_dict))?;
        debug!("Getting HTTPS proxy: {:?}", https);

        let bypass = Sysproxy::get_bypass(&service, Some(&proxies_dict))?;
        debug!("Getting bypass domains: {:?}", bypass);

        socks.bypass = bypass;

        if !socks.enable {
            if http.enable {
                socks.enable = true;
                socks.host = http.host;
                socks.port = http.port;
            }

            if https.enable {
                socks.enable = true;
                socks.host = https.host;
                socks.port = https.port;
            }
        }

        Ok(socks)
    }

    #[inline]
    pub fn set_system_proxy(&self) -> Result<()> {
        let service = get_active_network_service()?;
        let service = service.to_string();
        let service = service.as_str();

        debug!("Use network service: {}", service);

        debug!("Setting SOCKS proxy");
        self.set_socks(service)?;

        debug!("Setting HTTP proxy");
        self.set_https(service)?;

        debug!("Setting HTTPS proxy");
        self.set_http(service)?;

        debug!("Setting bypass domains");
        self.set_bypass(service)?;
        Ok(())
    }

    #[inline]
    pub fn get_http(
        service: &CFString,
        cfd: Option<&CFDictionary<CFString, CFType>>,
    ) -> Result<Sysproxy> {
        let cfd = match cfd {
            Some(s) => s,
            None => &get_proxies_dict_from_service_uuid(service)?,
        };
        parse_proxies_from_dict(cfd, ProxyType::Http)
    }

    #[inline]
    pub fn get_https(
        service: &CFString,
        cfd: Option<&CFDictionary<CFString, CFType>>,
    ) -> Result<Sysproxy> {
        let cfd = match cfd {
            Some(s) => s,
            None => &get_proxies_dict_from_service_uuid(service)?,
        };
        parse_proxies_from_dict(cfd, ProxyType::Https)
    }

    #[inline]
    pub fn get_socks(
        service: &CFString,
        cfd: Option<&CFDictionary<CFString, CFType>>,
    ) -> Result<Sysproxy> {
        let cfd = match cfd {
            Some(s) => s,
            None => &get_proxies_dict_from_service_uuid(service)?,
        };
        parse_proxies_from_dict(cfd, ProxyType::Socks)
    }

    #[inline]
    pub fn get_bypass(
        service: &CFString,
        cfd: Option<&CFDictionary<CFString, CFType>>,
    ) -> Result<String> {
        let cfd = match cfd {
            Some(s) => s,
            None => &get_proxies_dict_from_service_uuid(service)?,
        };
        let bypass_list = parse_bypass_from_dict(cfd)?;
        Ok(bypass_list.join(","))
    }

    #[inline]
    pub fn set_http(&self, service: &str) -> Result<()> {
        set_proxy(self, ProxyType::Http, service)
    }

    #[inline]
    pub fn set_https(&self, service: &str) -> Result<()> {
        set_proxy(self, ProxyType::Https, service)
    }

    #[inline]
    pub fn set_socks(&self, service: &str) -> Result<()> {
        set_proxy(self, ProxyType::Socks, service)
    }

    #[inline]
    pub fn set_bypass(&self, service: &str) -> Result<()> {
        set_bypass(self, service)
    }

    #[inline]
    pub fn has_permission() -> bool {
        let check = || -> Result<()> {
            let service = get_active_network_service()?.to_string();
            run_networksetup(&["-setwebproxystate", &service, "off"])?;
            Ok(())
        };

        match check() {
            Ok(_) => true,
            Err(e) => {
                debug!("Permission check failed: {:?}", e);
                false
            }
        }
    }
}

impl Autoproxy {
    #[inline]
    pub fn get_auto_proxy() -> Result<Autoproxy> {
        let service = get_active_network_service_uuid()?;
        let store = SCDynamicStoreBuilder::new("sysproxy-rs")
            .build()
            .ok_or(Error::SCDynamicStore)?;
        get_autoproxies_by_service_uuid(&store, &service)
    }

    #[inline]
    pub fn set_auto_proxy(&self) -> Result<()> {
        let service = get_active_network_service()?.to_string();
        let service = service.as_str();
        let enable = if self.enable { "on" } else { "off" };
        let url = if self.url.is_empty() {
            "\"\""
        } else {
            &self.url
        };
        run_networksetup(&["-setautoproxyurl", service, url])?;
        run_networksetup(&["-setautoproxystate", service, enable])?;

        Ok(())
    }
}

#[inline]
fn run_networksetup<'a>(args: &[&str]) -> Result<Cow<'a, str>> {
    let mut command = Command::new("networksetup");
    let outoput = command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = outoput.output()?;
    let status = outoput.status()?;

    let stdout = from_utf8(&output.stdout).map_err(|_| Error::ParseStr("output".into()))?;

    if !status.success() && stdout.contains("requires admin privileges") {
        log::error!(
            "Admin privileges required to run networksetup with args: {:?}, error: {}",
            args,
            stdout
        );
        return Err(Error::RequiresAdminPrivileges);
    }

    Ok(Cow::Owned(stdout.to_string()))
}

#[inline]
fn set_proxy(proxy: &Sysproxy, proxy_type: ProxyType, service: &str) -> Result<()> {
    let host = proxy.host.as_str();
    let port = format!("{}", proxy.port);
    let port = port.as_str();

    run_networksetup(&[proxy_type.as_set_str(), service, host, port])?;

    let enable = if proxy.enable { "on" } else { "off" };

    run_networksetup(&[proxy_type.as_state_cmd(), service, enable])?;

    Ok(())
}

#[inline]
fn set_bypass(proxy: &Sysproxy, service: &str) -> Result<()> {
    let domains = proxy.bypass.split(",").collect::<Vec<_>>();
    run_networksetup(&[["-setproxybypassdomains", service].to_vec(), domains].concat())?;
    Ok(())
}

fn get_active_network_service() -> Result<CFString> {
    let service_uuid = get_active_network_service_uuid()?;
    let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
    let services = SCNetworkService::get_services(&scp);
    for service in &services {
        if let Some(uuid) = service.id() {
            if uuid == service_uuid {
                if let Some(interface) = service.network_interface() {
                    if let Some(name) = interface.display_name() {
                        return Ok(name);
                    }
                }
            }
        }
    }
    Err(Error::NetworkInterface)
}

fn get_active_network_service_uuid() -> Result<CFString> {
    let store = SCDynamicStoreBuilder::new("sysproxy-rs")
        .build()
        .ok_or(Error::SCDynamicStore)?;
    let global_ipv4_key = CFString::from_static_string("State:/Network/Global/IPv4");
    let sets = store.get(global_ipv4_key).ok_or(Error::SCDynamicStore)?;
    if let Some(dict) = sets.downcast_into::<CFDictionary>() {
        let key = CFString::from_static_string("PrimaryService");
        let val_ptr = dict.find(key.as_CFTypeRef() as *const _);
        if let Some(ptr) = val_ptr {
            let service_id_cf = unsafe { CFString::wrap_under_get_rule(*ptr as _) };
            return Ok(service_id_cf);
        }
    }
    Err(Error::NetworkInterface)
}

fn parse_proxies_from_dict(
    cfd: &CFDictionary<CFString, CFType>,
    proxy_type: ProxyType,
) -> Result<Sysproxy> {
    // When proxy is not configured, these keys may not exist - default to disabled
    let enable = get_proxy_value(cfd, proxy_type.as_enable())
        .and_then(|x| x.downcast::<CFNumber>())
        .and_then(|num| num.to_i32())
        .map(|v| v != 0)
        .unwrap_or(false);

    // Read host/port even when disabled (macOS preserves these values)
    let port = get_proxy_value(cfd, proxy_type.as_port())
        .and_then(|x| x.downcast::<CFNumber>())
        .and_then(|num| num.to_i32())
        .unwrap_or(0);
    let host = get_proxy_value(cfd, proxy_type.as_host())
        .and_then(|x| x.downcast::<CFString>().map(|s| s.to_string()))
        .unwrap_or_default();

    Ok(Sysproxy {
        enable,
        host,
        port: port as u16,
        bypass: String::new(),
    })
}

fn parse_proxyauto_from_dict(cfd: &CFDictionary<CFString, CFType>) -> Result<Autoproxy> {
    // When auto proxy is not configured, these keys may not exist - default to disabled
    let enable = get_proxy_value(cfd, "ProxyAutoConfigEnable")
        .and_then(|x| x.downcast::<CFNumber>())
        .and_then(|num| num.to_i32())
        .map(|v| v != 0)
        .unwrap_or(false);

    // If not enabled, return default disabled auto proxy
    if !enable {
        return Ok(Autoproxy {
            enable: false,
            url: String::new(),
        });
    }

    let url = get_proxy_value(cfd, "ProxyAutoConfigURLString")
        .and_then(|x| x.downcast::<CFString>().map(|s| s.to_string()))
        .ok_or_else(|| Error::ParseStr("Unable to parse auto proxy URL from CSP".into()))?;

    let url = if url == "\"\"" { String::new() } else { url };

    Ok(Autoproxy { enable, url })
}

fn parse_bypass_from_dict(cfd: &CFDictionary<CFString, CFType>) -> Result<Vec<String>> {
    let bypass_list_raw = get_proxy_value(cfd, "ExceptionsList")
        .and_then(|x| x.downcast::<CFArray>())
        .ok_or_else(|| Error::ParseStr("Unable to parse bypass list".into()))?;

    let mut bypass_list = Vec::with_capacity(bypass_list_raw.len() as usize);
    for bypass_raw in &bypass_list_raw {
        let cf_type: CFType = unsafe { TCFType::wrap_under_get_rule(*bypass_raw as _) };
        if let Some(cf_string) = cf_type.downcast::<CFString>() {
            bypass_list.push(cf_string.to_string());
        }
    }

    Ok(bypass_list)
}

fn get_proxy_value<'a>(
    dict: &'a CFDictionary<CFString, CFType>,
    key: &'static str,
) -> Option<ItemRef<'a, CFType>> {
    let cf_key = CFString::from_static_string(key);
    dict.find(&cf_key)
}

// #[allow(dead_code)]
// fn get_service_id_by_bsd_name(scp: &SCPreferences, bsd_name: &str) -> Option<CFString> {
//     let services = SCNetworkService::get_services(scp);
//     for service in &services {
//         if let Some(interface) = service
//             .network_interface()
//             .and_then(|scn_inter| scn_inter.bsd_name().map(|name| name.to_string()))
//         {
//             if interface == bsd_name {
//                 return service.id();
//             }
//         }
//     }
//     None
// }

fn get_service_id_by_display_name(scp: &SCPreferences, name: &CFString) -> Option<CFString> {
    let services = SCNetworkService::get_services(scp);
    for service in &services {
        if let Some(interface) = service
            .network_interface()
            .and_then(|scn_inter| scn_inter.display_name())
        {
            if interface == *name {
                return service.id();
            }
        }
    }
    None
}

fn get_autoproxies_by_service_uuid(
    store: &SCDynamicStore,
    service_uuid: &CFString,
) -> Result<Autoproxy> {
    let proxy_key = CFString::new(&format!("Setup:/Network/Service/{}/Proxies", service_uuid));

    let proxies_cf_type = store
        .get(proxy_key)
        .ok_or_else(|| Error::ParseStr("Proxy settings not found in DynamicStore".into()))?;

    let proxies_dict_raw = proxies_cf_type
        .downcast_into::<CFDictionary>()
        .ok_or_else(|| Error::ParseStr("Not a dictionary".into()))?;

    let proxies_dict: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_get_rule(proxies_dict_raw.as_concrete_TypeRef() as _) };

    parse_proxyauto_from_dict(&proxies_dict)
}

fn get_proxies_by_service_uuid(
    scp: &SCPreferences,
    service_uuid: &CFString,
) -> Result<CFDictionary<CFString, CFType>> {
    unsafe {
        let service_ref = SCNetworkServiceCopy(
            scp.as_concrete_TypeRef(),
            service_uuid.as_concrete_TypeRef(),
        );
        if service_ref.is_null() {
            return Err(Error::SCPreferences);
        }

        let protocol_ref = SCNetworkServiceCopyProtocol(
            service_ref,
            CFString::from_static_string("Proxies").as_concrete_TypeRef(),
        );
        if protocol_ref.is_null() {
            return Err(Error::SCPreferences);
        }

        let config = SCNetworkProtocolGetConfiguration(protocol_ref);
        if config.is_null() {
            return Err(Error::SCPreferences);
        }

        let dict: CFDictionary<CFString, CFType> = CFDictionary::wrap_under_get_rule(config as _);

        CFRelease(service_ref);
        CFRelease(protocol_ref);

        Ok(dict)
    }
}

pub fn get_proxies_dict_from_service_uuid(
    service: &CFString,
) -> Result<CFDictionary<CFString, CFType>> {
    let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
    let service_uuid =
        get_service_id_by_display_name(&scp, service).ok_or(Error::NetworkInterface)?;
    get_proxies_by_service_uuid(&scp, &service_uuid)
}

#[test]
fn test_get_service_id_by_display_name() {
    let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
    let services = SCNetworkService::get_services(&scp);

    // Find first service with a valid display name (CI may not have Wi-Fi)
    let Some(display_name) = services.iter().find_map(|service| {
        service
            .network_interface()
            .and_then(|iface| iface.display_name())
    }) else {
        println!("No network service found, skipping test");
        return;
    };

    println!("Testing with service: {:?}", display_name);
    let Some(service_uuid) = get_service_id_by_display_name(&scp, &display_name) else {
        panic!("Failed to get service UUID for {:?}", display_name);
    };
    assert!(!service_uuid.to_string().is_empty());
    println!("service_uuid: {:?}", service_uuid);

    // Proxy settings may not exist for all services
    match get_proxies_by_service_uuid(&scp, &service_uuid) {
        Ok(proxies) => println!("proxies: {:?}", proxies),
        Err(e) => println!("No proxy settings for this service: {:?}", e),
    }
}

#[test]
fn test_set_bypass() {
    let proxy = Sysproxy {
        host: "proxy.example.com".into(),
        port: 8080,
        enable: true,
        bypass: "no".into(),
    };
    let result = proxy.set_bypass("Wi-Fi");
    if let Err(e) = result {
        assert!(matches!(e, Error::RequiresAdminPrivileges));
        assert!(!Sysproxy::has_permission());
    }
}
