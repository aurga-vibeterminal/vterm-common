//! Live system-proxy detection for outbound HTTP calls.
//!
//! The proxy environment (`HTTP_PROXY`/`HTTPS_PROXY`/…) of a long-running
//! daemon is a snapshot from process start: when the user toggles the system
//! proxy while vterm-server keeps running, reqwest clients built from that
//! snapshot keep using a dead proxy (or keep bypassing a live one). This
//! module instead asks the OS desktop settings at request time:
//!
//! - Linux: `gsettings` (GNOME family: `org.gnome.system.proxy`), then KDE's
//!   `~/.config/kioslaverc` (a plain INI file, no subprocess needed);
//! - macOS: `scutil --proxy`;
//! - Windows: `reg query` on `HKCU\...\Internet Settings`.
//!
//! When a desktop source is found, its answer is authoritative — including an
//! explicit "proxy disabled", which must win over the stale process env. When
//! no desktop source exists (headless server, ssh session), the caller falls
//! back to reqwest's default env-var behavior. Detection is cached for a few
//! seconds so bursty addon calls do not spawn a subprocess per request.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How the current request should reach the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedProxy {
    /// A desktop settings source positively reports the proxy is off.
    /// Overrides any stale proxy env the daemon was started with.
    Direct,
    /// Use this proxy URL (`http://host:port` or `socks5://host:port`).
    Url(String),
    /// No desktop settings source is available (headless): keep reqwest's
    /// default env-var behavior.
    Environment,
}

/// Detection is subprocess-based; cache briefly so a burst of addon requests
/// shares one probe.
const CACHE_TTL: Duration = Duration::from_secs(3);

static CACHE: Mutex<Option<(Instant, ResolvedProxy)>> = Mutex::new(None);

/// Resolve the current system proxy state, cached for [`CACHE_TTL`].
pub fn resolve_system_proxy() -> ResolvedProxy {
    if let Some((at, cached)) = CACHE.lock().unwrap().as_ref() {
        if at.elapsed() < CACHE_TTL {
            return cached.clone();
        }
    }
    let resolved = detect_system_proxy();
    *CACHE.lock().unwrap() = Some((Instant::now(), resolved.clone()));
    resolved
}

fn detect_system_proxy() -> ResolvedProxy {
    #[cfg(target_os = "macos")]
    {
        detect_macos()
    }
    #[cfg(target_os = "windows")]
    {
        detect_windows()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        detect_linux()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        ResolvedProxy::Environment
    }
}

// ---------------------------------------------------------------------------
// macOS: scutil --proxy
// ---------------------------------------------------------------------------

/// Parse `scutil --proxy` output. Priority: HTTPS → HTTP → SOCKS.
fn parse_scutil(output: &str) -> ResolvedProxy {
    let get = |key: &str| -> Option<String> {
        output.lines().map(str::trim).find_map(|line| {
            let (k, v) = line.split_once(" : ")?;
            (k == key).then(|| v.trim().to_string())
        })
    };
    let enabled = |key: &str| get(key).as_deref() == Some("1");
    if enabled("HTTPSEnable") {
        if let (Some(host), Some(port)) = (get("HTTPSProxy"), get("HTTPSPort")) {
            return ResolvedProxy::Url(format!("http://{host}:{port}"));
        }
    }
    if enabled("HTTPEnable") {
        if let (Some(host), Some(port)) = (get("HTTPProxy"), get("HTTPPort")) {
            return ResolvedProxy::Url(format!("http://{host}:{port}"));
        }
    }
    if enabled("SOCKSEnable") {
        if let (Some(host), Some(port)) = (get("SOCKSProxy"), get("SOCKSPort")) {
            return ResolvedProxy::Url(format!("socks5://{host}:{port}"));
        }
    }
    ResolvedProxy::Direct
}

#[cfg(target_os = "macos")]
fn detect_macos() -> ResolvedProxy {
    match std::process::Command::new("scutil").arg("--proxy").output() {
        Ok(out) if out.status.success() => parse_scutil(&String::from_utf8_lossy(&out.stdout)),
        _ => ResolvedProxy::Environment,
    }
}

// ---------------------------------------------------------------------------
// Windows: Internet Settings registry via `reg query`
// ---------------------------------------------------------------------------

/// `reg query ... /v ProxyEnable` output contains `ProxyEnable    REG_DWORD    0x1`.
fn reg_dword_enabled(output: &str) -> Option<bool> {
    let value = output
        .lines()
        .find(|line| line.contains("REG_DWORD"))?
        .split_whitespace()
        .next_back()?;
    u32::from_str_radix(value.trim_start_matches("0x"), 16)
        .ok()
        .map(|v| v != 0)
}

/// ProxyServer is either `host:port` or per-protocol `http=h:p;https=h:p;…`.
fn parse_reg_proxy_server(output: &str) -> Option<String> {
    let value = output
        .lines()
        .find(|line| line.contains("REG_SZ"))?
        .split_once("REG_SZ")?
        .1
        .trim()
        .to_string();
    if value.is_empty() {
        return None;
    }
    let picked = if value.contains('=') {
        value
            .split(';')
            .find_map(|part| {
                let (scheme, addr) = part.split_once('=')?;
                (scheme.trim() == "http").then(|| addr.trim().to_string())
            })
            .or_else(|| {
                value
                    .split(';')
                    .filter_map(|part| part.split_once('='))
                    .next()
                    .map(|(_, addr)| addr.trim().to_string())
            })?
    } else {
        value
    };
    if picked.is_empty() {
        return None;
    }
    if picked.contains("://") {
        Some(picked)
    } else {
        Some(format!("http://{picked}"))
    }
}

#[cfg(target_os = "windows")]
fn detect_windows() -> ResolvedProxy {
    const KEY: &str = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    let query = |value: &str| {
        let mut command = std::process::Command::new("reg");
        command.args(["query", KEY, "/v", value]);
        crate::command_no_window(&mut command);
        command
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
    };
    match query("ProxyEnable").as_deref().map(reg_dword_enabled) {
        Some(Some(false)) => ResolvedProxy::Direct,
        Some(Some(true)) => match query("ProxyServer")
            .as_deref()
            .and_then(parse_reg_proxy_server)
        {
            Some(url) => ResolvedProxy::Url(url),
            None => ResolvedProxy::Direct,
        },
        _ => ResolvedProxy::Environment,
    }
}

// ---------------------------------------------------------------------------
// Linux: gsettings (GNOME family), then KDE's kioslaverc
// ---------------------------------------------------------------------------

#[cfg(all(unix, not(target_os = "macos")))]
fn gsettings(schema: &str, key: &str) -> Option<String> {
    let out = std::process::Command::new("gsettings")
        .args(["get", schema, key])
        .output()
        .ok()
        .filter(|out| out.status.success())?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Some(value.trim_matches('\'').to_string())
}

/// Build a proxy URL from a gsettings schema like `org.gnome.system.proxy.http`.
#[cfg(all(unix, not(target_os = "macos")))]
fn gsettings_proxy_url(schema: &str, scheme: &str) -> Option<String> {
    let host = gsettings(schema, "host")?;
    if host.is_empty() {
        return None;
    }
    let port = gsettings(schema, "port")?
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0)?;
    Some(format!("{scheme}://{host}:{port}"))
}

/// GNOME manual mode: prefer the HTTP proxy (covers https:// targets through
/// CONNECT), then HTTPS, then SOCKS.
#[cfg(all(unix, not(target_os = "macos")))]
fn detect_gnome_manual() -> Option<ResolvedProxy> {
    if let Some(url) = gsettings_proxy_url("org.gnome.system.proxy.http", "http") {
        return Some(ResolvedProxy::Url(url));
    }
    if let Some(url) = gsettings_proxy_url("org.gnome.system.proxy.https", "http") {
        return Some(ResolvedProxy::Url(url));
    }
    if let Some(url) = gsettings_proxy_url("org.gnome.system.proxy.socks", "socks5") {
        return Some(ResolvedProxy::Url(url));
    }
    // Manual mode with no host configured is effectively off.
    Some(ResolvedProxy::Direct)
}

/// KDE `kioslaverc` keys are top-level: `ProxyType=0..4`, and for manual mode
/// `httpProxy=http://host port` (note the space, not a colon).
fn parse_kioslaverc(contents: &str) -> Option<ResolvedProxy> {
    let get = |key: &str| -> Option<String> {
        contents.lines().map(str::trim).find_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k == key).then(|| v.trim().to_string())
        })
    };
    match get("ProxyType").as_deref() {
        // 0 = no proxy.
        Some("0") => Some(ResolvedProxy::Direct),
        // 1 = manual.
        Some("1") => {
            let raw = get("httpProxy")?;
            // KDE stores "scheme://host port"; the space splits host and port.
            let (base, port) = raw.rsplit_once(' ').unwrap_or((raw.as_str(), "8080"));
            let base = base.trim_end_matches('/');
            if base.is_empty() {
                return Some(ResolvedProxy::Direct);
            }
            let with_scheme = if base.contains("://") {
                base.to_string()
            } else {
                format!("http://{base}")
            };
            Some(ResolvedProxy::Url(format!("{with_scheme}:{port}")))
        }
        // 4 = use environment variables; 2/3 (WPAD/system) unsupported.
        _ => Some(ResolvedProxy::Environment),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn detect_linux() -> ResolvedProxy {
    if let Some(mode) = gsettings("org.gnome.system.proxy", "mode") {
        return match mode.as_str() {
            "none" => ResolvedProxy::Direct,
            "manual" => detect_gnome_manual().unwrap_or(ResolvedProxy::Direct),
            // "auto" is a PAC URL we cannot evaluate without a JS engine;
            // fall back to env behavior as the least-wrong option.
            _ => ResolvedProxy::Environment,
        };
    }
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|home| std::path::PathBuf::from(home).join(".config"))
        });
    if let Some(dir) = config_home {
        if let Ok(contents) = std::fs::read_to_string(dir.join("kioslaverc")) {
            if let Some(resolved) = parse_kioslaverc(&contents) {
                return resolved;
            }
        }
    }
    ResolvedProxy::Environment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scutil_manual_http_and_socks() {
        let output = "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 127.0.0.1\n  HTTPPort : 7890\n  SOCKSEnable : 0\n}\n";
        assert_eq!(
            parse_scutil(output),
            ResolvedProxy::Url("http://127.0.0.1:7890".to_string())
        );
    }

    #[test]
    fn scutil_disabled_means_direct() {
        let output = "<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n  SOCKSEnable : 0\n}\n";
        assert_eq!(parse_scutil(output), ResolvedProxy::Direct);
    }

    #[test]
    fn reg_enable_and_server_parsing() {
        let enabled = "\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\n    ProxyEnable    REG_DWORD    0x1\n";
        assert_eq!(reg_dword_enabled(enabled), Some(true));
        assert_eq!(
            reg_dword_enabled("    ProxyEnable    REG_DWORD    0x0\n"),
            Some(false)
        );
        assert_eq!(
            parse_reg_proxy_server("    ProxyServer    REG_SZ    127.0.0.1:7890\n"),
            Some("http://127.0.0.1:7890".to_string())
        );
        assert_eq!(
            parse_reg_proxy_server(
                "    ProxyServer    REG_SZ    http=proxy.local:8080;https=proxy.local:8443\n"
            ),
            Some("http://proxy.local:8080".to_string())
        );
        assert_eq!(
            parse_reg_proxy_server("    ProxyServer    REG_SZ    \n"),
            None
        );
    }

    #[test]
    fn kioslaverc_manual_and_off() {
        assert_eq!(
            parse_kioslaverc("ProxyType=0\n"),
            Some(ResolvedProxy::Direct)
        );
        assert_eq!(
            parse_kioslaverc("ProxyType=1\nhttpProxy=http://127.0.0.1 7890\n"),
            Some(ResolvedProxy::Url("http://127.0.0.1:7890".to_string()))
        );
        assert_eq!(
            parse_kioslaverc("ProxyType=4\n"),
            Some(ResolvedProxy::Environment)
        );
    }

    #[test]
    fn resolve_system_proxy_returns_a_decision() {
        // Smoke test on the host: must not panic and must cache.
        let first = resolve_system_proxy();
        let second = resolve_system_proxy();
        assert_eq!(first, second);
    }
}
