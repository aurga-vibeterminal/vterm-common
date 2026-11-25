use std::ffi::OsString;
use std::sync::OnceLock;

pub const SCREEN_PERF_LOG_ENV: &str = "VTERM_SCREEN_PERF_LOG";

fn enabled_value(value: Option<OsString>) -> bool {
    value.is_some_and(|value| !value.is_empty() && value != "0")
}

pub fn screen_perf_log_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| enabled_value(std::env::var_os(SCREEN_PERF_LOG_ENV)))
}

#[cfg(test)]
mod tests {
    use super::enabled_value;

    #[test]
    fn perf_log_requires_a_nonzero_value() {
        assert!(!enabled_value(None));
        assert!(!enabled_value(Some("".into())));
        assert!(!enabled_value(Some("0".into())));
        assert!(enabled_value(Some("1".into())));
        assert!(enabled_value(Some("true".into())));
    }
}
