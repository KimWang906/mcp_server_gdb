#[derive(Debug)]
/// Server Configuration
pub struct Config {
    /// Server URL
    pub server_ip: String,
    /// Server port
    pub server_port: u16,
    /// GDB command execution timeout in seconds
    pub command_timeout: u64,
    /// Optional path to GEF rc file
    pub gef_rc: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_ip: std::env::var("SERVER_IP").unwrap_or_else(|_| "127.0.0.1".to_string()),
            server_port: std::env::var("SERVER_PORT")
                .unwrap_or_else(|_| "7774".to_string())
                .parse()
                .expect("Invalid server port"),
            command_timeout: std::env::var("GDB_COMMAND_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            gef_rc: std::env::var("GEF_RC")
                .ok()
                .map(std::path::PathBuf::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::env;
    use std::path::PathBuf;

    #[test]
    fn config_reads_gef_rc_from_env() {
        let key = "GEF_RC";
        let original = env::var(key).ok();
        let sample = PathBuf::from("/tmp/test-gef.rc");
        unsafe {
            env::set_var(key, &sample);
        }
        let config = Config::default();
        assert_eq!(config.gef_rc, Some(sample));
        match original {
            Some(value) => unsafe {
                env::set_var(key, value);
            },
            None => unsafe {
                env::remove_var(key);
            },
        }
    }
}
