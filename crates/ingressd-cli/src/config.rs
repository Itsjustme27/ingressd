//! Top-level `config.toml` model: general, rules, intel, metrics, sinks,
//! enforce, log. Strict (`deny_unknown_fields`), defaulted, and validated.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

use ingressd_core::config::RulesConfig;

/// The full runtime configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub rules: RulesConfig,
    pub intel: Intel,
    pub metrics: Metrics,
    pub sinks: Sinks,
    pub enforce: Enforce,
    pub log: Log,
    /// `[custom_signatures]` — Snort-style rules loaded at startup.
    pub custom_signatures: CustomSignatures,
}

/// `[custom_signatures]` — load Snort `.rules` files and/or inline rules.
///
/// Parsed into the engine's signature set at startup (and on `SIGHUP`); each
/// enforceable rule becomes a `custom-signature` alert, and unparseable/unsupported
/// lines are reported. Use `ingressd snort2sigma` to also emit Sigma for the SIEM.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomSignatures {
    /// Master switch (off by default).
    pub enabled: bool,
    /// External Snort `.rules` files to load.
    pub files: Vec<PathBuf>,
    /// Inline Snort rule text, one rule per string entry.
    pub rules: Vec<String>,
    /// Snort variables: `HOME_NET = "..."`, `EXTERNAL_NET = "any"`, etc.
    pub vars: HashMap<String, String>,
}

/// `[general]` — inputs and host context.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    /// Interface for live capture (empty => auto-detect default route).
    pub iface: String,
    /// Replay this pcap file instead of live capture.
    pub pcap: Option<PathBuf>,
    /// Parse this VPC flow log file (`-` = stdin) instead of frames.
    pub flow_log: Option<PathBuf>,
    /// Extra addresses owned by this host (CIDR/IP strings), merged with auto.
    pub host_ips: Vec<String>,
    /// Seconds between host-address refreshes.
    pub refresh_host_secs: u64,
    /// Allowlisted peers (CIDR or IP strings): never alert, never block.
    pub allowlist: Vec<String>,
    /// Directory for feed caches and rotating state.
    pub cache_dir: Option<PathBuf>,
    /// Bounded event-channel capacity.
    pub channel_capacity: usize,
    /// Sensor id stamped on alerts (defaults to $HOSTNAME when empty).
    pub sensor_id: String,
    /// Behavior when the capture->engine channel is full: `drop` | `stall` | `exit`.
    /// `drop` = fail-open (keep serving alerts, shed load); `stall` = apply
    /// backpressure; `exit` = fail-closed (stop rather than miss traffic).
    pub on_queue_full: String,
    /// Pin the capture thread to these CPU ids (Linux, live capture; empty = none).
    pub cpu_affinity: Vec<usize>,
}

/// `[intel]` — threat-intel feeds and optional geo.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Intel {
    /// IP/CIDR blocklist feeds.
    pub feeds: Vec<Feed>,
    /// Refresh interval in seconds (default 3600).
    pub refresh_secs: u64,
    /// Optional local MaxMind DB for ASN/country enrichment.
    pub geoip_db: Option<PathBuf>,
}

/// One intel feed. Exactly one of `url` or `path` must be set.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Feed {
    /// Human-readable name (also the cache key).
    pub name: String,
    /// HTTPS URL to fetch.
    pub url: Option<String>,
    /// Local file path.
    pub path: Option<PathBuf>,
    /// Enable/disable without deleting the entry.
    pub enabled: bool,
}

/// `[metrics]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Metrics {
    pub enabled: bool,
    /// Address to bind the Prometheus endpoint (keep to localhost).
    pub listen: String,
}

/// `[sinks]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sinks {
    /// Write JSONL alerts to stdout.
    pub stdout: bool,
    /// Write JSONL alerts to a size-rotated file.
    pub alerts_file: Option<PathBuf>,
    /// Rotate once a file exceeds this many bytes.
    pub rotate_max_bytes: u64,
    /// Number of rotated files to retain.
    pub rotate_max_files: usize,
    /// Delete rotated alert files older than this many days (GDPR/retention).
    /// `None` = size/count retention only.
    pub retention_days: Option<u64>,
    /// Zero the host-side address in emitted alerts (PII redaction of internal IPs).
    pub redact_local_ip: bool,
    /// Also send alerts to syslog (Unix).
    pub syslog: bool,
    /// POST alerts to a webhook (Slack/Teams/SIEM).
    pub webhook_url: Option<String>,
    /// Optional bearer token for the webhook.
    pub webhook_token: Option<String>,
    /// Emit ECS-style field names for the webhook payload.
    pub webhook_ecs: bool,
}

/// `[enforce]` — opt-in active response (nftables).
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Enforce {
    /// Master switch (off by default).
    pub enabled: bool,
    /// Log what would be blocked without doing it (default true).
    pub dry_run: bool,
    /// nft table family (ip or ip6).
    pub family: String,
    /// nft table name.
    pub table: String,
    /// nft set name (must have `flags timeout`).
    pub set: String,
    /// Block timeout in seconds.
    pub timeout_secs: u64,
    /// Max entries in the block set.
    pub max_entries: usize,
    /// Optional cloud-native hook (run instead of local nft), `{{ip}}` substituted.
    pub hook_command: Option<String>,
    /// Min severity to trigger a block.
    pub min_severity: ingressd_core::types::Severity,
}

/// `[log]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    /// `error | warn | info | debug | trace`.
    pub level: String,
}

// ---- Defaults ----

impl Default for Config {
    fn default() -> Self {
        Config {
            general: General::default(),
            rules: RulesConfig::default(),
            intel: Intel::default(),
            metrics: Metrics::default(),
            sinks: Sinks::default(),
            enforce: Enforce::default(),
            log: Log::default(),
            custom_signatures: CustomSignatures::default(),
        }
    }
}

impl Default for CustomSignatures {
    fn default() -> Self {
        CustomSignatures {
            enabled: false,
            files: Vec::new(),
            rules: Vec::new(),
            vars: HashMap::new(),
        }
    }
}

impl Default for General {
    fn default() -> Self {
        General {
            iface: String::new(),
            pcap: None,
            flow_log: None,
            host_ips: Vec::new(),
            refresh_host_secs: 30,
            allowlist: Vec::new(),
            cache_dir: None,
            channel_capacity: 100_000,
            sensor_id: String::new(),
            on_queue_full: "drop".to_string(),
            cpu_affinity: Vec::new(),
        }
    }
}

impl Default for Intel {
    fn default() -> Self {
        Intel {
            feeds: Vec::new(),
            refresh_secs: 3600,
            geoip_db: None,
        }
    }
}

impl Default for Feed {
    fn default() -> Self {
        Feed {
            name: String::new(),
            url: None,
            path: None,
            enabled: true,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            enabled: true,
            listen: "127.0.0.1:9102".to_string(),
        }
    }
}

impl Default for Sinks {
    fn default() -> Self {
        Sinks {
            stdout: true,
            alerts_file: None,
            rotate_max_bytes: 10 * 1024 * 1024,
            rotate_max_files: 5,
            retention_days: None,
            redact_local_ip: false,
            syslog: false,
            webhook_url: None,
            webhook_token: None,
            webhook_ecs: false,
        }
    }
}

impl Default for Enforce {
    fn default() -> Self {
        Enforce {
            enabled: false,
            dry_run: true,
            family: "ip".to_string(),
            table: "ingressd".to_string(),
            set: "blocklist".to_string(),
            timeout_secs: 3600,
            max_entries: 10_000,
            hook_command: None,
            min_severity: ingressd_core::types::Severity::High,
        }
    }
}

impl Default for Log {
    fn default() -> Self {
        Log {
            level: "info".to_string(),
        }
    }
}

/// Which input the process should use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    /// Live interface capture.
    Live,
    /// pcap replay.
    Pcap,
    /// VPC flow logs.
    FlowLog,
}

impl Config {
    /// Parse configuration from a TOML string, then validate.
    pub fn from_toml(text: &str) -> Result<Config, String> {
        let cfg: Config = toml::from_str(text).map_err(|e| format!("config parse error: {e}"))?;
        cfg.validate().map_err(|errs| errs.join("\n"))?;
        Ok(cfg)
    }

    /// Load and validate from a file path.
    pub fn load(path: &str) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        Config::from_toml(&text)
    }

    /// The single active input source. Returns an error if several are set.
    pub fn source(&self) -> Result<SourceKind, String> {
        let g = &self.general;
        match (g.pcap.is_some(), g.flow_log.is_some()) {
            (true, true) => {
                Err("set only one of general.pcap / general.flow_log / live capture".into())
            }
            (true, false) => Ok(SourceKind::Pcap),
            (false, true) => Ok(SourceKind::FlowLog),
            (false, false) => Ok(SourceKind::Live),
        }
    }

    /// Validate the whole configuration (rules plus cli-level sections).
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs: Vec<String> = Vec::new();
        if let Err(e) = self.rules.validate() {
            errs.extend(e);
        }
        // allowlist entries must parse as IP or CIDR.
        for a in &self.general.allowlist {
            if parse_cidr(a).is_none() {
                errs.push(format!("general.allowlist: invalid CIDR/IP '{a}'"));
            }
        }
        for a in &self.general.host_ips {
            if parse_cidr(a).is_none() {
                errs.push(format!("general.host_ips: invalid CIDR/IP '{a}'"));
            }
        }
        // metrics listen address must parse.
        if self.metrics.listen.parse::<std::net::SocketAddr>().is_err() {
            errs.push(format!(
                "metrics.listen: invalid socket address '{}'",
                self.metrics.listen
            ));
        }
        // feeds need exactly one of url/path.
        for f in &self.intel.feeds {
            let has = [f.url.is_some(), f.path.is_some()]
                .iter()
                .filter(|x| **x)
                .count();
            if f.name.is_empty() {
                errs.push("intel.feed: name must not be empty".into());
            }
            if has != 1 {
                errs.push(format!(
                    "intel.feed '{}': set exactly one of url or path",
                    f.name
                ));
            }
            if let Some(u) = &f.url {
                if !u.starts_with("https://") {
                    errs.push(format!("intel.feed '{}': url must be https", f.name));
                }
            }
        }
        if !(self.enforce.family == "ip" || self.enforce.family == "ip6") {
            errs.push(format!(
                "enforce.family: must be 'ip' or 'ip6', got '{}'",
                self.enforce.family
            ));
        }
        if self.sinks.rotate_max_files == 0 {
            errs.push("sinks.rotate_max_files must be >= 1".into());
        }
        if let Some(days) = self.sinks.retention_days {
            if days == 0 {
                errs.push("sinks.retention_days must be >= 1 when set".into());
            }
        }
        if self.general.channel_capacity == 0 {
            errs.push("general.channel_capacity must be >= 1".into());
        }
        if !matches!(
            self.general.on_queue_full.as_str(),
            "drop" | "stall" | "exit"
        ) {
            errs.push(format!(
                "general.on_queue_full must be drop|stall|exit, got '{}'",
                self.general.on_queue_full
            ));
        }
        // source must be resolvable.
        if self.source().is_err() {
            errs.push("multiple capture sources configured".into());
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }
}

/// Parse an IP-or-CIDR string into an `ipnet::IpNet` (bare IPs become host nets).
pub fn parse_cidr(s: &str) -> Option<ipnet::IpNet> {
    if let Ok(n) = s.parse::<ipnet::IpNet>() {
        return Some(n);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        let cidr = if ip.is_ipv4() {
            format!("{ip}/32")
        } else {
            format!("{ip}/128")
        };
        return cidr.parse::<ipnet::IpNet>().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_uses_defaults() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.metrics.listen, "127.0.0.1:9102");
        assert_eq!(c.source().unwrap(), SourceKind::Live);
    }

    #[test]
    fn rejects_unknown_key() {
        assert!(Config::from_toml("[general]\nbogus = 1\n").is_err());
    }

    #[test]
    fn pcap_source_and_bad_feed() {
        let toml = r#"
            [general]
            pcap = "/tmp/x.pcap"
            [[intel.feeds]]
            name = "dup"
            url = "http://insecure"
        "#;
        let c = Config::from_toml(toml);
        // url must be https -> validation error
        let err = c.unwrap_err();
        assert!(err.contains("https"), "unexpected error: {err}");
    }

    #[test]
    fn allowlist_validated() {
        let toml = r#"
            [general]
            allowlist = ["203.0.113.0/24", "not-an-ip"]
        "#;
        let err = Config::from_toml(toml).unwrap_err();
        assert!(err.contains("allowlist"), "unexpected: {err}");
    }
}
