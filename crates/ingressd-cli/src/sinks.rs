//! Alert output sinks: stdout, a size-rotated JSON-Lines file, syslog (Unix),
//! and an async HTTPS webhook with retry/backoff. An optional ECS field mapping
//! is applied to the webhook payload.

use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::sync::mpsc;

use ingressd_core::metrics::Counters;
use ingressd_core::types::{Alert, Severity};

use crate::config::Sinks as SinksCfg;

/// Append a webhook JSON payload off the hot path.
pub type WebhookTx = mpsc::Sender<String>;
pub type WebhookRx = mpsc::Receiver<String>;

/// A size-rotated file writer (`alerts.jsonl`, `.1`..`.N`).
pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    max_files: usize,
    file: Option<File>,
    written: u64,
}

impl RotatingFile {
    /// Open (or create) the base file for append.
    pub fn new(path: PathBuf, max_bytes: u64, max_files: usize) -> std::io::Result<RotatingFile> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(RotatingFile { path, max_bytes, max_files, file: Some(file), written })
    }

    /// Write one line (a newline is appended), rotating when over the byte cap.
    pub fn write_line(&mut self, line: &[u8]) -> std::io::Result<()> {
        if let Some(f) = self.file.as_mut() {
            f.write_all(line)?;
            f.write_all(b"\n")?;
            f.flush()?;
            self.written += line.len() as u64 + 1;
            if self.written >= self.max_bytes {
                self.rotate()?;
            }
        }
        Ok(())
    }

    fn suffixed(&self, i: usize) -> PathBuf {
        if i == 0 {
            return self.path.clone();
        }
        let mut s = self.path.as_os_str().to_os_string();
        s.push(format!(".{i}"));
        PathBuf::from(s)
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        // Close, drop the oldest, shift .n-1 -> .n, base -> .1, then reopen fresh.
        self.file = None;
        let oldest = self.suffixed(self.max_files);
        if oldest.exists() {
            let _ = std::fs::remove_file(&oldest);
        }
        for i in (1..self.max_files).rev() {
            let from = self.suffixed(i);
            if from.exists() {
                let to = self.suffixed(i + 1);
                let _ = std::fs::rename(&from, &to);
            }
        }
        let base = self.suffixed(0);
        let to = self.suffixed(1);
        if base.exists() {
            std::fs::rename(&base, &to)?;
        }
        let f = OpenOptions::new().create(true).truncate(true).write(true).open(&base)?;
        self.file = Some(f);
        self.written = 0;
        Ok(())
    }
}

/// Fan alerts out to the configured sinks.
pub struct Sink {
    stdout: bool,
    file: Option<RotatingFile>,
    counters: Arc<Counters>,
    webhook_tx: Option<WebhookTx>,
    ecs: bool,
    redact_local: bool,
    #[cfg(unix)]
    syslog: Option<std::os::unix::net::UnixDatagram>,
}

impl Sink {
    /// Build from sink config. Returns the sink and, if a webhook is configured,
    /// the receiver to drive [`run_webhook`].
    pub fn new(cfg: &SinksCfg, counters: Arc<Counters>) -> (Sink, Option<WebhookRx>) {
        let file = cfg
            .alerts_file
            .as_ref()
            .and_then(|p| match RotatingFile::new(p.clone(), cfg.rotate_max_bytes, cfg.rotate_max_files) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::error!("cannot open alerts file {}: {e}", p.display());
                    None
                }
            });

        #[cfg(unix)]
        let syslog = if cfg.syslog {
            match std::os::unix::net::UnixDatagram::unbound() {
                Ok(s) => {
                    let target = PathBuf::from("/dev/log");
                    // Best effort: if /dev/log is absent, keep the socket unbound
                    // and send_to will simply fail quietly per message.
                    let _ = s.connect(&target);
                    Some(s)
                }
                Err(e) => {
                    tracing::warn!("syslog unavailable: {e}");
                    None
                }
            }
        } else {
            None
        };

        let (webhook_tx, webhook_rx) = if cfg.webhook_url.is_some() {
            let (tx, rx) = mpsc::channel::<String>(1000);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let sink = Sink {
            stdout: cfg.stdout,
            file,
            counters,
            webhook_tx,
            ecs: cfg.webhook_ecs,
            redact_local: cfg.redact_local_ip,
            #[cfg(unix)]
            syslog,
        };
        (sink, webhook_rx)
    }

    /// Emit one alert to all enabled sinks.
    pub fn emit(&mut self, alert: &Alert) {
        let alert = if self.redact_local {
            let mut a = alert.clone();
            a.local_ip = mask_ip(a.local_ip);
            Cow::Owned(a)
        } else {
            Cow::Borrowed(alert)
        };
        let json = match serde_json::to_string(&*alert) {
            Ok(s) => s,
            Err(e) => {
                self.counters.inc_drops(1);
                tracing::error!("failed to serialize alert: {e}");
                return;
            }
        };

        if self.stdout {
            println!("{json}");
        }

        if let Some(f) = self.file.as_mut() {
            if let Err(e) = f.write_line(json.as_bytes()) {
                tracing::error!("alerts file write failed: {e}");
            }
        }

        #[cfg(unix)]
        if let Some(s) = &self.syslog {
            let msg = format!("<13>ingressd[{}]: {json}", std::process::id());
            let _ = s.send(msg.as_bytes());
        }

        if let Some(tx) = &self.webhook_tx {
            let payload = if self.ecs { to_ecs(&alert) } else { json };
            // Never block the engine loop on a slow sink.
            if tx.try_send(payload).is_err() {
                self.counters.inc_drops(1);
            }
        }
    }
}

/// Redact a host-side address to its /24 (v4) or /64 (v6) prefix.
fn mask_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mut o = v4.octets();
            o[3] = 0;
            IpAddr::V4(Ipv4Addr::from(o))
        }
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            for b in o.iter_mut().skip(8) {
                *b = 0;
            }
            IpAddr::V6(Ipv6Addr::from(o))
        }
    }
}

fn sev_number(s: Severity) -> u8 {
    match s {
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 5,
    }
}

/// Map an alert to Elastic Common Schema fields.
pub fn to_ecs(alert: &Alert) -> String {
    let (source_ip, dest_ip) = match alert.direction {
        ingressd_core::types::Direction::Inbound => (alert.peer_ip, alert.local_ip),
        ingressd_core::types::Direction::Outbound => (alert.local_ip, alert.peer_ip),
    };

    let mut root = Map::new();
    root.insert("@timestamp".into(), Value::String(alert.time.to_rfc3339()));

    let mut event = Map::new();
    event.insert("kind".into(), Value::String("alert".into()));
    event.insert("category".into(), Value::String("network".into()));
    event.insert("module".into(), Value::String("ingressd".into()));
    event.insert("severity".into(), Value::from(sev_number(alert.severity)));
    event.insert("code".into(), Value::String(alert.rule.to_string()));
    event.insert("action".into(), Value::String(alert.rule.as_str().to_string()));
    event.insert("risk_score".into(), Value::from(alert.risk_score));
    root.insert("event".into(), Value::Object(event));

    let mut source = Map::new();
    source.insert("ip".into(), Value::String(source_ip.to_string()));
    if let Some(p) = alert.ports.src {
        source.insert("port".into(), Value::from(p));
    }
    root.insert("source".into(), Value::Object(source));

    let mut dest = Map::new();
    dest.insert("ip".into(), Value::String(dest_ip.to_string()));
    if let Some(p) = alert.ports.dst {
        dest.insert("port".into(), Value::from(p));
    }
    root.insert("destination".into(), Value::Object(dest));

    let mut network = Map::new();
    network.insert("transport".into(), Value::String(alert.proto.to_string()));
    network.insert("direction".into(), Value::String(alert.direction.to_string()));
    root.insert("network".into(), Value::Object(network));

    let mut rule = Map::new();
    rule.insert("name".into(), Value::String(alert.rule.as_str().to_string()));
    rule.insert("reference".into(), Value::String(format!("https://attack.mitre.org/techniques/{}", alert.mitre)));
    root.insert("rule".into(), Value::Object(rule));

    let mut mitre = Map::new();
    mitre.insert("technique_id".into(), Value::String(alert.mitre.clone()));
    mitre.insert("tactic_id".into(), Value::String(alert.tactic.clone()));
    mitre.insert("tactic_name".into(), Value::String(alert.tactic_name.clone()));
    root.insert("mitre".into(), Value::Object(mitre));

    root.insert("tags".into(), Value::Array(alert.tags.iter().map(|t| Value::String(t.clone())).collect()));

    let mut labels = Map::new();
    labels.insert("mitre_technique_id".into(), Value::String(alert.mitre.clone()));
    if let Some(cc) = &alert.peer_country {
        labels.insert("peer_country".into(), Value::String(cc.clone()));
    }
    if let Some(asn) = alert.peer_asn {
        labels.insert("peer_asn".into(), Value::from(asn));
    }
    root.insert("labels".into(), Value::Object(labels));

    root.insert("message".into(), Value::String(alert.detail.clone()));
    root.insert("ingressd".into(), Value::Object({
        let mut m = Map::new();
        m.insert("count".into(), Value::from(alert.count));
        m.insert("window_s".into(), Value::from(alert.window_s));
        m
    }));

    Value::Object(root).to_string()
}

/// POST queued payloads to the webhook with bounded exponential backoff.
pub async fn run_webhook(mut rx: WebhookRx, url: String, token: Option<String>, client: reqwest::Client) {
    while let Some(payload) = rx.recv().await {
        let mut attempt = 0u32;
        let mut backoff = Duration::from_millis(500);
        loop {
            let mut req = client.post(&url).header("content-type", "application/json").body(payload.clone());
            if let Some(t) = &token {
                req = req.bearer_auth(t);
            }
            match req.send().await {
                Ok(r) if r.status().is_success() => break,
                Ok(r) => tracing::warn!("webhook returned {}", r.status()),
                Err(e) => tracing::warn!("webhook request failed: {e}"),
            }
            attempt += 1;
            if attempt >= 3 {
                tracing::warn!("giving up on webhook payload after {attempt} attempts");
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff *= 2;
        }
    }
}
