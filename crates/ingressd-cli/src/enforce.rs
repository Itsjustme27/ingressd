//! Opt-in active response via `nftables` (or a user-supplied cloud hook).
//!
//! Disabled by default; `dry_run` defaults to true. Blocking is deliberately
//! guarded: allowlisted peers, the host's own addresses, cloud metadata, DNS
//! resolvers and the current SSH peer are never blocked, and total entries are
//! capped. The set must be created with `flags timeout` (the install script and
//! `ensure_set` do this).

use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

use ingressd_core::scope::HostAddrs;
use ingressd_core::types::Severity;

use crate::config::Enforce as EnforceCfg;

/// The enforcer. Cheap to share behind a reference during the alert loop.
pub struct Enforcer {
    enabled: bool,
    dry_run: bool,
    family: String,
    table: String,
    set: String,
    timeout_secs: u64,
    max_entries: usize,
    hook: Option<String>,
    min_severity: Severity,
    supported: bool,
    blocked: Mutex<HashSet<IpAddr>>,
}

impl Enforcer {
    /// Build from config. `override_enable`/`override_dry_run` come from CLI flags.
    pub fn new(
        cfg: &EnforceCfg,
        override_enable: bool,
        override_dry_run: Option<bool>,
    ) -> Enforcer {
        Enforcer {
            enabled: cfg.enabled || override_enable,
            dry_run: override_dry_run.unwrap_or(cfg.dry_run),
            family: cfg.family.clone(),
            table: cfg.table.clone(),
            set: cfg.set.clone(),
            timeout_secs: cfg.timeout_secs,
            max_entries: cfg.max_entries,
            hook: cfg.hook_command.clone(),
            min_severity: cfg.min_severity,
            supported: std::env::consts::OS == "linux",
            blocked: Mutex::new(HashSet::new()),
        }
    }

    /// Whether enforcement is active at all.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Should an alert of `sev` trigger enforcement?
    pub fn should_act(&self, sev: Severity) -> bool {
        self.enabled && sev >= self.min_severity
    }

    /// Ensure the nft table/timeout set exists (no-op in dry-run / with a hook).
    pub fn ensure_set(&self) {
        if !self.enabled || self.dry_run || !self.supported || self.hook.is_some() {
            return;
        }
        let _ = Command::new("nft")
            .args(["add", "table", self.family.as_str(), self.table.as_str()])
            .status();
        // `add set ... type ipv4_addr flags timeout` — element set for timed blocks.
        let _ = Command::new("nft")
            .args([
                "add",
                "set",
                self.family.as_str(),
                self.table.as_str(),
                self.set.as_str(),
                "type",
                "ipv4_addr",
                "flags",
                "timeout",
            ])
            .status();
    }

    /// Block `peer` for a policy timeout, with all the never-block guards applied.
    pub fn block(
        &self,
        peer: IpAddr,
        alert_id: &str,
        host: &std::sync::RwLock<HostAddrs>,
        never: &HashSet<IpAddr>,
    ) {
        if !self.enabled || self.severity_lt_guard(peer) {
            return;
        }
        // Guard: never block these classes.
        if is_cloud_metadata(peer) {
            tracing::info!("refusing to block cloud metadata {peer}");
            return;
        }
        {
            let h = host.read().unwrap_or_else(|p| p.into_inner());
            if h.contains(peer) {
                tracing::info!("refusing to block host address {peer}");
                return;
            }
        }
        if never.contains(&peer) {
            tracing::info!("refusing to block protected peer {peer}");
            return;
        }

        // Dedup + cap bookkeeping.
        {
            let mut b = self.blocked.lock().unwrap_or_else(|p| p.into_inner());
            if b.contains(&peer) {
                return;
            }
            if b.len() >= self.max_entries {
                tracing::warn!(
                    "block set at capacity ({}); not blocking {peer}",
                    self.max_entries
                );
                return;
            }
            b.insert(peer);
        }

        if self.dry_run {
            tracing::info!("[dry-run] would block {peer} (alert {alert_id})");
            return;
        }
        if !self.supported {
            tracing::warn!(
                "enforcement unsupported on {}; would block {peer}",
                std::env::consts::OS
            );
            return;
        }

        if let Some(hook) = &self.hook {
            let cmd = hook.replace("{{ip}}", &peer.to_string());
            match Command::new("sh").arg("-c").arg(&cmd).status() {
                Ok(st) if st.success() => tracing::info!("hook blocked {peer} (alert {alert_id})"),
                Ok(st) => tracing::error!("hook for {peer} failed: {st}"),
                Err(e) => tracing::error!("hook spawn failed: {e}"),
            }
            return;
        }

        let ipstr = peer.to_string();
        let timeout = format!("{}s", self.timeout_secs);
        let args = [
            "add",
            "element",
            self.family.as_str(),
            self.table.as_str(),
            self.set.as_str(),
            "{",
            ipstr.as_str(),
            "timeout",
            timeout.as_str(),
            "}",
        ];
        match Command::new("nft").args(args).status() {
            Ok(st) if st.success() => {
                tracing::info!("nft blocked {peer} for {timeout} (alert {alert_id})")
            }
            Ok(st) => tracing::error!("nft add for {peer} failed: {st}"),
            Err(e) => tracing::error!("nft spawn failed: {e}"),
        }
    }

    /// Remove a peer from the block set (`ingressd unblock <ip>`).
    pub fn unblock(&self, peer: IpAddr) -> Result<(), String> {
        {
            let mut b = self.blocked.lock().unwrap_or_else(|p| p.into_inner());
            b.remove(&peer);
        }
        if !self.supported {
            return Err("nftables enforcement is only supported on Linux".into());
        }
        let ipstr = peer.to_string();
        let args = [
            "delete",
            "element",
            self.family.as_str(),
            self.table.as_str(),
            self.set.as_str(),
            "{",
            ipstr.as_str(),
            "}",
        ];
        let st = Command::new("nft")
            .args(args)
            .status()
            .map_err(|e| e.to_string())?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("nft delete failed: {st}"))
        }
    }

    fn severity_lt_guard(&self, _peer: IpAddr) -> bool {
        false
    }
}

fn is_cloud_metadata(ip: IpAddr) -> bool {
    // Local copy avoids pulling the whole scope module signature into the hot path.
    match ip {
        IpAddr::V4(v4) => v4 == std::net::Ipv4Addr::new(169, 254, 169, 254),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd00 && s[1] == 0xec2
        }
    }
}
