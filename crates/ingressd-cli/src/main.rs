//! `ingressd` — the CLI binary: config, runtime wiring, sinks, metrics, reload,
//! and optional enforcement.
#![forbid(unsafe_code)]

mod config;
mod enforce;
mod listener;
mod metrics_server;
mod sinks;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use ipnet::IpNet;

use ingressd_capture::{event_channel, HostHandle};
use ingressd_core::intel::IntelArc;
use ingressd_core::metrics::Counters;
use ingressd_core::scope::HostAddrs;
use ingressd_core::types::PacketEvent;
use ingressd_core::Engine;
use ingressd_intel::{FeedLocation, FeedSpec, Intel};

use config::{parse_cidr, Config, SourceKind};
use enforce::Enforcer;
use sinks::{run_webhook, Sink};

#[derive(Parser)]
#[command(
    name = "ingressd",
    version,
    about = "Passive public-IP traffic threat detector"
)]
struct Cli {
    /// Path to config.toml.
    #[arg(
        long,
        env = "INGRESSD_CONFIG",
        default_value = "/etc/ingressd/config.toml"
    )]
    config: String,
    /// Live capture interface (overrides config; empty = auto-detect default route).
    #[arg(long)]
    iface: Option<String>,
    /// Replay a pcap file (overrides config). Requires no privileges.
    #[arg(long)]
    pcap: Option<String>,
    /// Parse a VPC flow-log file ('-' = stdin) (overrides config).
    #[arg(long)]
    flow_log: Option<String>,
    /// Enable active response even if config has it off.
    #[arg(long)]
    enforce: bool,
    /// Force dry-run on/off.
    #[arg(long)]
    dry_run: Option<bool>,
    /// Validate the effective configuration and exit.
    #[arg(long)]
    check_config: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Remove a peer from the block set.
    Unblock {
        /// Peer IP to unblock.
        ip: String,
    },
    /// Validate a specific config file and exit.
    ValidateConfig {
        /// Path to check.
        path: String,
    },
    /// Write a sample attack+benign pcap (for testing offline detection).
    GenPcap {
        /// Output pcap path.
        out: String,
    },
    /// Emit the Sigma rule pack (multi-document YAML) to stdout for SIEM import.
    Sigma,
    /// Convert a Snort `.rules` file to Sigma YAML (stdout, or to `out`).
    Snort2Sigma {
        /// Input Snort rules file.
        input: String,
        /// Optional output path (default: stdout).
        out: Option<String>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(Command::ValidateConfig { path }) = &cli.command {
        init_tracing("info");
        return match Config::load(path) {
            Ok(_) => {
                println!("config OK: {path}");
                Ok(())
            }
            Err(e) => {
                eprintln!("invalid config:\n{e}");
                std::process::exit(2);
            }
        };
    }

    if let Some(Command::GenPcap { out }) = &cli.command {
        let frames = ingressd_core::gen::attack_scenario();
        let mut w = ingressd_core::pcap::PcapWriter::new(std::io::BufWriter::new(
            std::fs::File::create(out)?,
        ))?;
        for (ts, f) in &frames {
            w.write_packet(*ts, f)?;
        }
        w.flush()?;
        println!("wrote {} packets to {out}", frames.len());
        return Ok(());
    }

    if matches!(cli.command, Some(Command::Sigma)) {
        print!("{}", ingressd_core::sigma::sigma_pack());
        return Ok(());
    }

    if let Some(Command::Snort2Sigma { input, out }) = &cli.command {
        let vars = ingressd_core::snort::VarMap::new();
        let text =
            std::fs::read_to_string(input).map_err(|e| anyhow::anyhow!("read {input}: {e}"))?;
        let yaml = ingressd_core::snort::snort_text_to_sigma(&text, &vars);
        match out {
            Some(p) => {
                std::fs::write(p, yaml)?;
                println!("wrote sigma to {p}");
            }
            None => print!("{yaml}"),
        }
        return Ok(());
    }

    let mut cfg = load_config(&cli).map_err(|e| anyhow::anyhow!(e))?;
    init_tracing(&cfg.log.level);

    if let Some(Command::Unblock { ip }) = &cli.command {
        let ip: IpAddr = match ip.parse() {
            Ok(i) => i,
            Err(e) => {
                eprintln!("bad ip: {e}");
                std::process::exit(2);
            }
        };
        let enf = Enforcer::new(&cfg.enforce, false, Some(false));
        return match enf.unblock(ip) {
            Ok(()) => {
                println!("unblocked {ip}");
                Ok(())
            }
            Err(e) => {
                eprintln!("unblock failed: {e}");
                std::process::exit(1);
            }
        };
    }

    if cli.check_config {
        println!("config OK");
        return Ok(());
    }

    let source = cfg.source().map_err(|e| anyhow::anyhow!(e))?;
    let is_live = source == SourceKind::Live;

    // Host addresses: configured base, plus live interface addresses in live mode.
    let base_hosts: Vec<IpAddr> = cfg
        .general
        .host_ips
        .iter()
        .filter_map(|s| parse_cidr(s))
        .map(|n| n.addr())
        .collect();
    let mut ha = HostAddrs::new();
    ha.set(current_hosts(&base_hosts));
    let host: HostHandle = Arc::new(RwLock::new(ha));

    // Threat intel store (local + cache now, network on refresh ticks).
    let store = Arc::new(Intel::new());
    let specs: Vec<FeedSpec> = build_specs(&cfg);
    let cache = cfg.general.cache_dir.clone();
    let report = store.load_local(&specs, cache.as_deref());
    tracing::info!(entries = report.entries, ok = report.feeds_ok, failed = ?report.failed, "loaded intel (local/cache)");

    let counters = Arc::new(Counters::new());
    counters.set_feed_age(store.age_seconds().unwrap_or(0));
    let intel_arc: IntelArc = Arc::clone(&store) as Arc<_>;
    let geo = load_geo(cfg.intel.geoip_db.as_ref());

    let allowlist: Vec<IpNet> = cfg
        .general
        .allowlist
        .iter()
        .filter_map(|s| parse_cidr(s))
        .collect();
    let sensor = resolve_sensor(&cfg);
    let mut engine = Engine::new(
        &cfg.rules,
        intel_arc.clone(),
        geo.clone(),
        counters.clone(),
        allowlist,
        sensor.clone(),
    );
    engine.set_listening_ports(&listener::listen_ports());
    counters.set_custom_signatures(cfg.rules.signature.len() as u64);
    tracing::info!(rules = ?engine.active_rules(), "detection engine ready");

    let (mut sink, webhook_rx) = Sink::new(&cfg.sinks, counters.clone());
    if let (Some(rx), Some(url)) = (webhook_rx, cfg.sinks.webhook_url.clone()) {
        tokio::spawn(run_webhook(
            rx,
            url,
            cfg.sinks.webhook_token.clone(),
            make_client(),
        ));
    }

    let started = Instant::now();
    let ready = Arc::new(AtomicBool::new(false));

    if cfg.metrics.enabled {
        let addr: SocketAddr = cfg
            .metrics
            .listen
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 9102)));
        let c = Arc::clone(&counters);
        let r = Arc::clone(&ready);
        tokio::spawn(async move {
            if let Err(e) = metrics_server::serve(addr, c, r, started).await {
                tracing::error!("http server: {e}");
            }
        });
    }

    let enforcer = Enforcer::new(&cfg.enforce, false, None);
    enforcer.ensure_set();
    let never_block = never_block_set();

    let (tx, mut rx) = event_channel(cfg.general.channel_capacity);
    let cap_stop = Arc::new(AtomicBool::new(false));
    start_capture(
        &cfg,
        host.clone(),
        tx,
        Arc::clone(&counters),
        cap_stop.clone(),
    )?;
    ready.store(true, Ordering::Relaxed);

    // Signal flags (SIGHUP reload, SIGTERM shutdown) via a dedicated task.
    let stop_now = Arc::new(AtomicBool::new(false));
    let reload_flag = Arc::new(AtomicBool::new(false));
    spawn_signal_task(Arc::clone(&stop_now), Arc::clone(&reload_flag));

    let mut listen_interval =
        tokio::time::interval(Duration::from_secs(cfg.general.refresh_host_secs.max(5)));
    let mut feed_interval =
        tokio::time::interval(Duration::from_secs(cfg.intel.refresh_secs.max(60)));
    let mut poll = tokio::time::interval(Duration::from_millis(500));
    listen_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    feed_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut running = true;
    while running {
        tokio::select! {
            maybe_ev = rx.recv() => match maybe_ev {
                Some(ev) => handle_event(&mut engine, &mut sink, &enforcer, &host, &never_block, ev),
                None => running = false,
            },
            _ = listen_interval.tick() => {
                engine.set_listening_ports(&listener::listen_ports());
                if is_live { refresh_hosts(&host, &base_hosts); }
                counters.set_channel_depth(rx.len() as u64);
            },
            _ = feed_interval.tick() => {
                let r = store.refresh(&specs, cache.as_deref()).await;
                counters.set_feed_age(store.age_seconds().unwrap_or(0));
                tracing::info!(entries = r.entries, failed = ?r.failed, "intel refresh");
            },
            _ = poll.tick() => {
                if stop_now.load(Ordering::Relaxed) { tracing::info!("shutdown requested"); running = false; }
                if reload_flag.swap(false, Ordering::Relaxed) {
                    do_reload(&cli, &mut cfg, &mut engine, &mut sink, &intel_arc, &counters);
                }
            }
        }
    }

    cap_stop.store(true, Ordering::Relaxed);
    write_run_state(cache.as_deref(), &counters, started);
    tracing::info!(
        packets = counters.packets(),
        alerts = counters.alerts_total(),
        "ingressd stopped"
    );
    Ok(())
}

// --------------------------- helpers ---------------------------

fn handle_event(
    engine: &mut Engine,
    sink: &mut Sink,
    enforcer: &Enforcer,
    host: &HostHandle,
    never: &HashSet<IpAddr>,
    ev: PacketEvent,
) {
    let alerts = engine.process(&ev);
    for a in alerts {
        sink.emit(&a);
        if enforcer.should_act(a.severity) {
            enforcer.block(a.peer_ip, &a.id, host, never);
        }
    }
}

fn do_reload(
    cli: &Cli,
    cfg: &mut Config,
    engine: &mut Engine,
    sink: &mut Sink,
    intel: &IntelArc,
    counters: &Arc<Counters>,
) {
    let mut new = match Config::load(&cli.config).map(|c| apply_cli(c, cli)) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("reload: config load failed: {e}");
            return;
        }
    };
    if let Err(e) = new.validate() {
        tracing::error!("reload: config invalid: {}", e.join("; "));
        return;
    }
    let extra = collect_custom_signatures(&new);
    new.rules.signature.extend(extra);
    let geo = load_geo(new.intel.geoip_db.as_ref());
    let allow: Vec<IpNet> = new
        .general
        .allowlist
        .iter()
        .filter_map(|s| parse_cidr(s))
        .collect();
    *engine = Engine::new(
        &new.rules,
        intel.clone(),
        geo,
        counters.clone(),
        allow,
        resolve_sensor(&new),
    );
    engine.set_listening_ports(&listener::listen_ports());
    counters.set_custom_signatures(new.rules.signature.len() as u64);
    let (new_sink, wrx) = Sink::new(&new.sinks, counters.clone());
    *sink = new_sink;
    if let (Some(rx), Some(url)) = (wrx, new.sinks.webhook_url.clone()) {
        tokio::spawn(run_webhook(
            rx,
            url,
            new.sinks.webhook_token.clone(),
            make_client(),
        ));
    }
    *cfg = new;
    tracing::info!("configuration reloaded");
}

fn start_capture(
    cfg: &Config,
    host: HostHandle,
    tx: ingressd_capture::EventTx,
    counters: Arc<Counters>,
    cap_stop: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    match cfg.source().map_err(|e| anyhow::anyhow!(e))? {
        SourceKind::Pcap => {
            let p = cfg
                .general
                .pcap
                .clone()
                .ok_or_else(|| anyhow::anyhow!("pcap source selected but unset"))?;
            ingressd_capture::pcap_file::spawn(&p, host, tx, counters);
            tracing::info!(path = %p.display(), "replaying pcap");
        }
        SourceKind::FlowLog => {
            let p = cfg
                .general
                .flow_log
                .clone()
                .ok_or_else(|| anyhow::anyhow!("flow_log source selected but unset"))?;
            ingressd_capture::flowlog::spawn(&p, host, tx, counters);
            tracing::info!(path = %p.display(), "reading flow logs");
        }
        SourceKind::Live => {
            #[cfg(all(target_os = "linux", feature = "live-capture"))]
            {
                let policy = ingressd_capture::QueuePolicy::parse(&cfg.general.on_queue_full);
                ingressd_capture::afpacket::spawn(
                    &cfg.general.iface,
                    host,
                    tx,
                    counters,
                    cap_stop,
                    policy,
                )
                .map_err(|e| anyhow::anyhow!("live capture: {e}"))?;
                tracing::info!(iface = %iface_or_auto(&cfg.general.iface), queue = %cfg.general.on_queue_full, "live capture running");
            }
            #[cfg(not(all(target_os = "linux", feature = "live-capture")))]
            {
                let _ = (host, tx, counters, cap_stop);
                anyhow::bail!("live capture requires Linux and building with --features live-capture (use --pcap for testing)");
            }
        }
    }
    Ok(())
}

fn iface_or_auto(iface: &str) -> &str {
    if iface.is_empty() {
        "auto"
    } else {
        iface
    }
}

/// Sensor id: config override, else `$HOSTNAME`, else a fallback.
fn resolve_sensor(cfg: &Config) -> String {
    if !cfg.general.sensor_id.is_empty() {
        return cfg.general.sensor_id.clone();
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "ingressd".to_string())
}

/// Configured host IPs plus (in a live, feature-enabled build) the interface's
/// own addresses.
fn current_hosts(base: &[IpAddr]) -> Vec<IpAddr> {
    let mut v = base.to_vec();
    #[cfg(all(target_os = "linux", feature = "live-capture"))]
    {
        let host_addrs = ingressd_capture::afpacket::live_host_addrs();
        v.extend(host_addrs.into_iter());
    }
    v
}

fn refresh_hosts(host: &HostHandle, base: &[IpAddr]) {
    let mut g = host.write().unwrap_or_else(|p| p.into_inner());
    g.set(current_hosts(base));
}

fn build_specs(cfg: &Config) -> Vec<FeedSpec> {
    let mut out = Vec::new();
    for f in &cfg.intel.feeds {
        if !f.enabled {
            continue;
        }
        let loc = match (&f.url, &f.path) {
            (Some(u), _) => FeedLocation::Url(u.clone()),
            (_, Some(p)) => FeedLocation::File(p.clone()),
            (None, None) => continue,
        };
        out.push(FeedSpec {
            name: f.name.clone(),
            location: loc,
        });
    }
    out
}

fn never_block_set() -> HashSet<IpAddr> {
    let mut set: HashSet<IpAddr> = listener::resolver_ips().into_iter().collect();
    for var in ["SSH_CLIENT", "SSH_CONNECTION"] {
        if let Ok(v) = std::env::var(var) {
            if let Some(first) = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<IpAddr>().ok())
            {
                set.insert(first);
            }
        }
    }
    set
}

fn load_config(cli: &Cli) -> Result<Config, String> {
    let base = if Path::new(&cli.config).exists() {
        Config::load(&cli.config)?
    } else {
        tracing::warn!("config '{}' not found; using defaults", cli.config);
        Config::default()
    };
    let cfg = apply_cli(base, cli);
    cfg.validate().map_err(|errs| errs.join("\n"))?;
    let extra = collect_custom_signatures(&cfg);
    let cfg = if extra.is_empty() {
        cfg
    } else {
        let mut c = cfg;
        c.rules.signature.extend(extra);
        c
    };
    Ok(cfg)
}

/// Parse `[custom_signatures]` Snort files/inline rules into engine signatures.
fn collect_custom_signatures(cfg: &Config) -> Vec<ingressd_core::config::SignatureCfg> {
    use ingressd_core::snort;
    let cs = &cfg.custom_signatures;
    if !cs.enabled {
        return Vec::new();
    }
    let mut vars = snort::VarMap::new();
    for (k, v) in &cs.vars {
        vars.set(k, v);
    }
    let mut out = Vec::new();
    for text in &cs.rules {
        out.extend(snort::snort_text_to_signatures(text, &vars));
    }
    for path in &cs.files {
        match snort::load_file(path, &vars) {
            Ok(rules) => {
                let n = rules.len();
                out.extend(rules.iter().filter_map(|r| r.to_signature()));
                tracing::info!(file = %path.display(), rules = n, enforceable = out.len(), "loaded snort rules");
            }
            Err(e) => tracing::warn!("cannot read snort file {}: {e}", path.display()),
        }
    }
    out
}

fn apply_cli(mut cfg: Config, cli: &Cli) -> Config {
    if let Some(i) = &cli.iface {
        cfg.general.iface = i.clone();
        cfg.general.pcap = None;
        cfg.general.flow_log = None;
    }
    if let Some(p) = &cli.pcap {
        cfg.general.pcap = Some(p.into());
        cfg.general.flow_log = None;
        cfg.general.iface.clear();
    }
    if let Some(f) = &cli.flow_log {
        cfg.general.flow_log = Some(f.into());
        cfg.general.pcap = None;
        cfg.general.iface.clear();
    }
    if cli.enforce {
        cfg.enforce.enabled = true;
    }
    if let Some(d) = cli.dry_run {
        cfg.enforce.dry_run = d;
    }
    cfg
}

fn load_geo(path: Option<&std::path::PathBuf>) -> ingressd_core::intel::GeoArc {
    match path {
        #[cfg(feature = "geoip")]
        Some(p) => match ingressd_intel::GeoDb::open(p) {
            Ok(db) => {
                tracing::info!(path = %p.display(), "geoip db loaded");
                Some(Arc::new(db) as Arc<dyn ingressd_core::intel::GeoSource>)
            }
            Err(e) => {
                tracing::warn!("geoip db open failed: {e}");
                None
            }
        },
        #[cfg(not(feature = "geoip"))]
        Some(p) => {
            tracing::warn!(
                "geoip_db set ({}), but binary built without --features geoip; ignoring",
                p.display()
            );
            None
        }
        None => None,
    }
}

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("ingressd/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
}

/// Persist a lightweight run-state snapshot for audit/retention on shutdown.
fn write_run_state(cache_dir: Option<&std::path::Path>, counters: &Counters, started: Instant) {
    let Some(dir) = cache_dir else { return };
    let path = dir.join("ingressd_state.json");
    let state = serde_json::json!({
        "schema_version": 1,
        "exit_time": chrono::Utc::now().to_rfc3339(),
        "uptime_s": started.elapsed().as_secs(),
        "packets": counters.packets(),
        "bytes": counters.bytes(),
        "parse_errors": counters.parse_errors(),
        "drops": counters.drops(),
        "skipped_nonpublic": counters.skipped_nonpublic(),
        "evictions": counters.evictions(),
        "alerts_total": counters.alerts_total(),
        "tracked_keys": counters.tracked_keys(),
        "feed_age_s": counters.feed_age(),
    });
    match serde_json::to_vec_pretty(&state) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&path, bytes) {
                tracing::warn!("failed to write run state {}: {e}", path.display());
            }
        }
        Err(e) => tracing::warn!("failed to serialize run state: {e}"),
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let default = format!("warn,ingressd={level}");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}

/// Spawn a task that sets shutdown/reload flags on SIGTERM/SIGHUP. On non-Unix
/// this is a no-op (there is no service manager sending those signals).
#[cfg(unix)]
fn spawn_signal_task(stop_now: Arc<AtomicBool>, reload_flag: Arc<AtomicBool>) {
    tokio::spawn(async move {
        match unix_signals() {
            Ok((mut term, mut int, mut hup)) => loop {
                tokio::select! {
                    _ = term.recv() => { stop_now.store(true, Ordering::Relaxed); break; }
                    _ = int.recv() => { stop_now.store(true, Ordering::Relaxed); break; }
                    _ = hup.recv() => { reload_flag.store(true, Ordering::Relaxed); }
                }
            },
            Err(e) => {
                tracing::warn!("signal setup failed ({e}); reload/shutdown via signals unavailable")
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_signal_task(_stop_now: Arc<AtomicBool>, _reload_flag: Arc<AtomicBool>) {}

#[cfg(unix)]
fn unix_signals() -> anyhow::Result<(
    tokio::signal::unix::Signal,
    tokio::signal::unix::Signal,
    tokio::signal::unix::Signal,
)> {
    use tokio::signal::unix::{signal, SignalKind};
    Ok((
        signal(SignalKind::terminate())?,
        signal(SignalKind::interrupt())?,
        signal(SignalKind::hangup())?,
    ))
}
