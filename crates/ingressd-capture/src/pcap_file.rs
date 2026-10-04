//! Offline `.pcap` replay. Portable (no `libpcap`): uses the crate's own pcap
//! reader and applies backpressure with a blocking send so replays are
//! deterministic — this is the input used by the end-to-end test.
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use ingressd_core::metrics::Counters;
use ingressd_core::pcap::PcapReader;

use crate::{frame_to_event, EventTx, HostHandle};

/// Spawn a thread that replays `path` into `tx`.
pub fn spawn(path: &Path, host: HostHandle, tx: EventTx, counters: Arc<Counters>) -> JoinHandle<()> {
    let path = path.to_path_buf();
    std::thread::Builder::new()
        .name("ingressd-pcap".to_string())
        .spawn(move || run(&path, &host, &tx, &counters))
        .expect("spawn pcap replay thread")
}

/// Read a pcap file and emit scoped events until EOF or the consumer closes.
pub fn run(path: &Path, host: &HostHandle, tx: &EventTx, counters: &Counters) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(path = %path.display(), "cannot open pcap: {e}");
            return;
        }
    };
    let mut reader = match PcapReader::new(BufReader::new(file)) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(path = %path.display(), "invalid pcap: {e}");
            return;
        }
    };
    loop {
        match reader.next_packet() {
            Ok(Some((ts, frame))) => {
                counters.inc_packets(1);
                counters.add_bytes(frame.len() as u64);
                if let Some(ev) = frame_to_event(&frame, ts, host, counters) {
                    if tx.blocking_send(ev).is_err() {
                        break; // consumer dropped
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("pcap replay stopped: {e}");
                break;
            }
        }
    }
}
