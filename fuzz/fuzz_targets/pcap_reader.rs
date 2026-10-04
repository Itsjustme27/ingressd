//! Fuzz the pcap reader: a malformed stream must error, never panic.
#![no_main]

use ingressd_core::pcap::read_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = read_all(data);
});
