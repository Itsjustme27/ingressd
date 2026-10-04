//! Fuzz the DNS message parser specifically (label/pointer handling is the
//! highest-risk decoder surface).
#![no_main]

use ingressd_core::decode::parse_dns;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_dns(data);
});
