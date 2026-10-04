//! Fuzz the full frame decoder: any input must parse without panicking.
#![no_main]

use ingressd_core::decode::decode_frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // We only care that decoding is total (no panic / OOB). Result ignored.
    let _ = decode_frame(data);
});
