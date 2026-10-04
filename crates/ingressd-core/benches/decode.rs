//! Decode-path microbenchmarks (`cargo bench -p ingressd-core`).

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ingressd_core::decode::decode_frame;
use ingressd_core::gen;

fn bench_decode(c: &mut Criterion) {
    let syn = gen::tcp(gen::attacker(1), gen::HOST, 40000, 22, gen::TCP_SYN, 0);
    let data = gen::udp(gen::HOST, gen::attacker(8), 51000, 53, b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03sub\x07example\x03org\x00\x00\x01\x00\x01");
    let icmp = gen::icmp_echo(gen::attacker(5), gen::HOST, 8, 60);

    let mut g = c.benchmark_group("decode");
    g.bench_function("tcp_syn", |b| {
        b.iter(|| decode_frame(black_box(&syn)).is_ok())
    });
    g.bench_function("udp_dns", |b| {
        b.iter(|| decode_frame(black_box(&data)).is_ok())
    });
    g.bench_function("icmp", |b| {
        b.iter(|| decode_frame(black_box(&icmp)).is_ok())
    });

    // Whole synthetic scenario build cost (not the decoder, but the harness).
    g.bench_function("scenario_build", |b| {
        b.iter(|| black_box(gen::attack_scenario().len()))
    });
    g.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
