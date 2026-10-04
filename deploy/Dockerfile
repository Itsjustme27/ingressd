# syntax=docker/dockerfile:1
# Build a static ingressd with live capture + GeoIP, run in a minimal image.
FROM rust:1.81 AS build
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools \
 && rustup target add x86_64-unknown-linux-musl
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY config.example.toml ./config.example.toml
# Vendored deps are not required; crates.io is fetched at build time.
RUN cargo build --release --locked --target x86_64-unknown-linux-musl --features live-capture,geoip

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/ingressd /usr/bin/ingressd
# Base config; mount your real config.toml over /etc/ingressd.
COPY --from=build /src/config.example.toml /etc/ingressd/config.toml
USER 65532:65532
EXPOSE 9102
# CAP_NET_RAW is granted at the container orchestrator level (see compose/k8s),
# NOT baked into the image, so the same image can run unprivileged for --pcap.
ENTRYPOINT ["/usr/bin/ingressd", "--config", "/etc/ingressd/config.toml"]
