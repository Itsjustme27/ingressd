# Deployment

Build the production binary with live capture (Linux):

```bash
cargo build --release --features live-capture        # add ,geoip for ASN/country
# static musl binary:
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --features live-capture
```

## systemd (single VM)

```bash
sudo apt-get install -y libcap2-bin
sudo ./deploy/install.sh
systemctl status ingressd
journalctl -u ingressd -f
```

`deploy/install.sh` creates a non-root `ingressd` user, installs the binary to
`/usr/bin/ingressd` with `cap_net_raw=ep`, drops other capabilities, installs the
hardened unit (`deploy/systemd/ingressd.service`), loads the AppArmor profile
(`deploy/security/apparmor/ingressd`) when available, and enables the service.

Key unit settings: `User=ingressd`, `AmbientCapabilities=CAP_NET_RAW`,
`CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN`, `NoNewPrivileges`,
`ProtectSystem=strict`, `PrivateTmp`, `RestrictAddressFamilies`, `MemoryMax=380M`,
optional `AppArmorProfile=ingressd` and `AllowedCPUs=`.

## Docker

```bash
docker build -f deploy/Dockerfile -t ingressd .
docker compose -f deploy/docker-compose.yml up -d   # host networking + CAP_NET_RAW
```

Add `NET_ADMIN` to `cap_add` only when `[enforce]` is enabled.

## Kubernetes (DaemonSet)

```bash
kubectl apply -f deploy/k8s/
```

`deploy/k8s/daemonset.yaml` runs one pod per node with `hostNetwork`,
`NET_RAW` only, `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`,
liveness/readiness probes on `/healthz`/`/readyz`, and resource limits.
Config comes from the `ingressd-config` ConfigMap; metrics are scraped via the
headless Service + ServiceMonitor (or `prometheus.io/*` annotations).

## Cloud-specific notes

- **AWS** — the primary ENI (`eth0`) carries the Elastic/public IP; instance
  traffic is visible directly. IMDS `169.254.169.254` is auto-excluded. For
  VPC-wide visibility use **Traffic Mirroring → GWLB** (capture the mirror NIC)
  or point `general.flow_log` at a VPC Flow Log stream. Allowlist ALB/health-check
  and bastion ranges. ingressd adds no security-group rules.
- **GCP** — capture the primary NIC, or use **VPC Flow Logs** for external-peer
  visibility when IPs are NAT'd. Allowlist `130.211.0.0/22` and `35.191.0.0/16`
  (health checks).
- **Azure** — capture the primary NIC or use **NSG/VNet Flow Logs**; allowlist
  the fabric controller `168.63.129.16`. IMDS `169.254.169.254` is excluded.
- **Mirror / TAP** — on physical/virtual taps, list monitored hosts in
  `general.host_ips`; direction and public-scoping derive from them, and traffic
  not involving a listed address is skipped.

## Operations

- **Reload config / rules / feeds:** `systemctl reload ingressd` (SIGHUP).
- **Revert a block:** `ingressd unblock <ip>`.
- **Health:** `curl -s localhost:9102/healthz`, `/readyz`, `/metrics`.
- **Retention:** tune `rotate_max_files` + `retention_days`; ship
  `alerts.jsonl` to your log pipeline.
