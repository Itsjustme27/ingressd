#!/usr/bin/env bash
#
# install.sh — build and install ingressd as a hardened systemd service.
# Creates a dedicated `ingressd` user and grants only CAP_NET_RAW via file
# capabilities. Run as root on the target Linux VM (Ubuntu 22.04/24.04, Debian 12).
#
#   sudo apt-get install -y libcap2-bin   # provides setcap
#   sudo ./deploy/install.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="${BIN_SRC:-$REPO_ROOT/target/release/ingressd}"
FEATURES="${FEATURES:-live-capture}"
PREFIX="${PREFIX:-/usr}"   # installs to /usr/bin/ingressd (matches the systemd unit + AppArmor profile)

USER_NAME=ingressd
STATE_DIR=/var/lib/ingressd
LOG_DIR=/var/log/ingressd
CONF_DIR=/etc/ingressd

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }

cd "$REPO_ROOT"

need cargo
need setcap

say "building ingressd (features: ${FEATURES:-none})"
cargo build --release --features "$FEATURES"

if [ ! -f "$BIN_SRC" ]; then
  echo "expected binary at $BIN_SRC after build" >&2
  exit 1
fi

say "creating service user '$USER_NAME'"
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$USER_NAME"
fi

say "installing directories"
install -d -m 0755 "$PREFIX/bin" "$CONF_DIR" "$STATE_DIR" "$LOG_DIR"

say "installing binary + file capabilities"
install -m 0755 "$BIN_SRC" "$PREFIX/bin/ingressd"
# Non-root process keeps only CAP_NET_RAW (capture). Re-add NET_ADMIN only if enforcing.
setcap 'cap_net_raw=ep' "$PREFIX/bin/ingressd"
chown "$USER_NAME:$USER_NAME" "$STATE_DIR" "$LOG_DIR"

# Optional AppArmor: install a deny-by-default profile when the tooling exists.
# Enable confinement by uncommenting AppArmorProfile= in the systemd unit.
if command -v apparmor_parser >/dev/null 2>&1; then
  install -m 0644 "$REPO_ROOT/deploy/apparmor/ingressd" /etc/apparmor.d/ingressd
  if apparmor_parser -r /etc/apparmor.d/ingressd; then
    say "loaded AppArmor profile 'ingressd' (set AppArmorProfile=ingressd in the unit to confine)"
  else
    say "WARNING: apparmor_parser rejected the profile; skipping confinement"
  fi
fi

if [ ! -f "$CONF_DIR/config.toml" ]; then
  say "installing default config to $CONF_DIR/config.toml"
  install -m 0640 "$REPO_ROOT/config.example.toml" "$CONF_DIR/config.toml"
  chown root:"$USER_NAME" "$CONF_DIR/config.toml"
else
  say "keeping existing $CONF_DIR/config.toml"
fi

say "installing systemd unit"
install -m 0644 "$REPO_ROOT/deploy/ingressd.service" /etc/systemd/system/ingressd.service

say "enabling and starting ingressd"
systemctl daemon-reload
systemctl enable --now ingressd

say "done"
cat <<EOF

Next steps:
  systemctl status ingressd
  journalctl -u ingressd -f              # live alerts (JSONL on stdout)
  curl -s http://127.0.0.1:9102/metrics  # Prometheus counters
  sudo $PREFIX/bin/ingressd unblock <ip>  # revert an enforcement action
  sudo $PREFIX/bin/ingressd --config $CONF_DIR/config.toml --pcap /path/to/sample.pcap  # offline test

Enable enforcement by setting [enforce] enabled=true (start with dry_run=true).
EOF
