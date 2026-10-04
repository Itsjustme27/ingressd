#!/usr/bin/env bash
# failopen_test.sh — verify general.on_queue_full behavior under backpressure.
#
#   on_queue_full = "drop"  -> fail-open : process survives, ingressd_drops_total climbs
#   on_queue_full = "exit"  -> fail-closed: process stops (never silently miss traffic)
#
# Force overflow with a tiny channel_capacity while tcpreplay floods the iface.
# Requires the live-capture binary + root/CAP_NET_RAW + tcpreplay + a stress pcap.
#
#   IFACE=eth0 PCAP=/tmp/ingressd-stress.pcap sudo -E ./scripts/failopen_test.sh
set -euo pipefail

IFACE="${IFACE:-eth0}"
BIN="${BIN:-target/release/ingressd}"
PCAP="${PCAP:-/tmp/ingressd-stress.pcap}"
[ -x "$BIN" ] || { echo "build --features live-capture first"; exit 1; }
[ -f "$PCAP" ] || { echo "no pcap at $PCAP (run scripts/stress_test.sh first)"; exit 1; }
command -v tcpreplay >/dev/null 2>&1 || { echo "tcpreplay required"; exit 1; }

mk_conf() { # $1 = policy
  cat <<EOF
[general]
iface = "$IFACE"
channel_capacity = 512
on_queue_full = "$1"
cache_dir = "/tmp/ingressd-fo"
[metrics]
enabled = true
listen = "127.0.0.1:9102"
[sinks]
stdout = false
[log]
level = "warn"
EOF
  mkdir -p /tmp/ingressd-fo
}

run_case() { # $1 = policy ; returns 0 if expected outcome
  local policy="$1" conf=/tmp/ingressd-fo-$policy.toml
  mk_conf "$policy" > "$conf"
  "$BIN" --config "$conf" >/tmp/ingressd-fo-$policy.log 2>&1 &
  local pid=$!
  tcpreplay -i "$IFACE" --pps=120000 --loop=0 "$PCAP" >/dev/null 2>&1 &
  local tcpr=$!
  sleep 8
  kill "$tcpr" 2>/dev/null || true
  local alive=0; kill -0 "$pid" 2>/dev/null && alive=1 || alive=0
  local drops; drops=$(curl -s http://127.0.0.1:9102/metrics | awk '/^ingressd_drops_total/{print $2}')
  kill "$pid" 2>/dev/null || true
  echo "policy=$policy alive=$alive drops=${drops:-0}"
  if [ "$policy" = "drop" ]; then
    [ "$alive" = 1 ] && [ "${drops:-0}" -gt 0 ]     # fail-open: alive, shedding
  else
    [ "$alive" = 0 ]                                 # fail-closed: stopped
  fi
}

echo "==> fail-open (drop)"
run_case drop && echo "PASS drop" || { echo "FAIL drop"; exit 1; }
echo "==> fail-closed (exit)"
run_case exit && echo "PASS exit" || { echo "FAIL exit"; exit 1; }
echo "ALL PASS"
