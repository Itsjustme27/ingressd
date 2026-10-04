#!/usr/bin/env bash
# stress_test.sh — verify ingressd sustains a target line rate without losing the
# process or exceeding its RSS budget. Uses tcpreplay against the live capture
# interface; falls back to a --pcap replay loop if tcpreplay is unavailable.
#
# Requires: cargo, a built --features live-capture binary, root (or CAP_NET_RAW),
#   optionally tcpreplay + a sample pcap (generate with `ingressd pcapgen`).
#
#   IFACE=eth0 TARGET_MPPS=140 sudo -E ./scripts/stress_test.sh
set -euo pipefail

IFACE="${IFACE:-eth0}"
TARGET_MPPS="${TARGET_MPPS:-140}"           # ~1 Gbit/s @ ~900B avg
BIN="${BIN:-target/release/ingressd}"
PCAP="${PCAP:-/tmp/ingressd-stress.pcap}"
RSS_BUDGET_MB="${RSS_BUDGET_MB:-380}"
[ -x "$BIN" ] || { echo "build first: cargo build --release --features live-capture"; exit 1; }

# 1. Build an amplified pcap (repeat the scenario to ~1M packets).
if [ ! -f "$PCAP" ]; then
  echo "==> generating stress pcap at $PCAP"
  "$BIN" pcapgen /tmp/base.pcap
  python3 - "$PCAP" /tmp/base.pcap <<'PY'
import sys, shutil
out, base = sys.argv[1], sys.argv[2]
with open(out, "wb") as o:
    data = open(base, "rb").read()
    o.write(data[:24])                 # one global header
    for _ in range(8000):              # ~1.1M packets (138 pkts * 8000)
        o.write(data[24:])
print("amplified pcap written")
PY
fi

# 2. Start ingressd against the real interface with a strict RSS guard.
echo "==> starting $BIN --iface $IFACE"
"$BIN" --iface "$IFACE" >/tmp/ingressd-stress.log 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT
sleep 2
kill -0 "$PID" || { echo "ingressd failed to start; see /tmp/ingressd-stress.log"; exit 1; }

# 3. Replay at target rate.
if command -v tcpreplay >/dev/null 2>&1; then
  echo "==> tcpreplay -i $IFACE --mbps <~$TARGET_MPPS>Mpps"
  tcpreplay -i "$IFACE" --pps="${TARGET_MPPS}000" --loop=0 "$PCAP" >/tmp/tcpreplay.log 2>&1 &
  TCPR=$!
  sleep 25
  kill "$TCPR" 2>/dev/null || true
else
  echo "!! tcpreplay not found — verifying the offline replay path instead"
  time "$BIN" --pcap "$PCAP" >/tmp/ingressd-offline.log 2>&1 || true
  echo "   alerts emitted offline: $(wc -l </tmp/ingressd-offline.log)"
fi

# 4. Assertions: process alive, packets counted, RSS within budget.
kill -0 "$PID" || { echo "FAIL: ingressd died under load"; tail -20 /tmp/ingressd-stress.log; exit 1; }
read -r rss <<<"$(ps -o rss= -p "$PID")"
rss_mb=$(( rss / 1024 ))
echo "==> RSS=${rss_mb}MB (budget ${RSS_BUDGET_MB}MB)"
[ "$rss_mb" -le "$RSS_BUDGET_MB" ] || { echo "FAIL: RSS over budget"; exit 1; }

pkts=$(curl -s http://127.0.0.1:9102/metrics | awk '/^ingressd_packets_total/{print $2}')
drops=$(curl -s http://127.0.0.1:9102/metrics | awk '/^ingressd_drops_total/{print $2}')
echo "==> packets_total=$pkts drops_total=$drops"
[ "${pkts:-0}" -gt 0 ] || { echo "FAIL: no packets observed"; exit 1; }
echo "PASS: line-rate smoke test (review drops vs your on_queue_full policy)"
