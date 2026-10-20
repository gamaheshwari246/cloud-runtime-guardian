#!/usr/bin/env bash
# Reproducible staging-only service / load / backup / restore verification.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v curl >/dev/null || { echo 'curl required' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 required' >&2; exit 2; }
tmp="$(mktemp -d)"
pid=''
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
mkdir -p "$tmp/live" "$tmp/backup"
go build -o "$tmp/crg-server" ./cmd/server
go build -o "$tmp/crg-ledgerctl" ./cmd/ledgerctl
go build -o "$tmp/crg-loadtest" ./cmd/loadtest
port="${CRG_TEST_PORT:-$(python3 -c 'import socket; s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')}"
"$tmp/crg-server" -addr "127.0.0.1:${port}" -data "$tmp/live/journal.jsonl" >"$tmp/server.log" 2>&1 &
pid=$!
ready=0
for i in $(seq 1 100); do
  if curl --max-time 1 -fsS "http://127.0.0.1:${port}/readyz" >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$pid" 2>/dev/null; then cat "$tmp/server.log" >&2; exit 1; fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then cat "$tmp/server.log" >&2; exit 1; fi
if ! "$tmp/crg-loadtest" -endpoint "http://127.0.0.1:${port}/v1/events" \
  -duration 3s -workers 8 -rps 45 -max-error-rate 0 -max-p99 1s > "$tmp/load.json"; then
  cat "$tmp/load.json" "$tmp/server.log" >&2
  exit 1
fi
curl -fsS "http://127.0.0.1:${port}/v1/stats" > "$tmp/original.json"
kill "$pid"
wait "$pid" || :
pid=''
"$tmp/crg-ledgerctl" -data "$tmp/live/journal.jsonl" -snapshot "$tmp/backup/crg-test.crg-snapshot.zip"
"$tmp/crg-ledgerctl" -verify-snapshot "$tmp/backup/crg-test.crg-snapshot.zip"
"$tmp/crg-ledgerctl" -restore-snapshot "$tmp/backup/crg-test.crg-snapshot.zip" -restore-dir "$tmp/restored"
"$tmp/crg-server" -addr "127.0.0.1:${port}" -data "$tmp/restored/journal.jsonl" >"$tmp/restored.log" 2>&1 &
pid=$!
ready=0
for i in $(seq 1 100); do
  if curl --max-time 1 -fsS "http://127.0.0.1:${port}/readyz" >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$pid" 2>/dev/null; then cat "$tmp/restored.log" >&2; exit 1; fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then cat "$tmp/restored.log" >&2; exit 1; fi
curl -fsS "http://127.0.0.1:${port}/v1/stats" > "$tmp/restored.json"
python3 - "$tmp/original.json" "$tmp/restored.json" <<'PY'
import json,sys
old,new=[json.load(open(p)) for p in sys.argv[1:]]
assert old==new,(old,new)
print('PASS: service ingestion and backup/restore state equality:',old)
PY
cat "$tmp/load.json"
