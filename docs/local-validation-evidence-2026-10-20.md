# Local hardening validation — 2026-10-20

## Scope

Single-process, loopback-only Go server on a development container. Generated
`process.exec` and `network.connect` events use benign executables and a
documentation-only destination. No real network destination was contacted by
the generated events. No Kubernetes cluster, eBPF probe or CNI was involved.

## Verified release checks

- `go test ./...`, `go test -race ./...`, `go vet ./...` and
  `go build -trimpath ./cmd/...`: passed locally.
- `scripts/verify-local-release.sh`: passed ingestion, snapshot verification,
  restore and exact state equality after service restart.
- GitHub Actions on commit `1c8661a31af666d8173fa941c5f881193953b7ff`:
  completed successfully; [workflow run](https://github.com/gamaheshwari246/cloud-runtime-guardian/actions/runs/39404084358).

## Bounded sustained-ingestion run

- Duration: **75 seconds**
- Target rate: **150 requests/second**, 24 load-generator workers
- Total requests: **11,249**
- Acknowledged: **11,249**
- Failed: **0**
- Achieved rate: **149.985 requests/second**
- Observed latency histogram: **p95 2 ms, p99 4 ms**, millisecond buckets
- Server resident memory near end of run: **18,100 KiB**
- Committed journal storage: **3,797,360 bytes**
- After restarting the server: **11,249 events recovered**, identical stats

Command:

```sh
go run ./cmd/loadtest \
  -endpoint http://127.0.0.1:18592/v1/events \
  -duration 75s -rps 150 -workers 24 \
  -max-error-rate 0.01 -max-p99 1s
```

## What these results do NOT establish

This was a short, benign synthetic test and is **not a production capacity
benchmark or availability certification**. It did not exercise verified
Kubernetes identities, CNI policy enforcement, incident-producing attack
sequences, authentic sensor event bursts, mTLS handshake performance, pod churn,
disk saturation, multi-node failover, 24-hour soak, or adversarial security
testing. Do not extrapolate its latency or memory numbers to production.

See [production validation gates](production-validation.md) for the remaining
release blockers and real-cluster acceptance requirements.
