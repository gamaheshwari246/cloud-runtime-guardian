# Cluster validation and deployment gate

**Current status: not approved for production.** This project has a functioning Go
collector and one heuristic detection rule. A local test pass does not validate
a privileged sensor, Kubernetes identity, zero-loss export, or security efficacy.
Do not enable enforcement; responses remain dry-run only.

## Before provisioning a cluster

1. Use Linux and a documented compatible version of Tetragon. Confirm the
   installed version actually emits the JSON event shapes consumed by
   `internal/tetragon/convert.go` (especially connection events). Unrecognized
   event shapes are deliberately ignored. Never assume deployment is complete
   merely because process execution is observed.
2. Export **one JSON event per line**, append only, with a newline after every
   complete record. Use rename/create log rotation, **not** `copytruncate`.
   The collector uses a same-disk durable JSON checkpoint and requires the
   archived log's inode to remain until fully consumed.
3. Operate the collector on the **same host** as Tetragon. Its host boot ID is
   taken from `/proc/sys/kernel/random/boot_id`; `-node` must match Tetragon's
   `node_name`. Provide a dedicated writable disk path for checkpoints and
   read-only access to Tetragon export files.
4. Limit input file access to the exporting agent and collector. Do not expose
   event logs to unauthenticated users: event metadata is security sensitive.
5. Terminate remote HTTP at a trusted TLS ingress, use a high-entropy
   `CRG_API_TOKEN` only for isolated experiments, and use separate authN/authZ
   and workload identity before any real deployment. `/metrics` requires the
   token if configured; `/healthz` and `/readyz` do not.
6. Keep export and checkpoint retention on persistent local storage. The
   collector will stop on missing/ambiguous archives, malformed target records,
   inode changes that cannot be reconciled, or checkpoint/boot mismatch.
   Alert on collector restarts and stopped processes.

## Local preflight (without a cluster)

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
go run ./cmd/server -addr 127.0.0.1:8080 -data ./data/journal.jsonl
# from another terminal:
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics
```

To test rename rotation using a local export, run collector with `-follow=true`,
append a valid Tetragon line, rename the current JSONL to `file.jsonl.1`,
create a new `file.jsonl`, and append another line. Both events must be ingested
once. Repeat with SIGTERM/restart between rename and the next append. The
collector refuses a transition with multiple archives because without a
rotation manifest it cannot prove none were skipped; archive glob should be
narrow and unused archives removed only after ingestion is confirmed.

## Acceptance gates once a cluster exists

- [ ] Exercise actual Tetragon output across supported kernels and runtimes.
- [ ] Verify process ancestry and outbound connection linkage under PID reuse.
- [ ] Quantify dropped events under real load; detect exporter-side loss.
- [ ] Run rolling agent upgrades and log rotation under continuous event flow.
- [ ] Test network loss, full disks, burst traffic and replica restart.
- [ ] Validate authentication, authorization, secrets, certificate rotation.
- [ ] Replace the bounded JSONL ledger with indexed, segmented durable storage.
- [ ] Establish backup/recovery, incident retention, alerting, and rate SLOs.
- [ ] Measure detection quality (false positives, false negatives, latency).
- [ ] Build and test safe workload-only enforcement with approval and rollback.

**Known correctness limitation:** The current reader supports only one
unambiguous rename/create transition at a time. It cannot guarantee lossless
processing across multiple intervening rotations or silent source-side drops.
This must be addressed by a cursor-based stream or durable sequence manifest
before a production deployment.
