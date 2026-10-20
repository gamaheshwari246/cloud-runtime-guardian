# Operator runbook (single-node preview)

## Status and boundary

The server + JSONL ledger is designed for **one active writer**. This is not
high availability and is not a complete endpoint security product. Kubernetes
replicas must remain `1`; never run multiple pods against one journal file.
Process/kernel observability still requires Tetragon and a real Linux host.
Automatic containment is disabled. Run the cluster validation in
`docs/cluster-readiness.md` before any broader deployment.

## Local development

```sh
go test ./...
go test -race ./...
go vet ./...
go run ./cmd/server -addr 127.0.0.1:8080 -data ./data/journal.jsonl
```

## Authentication and encrypted transport

Development on loopback can run unauthenticated. For a non-loopback listener,
configure two **different** random values of at least 24 characters:
`CRG_INGEST_TOKEN` is permitted only `POST /v1/events`; `CRG_ADMIN_TOKEN`
grants read access to incidents/metrics and dry-run response proposals.
Use a real certificate with SANs matching the requested hostname:

```sh
CRG_INGEST_TOKEN="$(openssl rand -hex 32)" \
CRG_ADMIN_TOKEN="$(openssl rand -hex 32)" \
  ./crg-server -addr 0.0.0.0:9443 -data /var/lib/crg/journal.jsonl \
    -tls-cert /etc/crg/tls/tls.crt -tls-key /etc/crg/tls/tls.key
```

**Do not run the example with those randomly generated values without saving
and securely distributing the collector token and separate analyst token.**
Secrets belong in a secrets manager / Kubernetes Secret; don't commit them.
`CRG_API_TOKEN` is a backward-compatible **development** credential and does
not satisfy non-loopback deployment requirements.

`GET /healthz` and `GET /readyz` intentionally do not authenticate, so keep
probe access restricted to the cluster. `/metrics` requires the admin token;
do not make it publicly accessible.

## Container and cluster preview

1. Build `docker build -t cloud-runtime-guardian:dev .` and run locally with
   a writable volume and mounted valid TLS certificate/key.
2. Pin the image to a digest in `deploy/kubernetes/server.yaml`.
3. Create Kubernetes secrets `crg-api-credentials` and `crg-tls` securely.
4. Choose and configure a single-node filesystem/PVC that supports `fsync`
   and Linux advisory locks; keep snapshots/backups and restrict PVC access.
5. Review network policies, pod permissions, certificate renewals, and
   liveness/readiness behavior before applying the manifest.
6. Validate restart with existing data, volume reattachment, high-watermark
   capacity, telemetry replay, and failover behavior in a disposable cluster.

**No live Kubernetes deployment is claimed.** The manifest is an untested
single-replica template pending a real cluster.

## Storage faults and recovery

- `journal already has a writer`: stop the conflicting instance; don't force
  unlock or delete the file. Use one leader only.
- `corrupt journal record`: stop ingestion, keep a forensic copy, restore from
  backup or perform deliberate manual repair; do not silently discard lines.
- `journal capacity reached`: stop new unique events before the configured
  bound; increase capacity after assessing memory budget. This is not a log
  compaction or long-term retention feature.
- Missing or ambiguous Tetragon export rotation: collection fails closed to
  protect data integrity; restore retained log files and investigate before
  restarting. Check source-side drop counters separately.
- The replay ledger can have one incomplete tail line removed at boot. A
  successfully fsynced newline-terminated record is treated as committed.
- Back up the journal while the service is **stopped**, or use a filesystem
  snapshot with suitable consistency guarantees; raw copy while running is
  not a guaranteed consistent backup.

## Monitoring and alerts

Readiness is false if the journal is unhealthy or capacity exhausted.
Prometheus-compatible gauges on authenticated `GET /metrics` include:
`crg_events_stored`, `crg_incidents`, `crg_dry_run_responses`,
`crg_event_capacity`, and `crg_ready`.

Alerts should include readiness unavailable, capacity nearing exhaustion,
collector restarts/errors, lag between export file size and checkpoint,
missing telemetry, and unexpected event rate changes. Scrapes require an
admin token and secure network routing. Upstream eBPF drops are not visible
through these gauges; instrument Tetragon separately.

## What the service does NOT guarantee

No durable unlimited-traffic ingestion, fleet upgrades, HA/replication, data
retention/rotation, tenant isolation, incident deduplication across nodes, or
kernel-level prevention. Per-event `fsync` favors correctness over throughput.
Validate sensor coverage, CPU/latency, and data-loss behavior under realistic
load before treating results as security signals for production decisions.

## Indexed query milestone and journal safety

Incident listing has an in-memory AVL index rebuilt entirely from the fsynced
journal. Numeric offsets are supported for existing clients, while
`GET /v1/incidents?limit=50&cursor=` enables stable keyset pagination during
new ingestion. The cursor is opaque and **must not be interpreted as a
security credential**. It is not a consistent multi-request snapshot if
records are deleted in a future release.

The journal rejects a second writer and now fails closed if its pathname is
replaced, truncated, externally appended, or permissions/hardlink count change.
It also rejects multiple JSON values on one replay line. If any guard fires,
stop ingestion, preserve the source ledger, investigate the cause, and restart
after correcting storage conditions. Never automatically reinitialize a
failed ledger. The identity checks do not defend against a hostile process
that already has filesystem write access or against all possible race windows.

Run `go test -race ./...` before release. Tests include a Linux SIGKILL of a
writer subprocess *after fsync*, crash reopening, cursor persistence after
restart, and fail-closed behavior for external inode mutation. There is still
**no** WAL compaction, external database, high availability, online backup, or
validated cluster failure recovery.

## Segmented WAL and lossless offline compaction

The original `-data` path is kept as an immutable-compatible legacy segment.
After it reaches 8 MiB, further writes are made to consecutive numbered files
under `<data>.segments/`, with a durably fsynced `HEAD` high-watermark. A
missing segment or broken sequence is a **startup failure**, not a fresh start.
Only the final active segment may have an incomplete trailing line repaired.
`HEAD` and numbered WAL files are part of one logical database. **Always back
up the original journal and the full `.segments/` directory together**, with
the server stopped or with an application-consistent filesystem snapshot.
Do not let a generic logrotate process touch these files.

The following commands must be run with the server **stopped**. The verifier
locks the same original file as the writer; it refuses another concurrent
writer. Verify and optionally compress only *closed* numbered segments:

```sh
go run ./cmd/ledgerctl -data ./data/journal.jsonl -max-records 100000
# After a separate, restorable backup:
go run ./cmd/ledgerctl -data ./data/journal.jsonl -max-records 100000 -compact-closed
```

Compression uses `fsync(temp)` -> atomic rename to `.wal.gz` -> `fsync(dir)`
-> verification against the original -> delete original -> `fsync(dir)`.
A crash after rename can leave both formats, in which case the next startup
verifies the two copies agree. Corruption in either copy causes startup to
fail closed. Historical IDs and records are never discarded. Re-compressing
an already archived segment does nothing.

**Retention is intentionally indefinite in this release.** Compression
reduces storage space but not replay count or in-memory event capacity. Do not
manually delete archived WAL files to enforce a TTL: that would remove the
idempotency keys and evidence needed for deterministic replay. A future
snapshot/retention milestone must preserve event hashes, incidents, action
history and the correlation window, define legal/audit retention, and include
cross-version restore validation before safe deletion can be enabled.

This remains a single-process ledger, **not** a database with HA, replicated
writes or incremental query indexes on disk. A snapshot of only the base
`.jsonl` file is no longer a complete backup once segments exist.

## Offline verified snapshot, restore, and backup retention

The `ledgerctl` backup format is a bounded ZIP containing `MANIFEST.json`,
`journal.jsonl`, and the full numbered WAL tree. Each file has a SHA-256
checksum and uncompressed byte length in the manifest. ZIP CRCs are checked as
well. A snapshot requires the **exclusive writer lock**: stop the server first.
The tool never deletes WAL records, nor does it reset idempotency keys.

```sh
# Stop the server and collector before taking a consistent offline backup.
mkdir -p ./backups
chmod 700 ./backups

go run ./cmd/ledgerctl -data ./data/journal.jsonl \
  -max-records 2000000 \
  -snapshot ./backups/crg-20261020T120000Z.crg-snapshot.zip

# Integrity and checksum check (does not modify the source ledger):
go run ./cmd/ledgerctl \
  -verify-snapshot ./backups/crg-20261020T120000Z.crg-snapshot.zip

# Restore into a NEW directory, never over an existing ledger. This verifies
# all archive digests and fully replays the WAL before publishing the result.
go run ./cmd/ledgerctl \
  -restore-snapshot ./backups/crg-20261020T120000Z.crg-snapshot.zip \
  -restore-dir ./restore-check

# After manually confirming this restored dataset is usable, use:
go run ./cmd/server -data ./restore-check/journal.jsonl

# Retain 3 newest individually verified archives with the controlled filename
# pattern crg-*.crg-snapshot.zip; leave authoritative WAL untouched.
go run ./cmd/ledgerctl -prune-snapshots-dir ./backups -keep-snapshots 3
```

**Safety notes:** The restore destination must not exist and must be on a
filesystem supporting atomic directory renames and directory fsync. Take
snapshots on a trusted local filesystem, not an untrusted shared mount. Preserve
both the backup and its keys/access controls using independent storage; the
archive includes sensitive telemetry and is only file-permission protected, not
encrypted. Archive creation checks capacity, file permissions, and source
stability, and refuses existing target names. Restore extracts into a private
temporary directory, checks digests, tests full WAL replay, and publishes it
only on success. An interruption before publication leaves only a removable
temporary directory; an interruption after publication leaves an intact
restored directory. Clean up orphan `.crg-restore-*` directories after inspecting
and confirming that no restore is running. Do not use this tool to restore
onto an existing directory, or to take hot backups while the server is running.

Backup retention only deletes matching **successfully verified** backup
archives, keeping at least two. It is not regulatory data retention, a WAL
truncation engine, or a durable state checkpoint for accelerated startup.
The engine still reconstructs its in-memory state from all committed records.
There is deliberately **no event TTL** in this milestone: deleting historical
records would change replay and idempotency semantics. Before implementing
actual ledger retention, design and validate a complete state snapshot
(including event hashes, correlation indexes, incident history, and response
idempotency), migration compatibility, and crash-safe checkpoint handoff.
