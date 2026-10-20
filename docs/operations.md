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
