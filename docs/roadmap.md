# Engineering roadmap

## Delivered: day-one core

- [x] Go HTTP ingestion for process execution and network connection events
- [x] Strict event validation and safe default bind address
- [x] Stable workload / host / boot / process correlation scopes
- [x] Event-time rule evaluation tolerant of arrival reordering
- [x] Incident records with evidence and deterministic IDs
- [x] Append-only, fsync'd local journal with restart replay
- [x] Idempotent retries and payload-conflict rejection
- [x] Dry-run-only, audited response proposals
- [x] Go race, concurrency, HTTP/security, and recovery tests
- [x] Standalone simulator

## Next: Linux sensor (highest priority)

Implement trusted host, boot and process identity using Linux kernel events. Prefer a real sensor with existing event streaming support for first integration, then write a carefully scoped standalone eBPF CO-RE proof-of-concept.

Acceptance tests:
- [ ] See a short-lived shell even when its lifespan is below a polling interval.
- [ ] Attribute a socket to the correct process when PID reuse is exercised.
- [ ] Distinguish host processes from container processes through cgroup/container identity.
- [ ] Detect and count kernel-to-userspace ring-buffer losses.
- [ ] Process event bursts with bounded agent memory; preserve or explicitly report losses.
- [ ] Handle sensor restart, host reboot, and incompatible kernel capabilities gracefully.

## After sensor: Kubernetes-aware correlation

- [ ] Watch pod/container metadata and verify event-producer identities.
- [ ] Build an authenticated mapping from cgroup/container to workload UID and labels.
- [ ] Resolve multi-generation process lineage.
- [ ] Apply allowlisted workloads and policy-defined egress expectations.
- [ ] Add benign, malicious, and noisy workload regression fixtures.

## After detection: safe response

- [ ] Explicit operator approval and per-workload authorization.
- [ ] Policy versioning, audit signatures, staged rollout, automatic expiry.
- [ ] Isolate only a test workload, not the node, cluster API, or management interface.
- [ ] Reconcile desired vs observed enforcement state after agent restart.
- [ ] Test rollback when enforcement is only partially applied.

## Production-scale work (separate project phases)

- [ ] Bounded indexed state per workload and event-time watermarks.
- [ ] Segmented/WAL-backed storage, compaction, disk-pressure policy and disaster recovery.
- [ ] mTLS, workload identity attestation, tenant isolation, authorization, audit retention.
- [ ] Telemetry volume controls and calibrated detection quality (precision/recall).
- [ ] SLO dashboards: ingestion throughput, end-to-end detection latency, p99, dropped events, false positives.
- [ ] Cross-host attack-path correlation and network flow observability.
- [ ] Benchmark kernel overhead in controlled environments and automate kernel compatibility CI.

**Milestone rule:** No enforcement path should ship before identity integrity, bounded resource usage, auditability, and rollback tests are credible.

## Reliability work (October 2026)

- [x] Resume a single rename/create export rotation after collector restart.
- [x] Reject ambiguous/missing archived records and incomplete rotated lines.
- [x] Expose liveness, readiness, and basic capacity gauges.
- [x] Test rotation, crash/restart, duplicated events and source corruption.
- [ ] Validate actual sensor event payloads and rotate under continuous cluster load.
- [ ] Add durable event sequence manifest or cursor-based streaming for multiple rotations.
- [ ] Segment and index event ledger; eliminate fixed event-capacity exhaustion.
