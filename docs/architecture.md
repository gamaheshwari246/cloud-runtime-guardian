# Architecture and detection semantics

```text
   simulated / future kernel events
               |
               v
      POST /v1/events (Go)
      validate + idempotency
               |
               v
      append-only journal -- fsync before HTTP 202
               |
               v
      scope partition (host + boot + workload)
               |
               v
      5-minute event-time correlation
               |
               v
      deterministic incident identifier
               |
          +----+----+
          |         |
       query API   response proposal API
                    (audit ONLY; no enforcement)
```

## Event contract

The API accepts exactly two event types:

- `process.exec`: process `entity_id`, PID, and `executable`.
- `network.connect`: process `entity_id`, PID, and `network` containing destination IP, port, and `tcp` or `udp`.

Both require `id`, `occurred_at` (RFC3339), `host_id`, `boot_id`, and `workload.id`. Optional metadata: `workload.namespace`, `workload.pod`, `workload.container_id`, and `process.parent_entity_id`.

The `process.entity_id` **must be stable during one process lifetime and unique after PID reuse**; for a future Linux probe, generate it from the host/boot epoch, process PID, and kernel process start time. Merely passing the numeric PID as the entity ID is incorrect. `boot_id` disambiguates process identities across reboots. `workload.id` must be a workload/container identity, not merely a pod IP. Until live identity verification exists, this is an untrusted assertion from the event producer.

## The v1 rule

Rule: `shell_external_egress`.

An incident is created when:

1. A `process.exec` event has a known shell executable (`sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, or `fish`).
2. A `network.connect` event targets an apparently external IP.
3. The events share **host ID, boot ID, and workload ID**.
4. The network event has the same process entity ID as the shell event, or its `parent_entity_id` is the shell's entity ID.
5. The connection's event time is **after** execution and no later than 5 minutes afterward.

The events may **arrive in either order**; matching always uses their timestamps. Incident ID is derived deterministically from rule ID and both source event IDs. This avoids duplicate incident creation on identical event replay.

**Limitations of the rule:** This is correlation, not proof of malware. Executable names can be spoofed, some legitimate shell sessions connect externally, and the engine cannot determine whether the shell is an approved administrative action. The next iteration needs trusted executable metadata, workload-specific rules, and alert suppression/exception handling.

## Crash behavior and correctness

- One lock serializes idempotency checks, journal commits, and in-memory indexing. This favors correctness over throughput in the MVP.
- A write is acknowledged only after durable append and fsync. A failed write puts the journal into a failed state; restart/replay is required.
- On restart, the ledger is replayed to rebuild event IDs, correlation state, incidents, and dry-run response history.
- A trailing non-newline record is treated as an incomplete write and truncated. Corruption of a complete newline-terminated record prevents startup.
- A conflicting payload for an existing event ID or response request ID is rejected with HTTP 409.
- At capacity, new unique events are rejected explicitly rather than silently discarded. Exact duplicates remain idempotently accepted.
- A query obtains a copy of incident structures under a read lock, avoiding races with future inserts.

## Operations and scalability

The current in-memory index stores candidate shell executions and external connections per scope; each new candidate scans possible counterparts within that scope. This is **not a production throughput design**. Before scaling, index by process entity ID, maintain a bounded event-time window, archive old events, and use an efficient state store. Favor explicit event-loss/backpressure metrics over silent drops.

For future true containment, use separate signed policy decisions and a scoped response controller, with testable rollback and control-plane-survivable connectivity. Never promote the current dry-run proposal endpoint to direct enforcement without authorization and safety gates.
