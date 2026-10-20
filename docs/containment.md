# Containment operator guide — controlled preview

## Safety boundary

The default deployment **cannot** alter any Kubernetes workload. The `CRG_CONTAINMENT_MODE` variable is unset and no containment RBAC is granted. Enable only on a disposable test cluster with a CNI known to enforce Kubernetes `NetworkPolicy`.

Containment is **pod-wide**, not per-container. It creates a NetworkPolicy selecting one server-verified pod UID via an idempotent label. The policy's `Egress` rules are empty, meaning all outbound connections are denied while the selector matches. It can disrupt DNS, databases, telemetry, and control-plane access. **No automatic action is triggered by a detection:** an administrator must initiate it manually, and affirm `confirm_pod_wide=true`.

A successful Kubernetes API write is not proof of dataplane convergence. Verify blocked connectivity and rollback on your CNI with real cluster tests. This is not suitable for protecting critical production services yet.

## Enable for local simulation

Start a fresh local journal. Set distinct development-only credentials and enable simulation:

```sh
export CRG_INGEST_TOKEN='development-collector-token-very-long'
export CRG_ADMIN_TOKEN='development-admin-token-different-long'
export CRG_CONTAINMENT_MODE=simulate
go run ./cmd/server -addr 127.0.0.1:8080 -data ./data/journal.jsonl
```

Ingest verified-identity-shaped test events (or run the integration tests). Simulation never touches the network. In a strict cluster environment, the server's identity verifier must check actual Kubernetes data before events can create eligible incidents.

```sh
curl -X POST http://127.0.0.1:8080/v1/incidents/INCIDENT_ID/containment \
  -H "Authorization: Bearer $CRG_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"request_id":"manual-001","reason":"Analyst approved test isolation","ttl_seconds":120,"confirm_pod_wide":true}'

curl -H "Authorization: Bearer $CRG_ADMIN_TOKEN" http://127.0.0.1:8080/v1/containments
curl -X DELETE -H "Authorization: Bearer $CRG_ADMIN_TOKEN" http://127.0.0.1:8080/v1/containments/manual-001
```

Requests are durable *desired state* (`requested`) until a controller successfully reconciles them (`applied`). Explicit release and TTL expiry durably record `release_requested` before removing the policy. Only after an acknowledged removal is `released` recorded. Reconciliations are idempotent, and automatic retries handle transient API failures. Historical containment transitions survive ledger replay and snapshots.

## Experimental Kubernetes path

1. Deploy strict ingestion first, following [`kubernetes-identity.md`](kubernetes-identity.md). Never accept unauthenticated workload IDs when real containment is enabled.
2. Apply **optional** `deploy/kubernetes/containment-rbac.yaml` after an access/security review. This grants cross-namespace `pods get/patch` and `networkpolicies get/create/delete` to the server. For narrower access, install separate namespace-scoped Roles in only the namespaces protected.
3. Set the server environment variable `CRG_CONTAINMENT_MODE=kubernetes` and restart only on a disposable cluster. The mode cannot be silently disabled while unresolved containment records exist.
4. Deploy `containment-sweeper.yaml` with its own restricted ServiceAccount to remove expired, ownership-verified NetworkPolicies during main-service outages. The sweeper scans at most 10,000 policies per run (200 pages × 50) and uses Kubernetes object UID preconditions for deletes. It never mutates pods.
5. Test a pod's connectivity before applying the policy, while active, after manual release, after TTL expiry, during controller downtime, and after pod replacement.
6. Alert on `crg_pending_containments`, reconciliation errors, sweeper job failures, and failed policy release. Preserve full journal and segment directory for audit replay.

The sweeper is **best effort**: Kubernetes CronJobs can be delayed or fail, and API availability is required. Native Kubernetes NetworkPolicy has no TTL primitive. Do not rely on expiry as a real-time fail-safe. In an emergency, an authorized operator must delete the CRG-owned policy manually after confirming its ownership and selector. Do not remove unrelated NetworkPolicies.

## Threat model and operational limitations

- The server has no cryptographic attestation of the Tetragon sensor. Per-node bearer tokens and pod API lookup constrain spoofing but do not prevent a compromised node agent from fabricating events about containers on that node.
- A privileged actor who can modify pod labels or network policies can bypass or alter containment. Kubernetes admission policies and RBAC are required beyond this prototype.
- NetworkPolicy isolation behavior is CNI-specific; pre-existing connections, hostNetwork pods, policy propagation and non-compliant CNI implementations require live validation.
- The backend rejects pod UID mismatch and a foreign policy with the same generated name. It does not isolate individual containers.
- A crash between applying a policy and recording `applied` is handled by idempotent reconciliation; a crash after a `release_requested` record is also retried.
- Do not rotate the authoritative ledger away while the server is running. Snapshots and restore must include all segment and containment records.
- This is **single-controller, single-writer** software. There is no validated HA leader election or federated fleet policy plane.

## Local acceptance commands

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
```

Cluster validation remains blocked until a working Kubernetes cluster with network-policy enforcement is available. No code review or local test suite can replace that final verification.
