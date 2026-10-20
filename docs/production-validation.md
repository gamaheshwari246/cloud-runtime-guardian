# Production validation and release gates (not yet certified)

This repository is a **single-node security research prototype** with controlled
staging functionality. Passing the GitHub unit/race suite is NOT evidence of
real-cluster CNI isolation, Linux kernel sensor compatibility, high availability,
or production throughput. Containment is disabled by default.

## Completed offline safety work

- Strict event source authentication: independent node token + verified TLS
  client certificate SAN bound to node. TLS 1.3 is required.
- Atomic node-token rotation on server `SIGHUP`: invalid new credentials leave
  the prior credential set active; no partial rollovers. Existing in-flight
  requests might finish with the earlier credential.
- Server and collector reload certificate/key files on new TLS handshakes;
  CA trust bundle changes still require a planned rollout/restart.
- Bounded sender concurrency and a configurable, bounded load generator.
- Durable WAL, idempotency, snapshot verification, offline restore and audit.
- Linux subprocess crash tests and simulated Kubernetes API containment tests.

## Critical blockers and why

1. **No real multi-node HA.** The write-ahead journal uses an exclusive local
   lock and one replica. Additional API replicas would not coordinate durable
   event IDs, fencing or state. A Kubernetes StatefulSet with one replica
   provides restart recovery on compatible persistent storage, not HA. A future
   HA backend needs a transactionally fenced leader or a distributed durable
   log/database, transactional idempotency, safe ordered replay, failover tests
   and load balancing. DO NOT change `replicas` to >1.
2. **Kubernetes NetworkPolicies are additive.** An empty egress list only
   removes permissions from *that* policy; another selecting policy can allow
   egress. Successful HTTP 201 on a NetworkPolicy is not proof of packet drop.
   `CRG_CONTAINMENT_MODE=kubernetes` is staging-only and additionally requires
   `CRG_EXPERIMENTAL_K8S_CONTAINMENT=1`. Production containment requires a CNI-
   specific deny enforcement mechanism or another fail-safe action, verified
   against actual dataplane traffic and competing allow policies.
3. **No live cluster verification.** Verify Tetragon event fields, missing
   events/ring-buffer loss, source-file rotation, pod recreation/UID churn,
   RBAC, mTLS, policy expiry, node drain and boot-ID rebinding on real hardware.
4. **Retention and volume ceilings.** Snapshots do not permit WAL deletion.
   Per-event Kubernetes API GET and fsync cause throughput bottlenecks. No
   horizontal scaling claims are valid. Deploy with capacity alerts and an
   operational disk reserve.
5. **No complete security review.** Perform dependency/OS-image scanning,
   fuzzing (including TLS/JSON/ZIP parsing), authorized penetration testing,
   supply-chain provenance verification, incident-response tabletop exercises,
   least privilege verification and continuous on-call monitoring.

## Release gate 1: reproducible offline validation

```bash
set -euo pipefail
gofmt -l cmd internal | tee /tmp/crg-unformatted
[ ! -s /tmp/crg-unformatted ]
go vet ./...
go test -race ./...
go build -trimpath ./cmd/...
```

Run a dedicated *non-strict loopback test server* with non-sensitive test data.
Then use the bounded load generator; capture JSON output together with CPU/RAM,
fsync latency, disk utilization, and server logs:

```bash
go run ./cmd/server -addr 127.0.0.1:8080 -data /tmp/crg-soak/journal.jsonl
# another shell: distinct run ID is chosen automatically
go run ./cmd/loadtest -duration 15m -workers 16 -rps 50 \
  -max-error-rate 0.005 -max-p99 500ms
```

This writes ~45,000 events and approaches the default 50,000-event limit.
For longer duration, increase the configured capacity *and provision sufficient
storage*, or start a new clean test dataset after taking a verified snapshot.
At least 24 hours under representative burst traffic are needed before claiming
soak stability. Re-run with 2x, 5x, and 10x of expected per-node ingestion load,
and with 50%/95%/99% full disk pressure and forced restarts. Record artifacts.

## Release gate 2: staging cluster CNI prerequisite

On a **disposable, authorized** cluster with actual CNI policy enforcement:

```bash
CRG_ALLOW_STAGING_CLUSTER_TEST=yes ./scripts/cni-policy-acceptance.sh
```

The script tests a temporary namespace for baseline connectivity, deny-policy
propagation and restoration. It DOES NOT validate the Cloud Runtime Guardian
controller. Repeat the test with an overlapping allow-egress policy and verify
that policy interactions do not invalidate your intended containment semantics.

## Release gate 3: integrated sensor/response acceptance (requires cluster)

- Provision per-node client certificates and tokens using a dedicated, auditable
  identity authority. Do not mount all node tokens into every collector pod.
- Enable the server's mTLS strict mode and check: valid token/certificate/node,
  no certificate, wrong node, expired certificate, rotating secret, and pod
  replacement. Validate clean authentication failure responses and no journal
  append on rejection.
- Confirm Tetragon is actually collecting the required exec/connect events,
  that loss counters are visible, and that the collector handles restart and
  at least two consecutive rotations without silent loss.
- Deploy a disposable victim namespace; authorize one test containment. Verify
  packets are denied at the dataplane (including with overlapping allow policy),
  never just API creation. Verify release, expiry, cleanup and API outage.
- Kill the API process, restart it on the same durable volume, replay journal
  state, ensure exactly one writer and no orphaned enforcement. Test node loss
  and data restoration; record RTO, RPO and any events not recoverable.
- Have independent reviewers approve privilege scope, software supply chain,
  threat model, false positive risk and rollback. Keep active enforcement off
  until all acceptance tests are independently recorded and signed off.

## Observability and fail-safe actions

Alert before journal approaches its configured capacity, on collector source
loss, failed Kubernetes verification, quarantine expiry failures, CNI API
errors, TLS failures, restart loops, and exhausted PVC. Monitor p99 request
latency and event ingestion error rate across representative peak periods.
Never equate a liveness 200 with healthy security coverage.

## Current release decision

**BLOCKED FOR PRODUCTION** until live enforcement, high availability/storage,
long soak and independent security validation pass. Suitable for staging and
controlled local development only.
