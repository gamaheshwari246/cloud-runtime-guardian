# MVP threat model and risk register

## Trust boundaries

1. **Event producer to API:** Current event source is untrusted; an attacker can claim any host/workload metadata if they have access to the API. Only bind locally while developing, and use an authentication gateway for controlled remote testing.
2. **API to storage:** Input validation limits payload size and identifiers. Accepted events are durable append-only records; disk exhaustion causes explicit failures.
3. **Detector to response:** A detection does not prove compromise. The response endpoint is a proposed action only. It does not call firewall, OS, Kubernetes, or cloud APIs.
4. **Controller to agent (future):** Future commands must be signed, authenticated, authorized, bounded in scope and TTL, and reconciled after restarts.

## Potential failures

| Failure | Current control | Remaining risk |
| --- | --- | --- |
| Duplicate telemetry | Event-id digest / replay-safe dedupe | Bad source IDs may fragment correlated evidence |
| PID reuse | Opaque process entity IDs and boot scope | No producer-side verification yet |
| Out-of-order events | Event-time pairing in either arrival order | Large clock skew and missing events are not fixed |
| Partial journal write | Discard incomplete trailing JSONL record | Storage faults or committed-line corruption require intervention |
| Disk pressure | Maximum event count and explicit HTTP 507 | No byte-based quota, eviction, or archival yet |
| False-positive containment | Enforcement is entirely disabled | Automated response must remain disabled until validated |
| Data exfiltration via logs | No environment/token logging | Telemetry can itself contain sensitive metadata |
| Credential theft | Optional bearer token for lab use | No TLS, RBAC, secret rotation, or identity federation built in |
| Traffic blackhole | No active policy writes | Future enforcement needs TTL, allowlists, and rollback |
| Multi-tenancy | No multi-tenant features | Do not host independent organizations on one instance |

## Security disclosure

Use the repository issue tracker for non-sensitive bug reports. Do not publish exploit details or customer-identifying telemetry in public issues.
