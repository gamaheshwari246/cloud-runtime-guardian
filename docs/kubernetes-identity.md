# Kubernetes-verified node ingestion (preview)

This is an opt-in, **fail-closed** ingestion boundary. It does not authenticate the kernel, cryptographically attest a node, or provide remote-workload attestation. A compromised node or stolen node credential can forge events for that node. It does bind one HTTPS collector credential to one node and independently checks the **current** Kubernetes API view of the pod UID, container ID, and assigned node before committing an event.

## Security model and availability

1. The node-local collector reads Tetragon JSONL and sends events using a unique `CRG_NODE_TOKEN` over HTTPS. The event must include Tetragon `pod.uid`, pod namespace/name and `container.id`; host-only events are rejected in strict mode.
2. The service locates the credential's assigned node without trusting any node field in the JSON, then checks `host_id` matches the converter's stable node hash.
3. Using its own projected Kubernetes ServiceAccount, the API calls `GET /api/v1/namespaces/{namespace}/pods/{name}` over server-verified HTTPS. It checks live `metadata.uid`, `spec.nodeName`, deletion state and a `containerID` in current regular/init/ephemeral container status. No cached Kubernetes identity is reused.
4. The server replaces the workload identifier with a stable SHA-256-derived `pod UID + container ID` key before durable ingest. Retries of the same source event remain idempotent.
5. Invalid source tokens return HTTP 401; stale/missing/mismatched pods return 409 (the collector stops and requires investigation); API outages/timeouts/permission errors return 503 (the collector retries without advancing its offset). The Kubernetes server is consulted even for idempotent event retries.

Because verification uses current pod status, **delayed events from already deleted/restarted pods cannot be backfilled** through this live ingestion path. Do not bypass it by disabling verification for the same endpoint; a future archival ingestion workflow will need separate authentication and verifiable historical membership. Kubernetes ServiceAccount tokens rotate automatically, so the client re-reads the token from the projected filesystem on every request.

## Server deployment prerequisites

- Apply `deploy/kubernetes/identity-rbac.yaml`, replacing `REPLACE_WITH_NAMESPACE` and ensuring the `ClusterRoleBinding` subject matches the StatefulSet namespace. Its RBAC is `get` on pods only; it does not grant list/watch/write or access to Secrets.
- Prepare a secure `credentials.json` **outside version control**:

```json
{"nodes":[{"node":"worker-1","token":"REPLACE_WITH_A_RANDOM_64_PLUS_CHARACTER_SECRET"}]}
```

  Every Kubernetes node used by a collector needs a distinct 32+ character random token. The node name must match Tetragon `node_name` and Kubernetes `spec.nodeName`. Use a secret-management process for token distribution and rotation; do not put real secrets in YAML or shell history. After updating the projected Secret, send `SIGHUP` to the server PID to atomically reload tokens. Invalid replacements are rejected without clearing the current credential set; confirm rotation from logs before retiring old tokens.
- Create Secrets in the chosen namespace (example commands; use your approved secret management system for production):

```sh
kubectl -n YOUR_NAMESPACE create secret generic crg-node-credentials --from-file=credentials.json=./credentials.json
kubectl -n YOUR_NAMESPACE create secret generic crg-api-credentials --from-literal=admin-token=YOUR_LONG_RANDOM_ADMIN_TOKEN
kubectl -n YOUR_NAMESPACE create secret tls crg-tls --cert=server.crt --key=server.key
kubectl -n YOUR_NAMESPACE create secret generic crg-collector-ca --from-file=ca.crt=./collector-ca.crt
```

- `deploy/kubernetes/server.yaml` enables `CRG_K8S_VERIFY=1`, mounts the credentials Secret `0440` under a dedicated non-root `fsGroup`, and configures TLS. Kubernetes projected secret symlinks are allowed only when they resolve within that mount. The server refuses to start in strict mode without HTTPS, distinct admin authentication, and a valid kube API/service-account configuration.
- Collector: set `CRG_NODE_TOKEN` and run with `-node <exact node name> -endpoint https://<service>:9443/v1/events`; configure trusted server roots on the collector host. The collector never reads the server's Kubernetes API credential.

## Limitations requiring cluster validation

- Tetragon's connection telemetry depends on the installed tracing policy; check actual `process_exec` and `process_connect` export schemas and events. <https://tetragon.io/docs/concepts/events/>
- The live Kubernetes lookup per event costs API requests; it needs rate, capacity, and denial-of-service testing before large fleets. Caching must account for watch continuity, TTL, UID changes, and deletion, and never silently accept stale membership.
- Mutual TLS binds a certificate SAN to the node token, but secure node enrollment, CA rotation, token issuance, boot attestation and revocation need a trusted external identity service.
- Existing `/metrics` requires an administrator token and the application still uses a single-node WAL. Automatic containment is disabled.
- Run end-to-end tests on real Linux nodes, restart pods during ingestion, deliberately revoke API RBAC, rotate projected tokens, and verify no stale events are accepted before considering this production-ready.

## Optional collector mutual TLS (recommended before cluster rollout)

In addition to node-bound bearer credentials, the server can require a client
certificate signed by a **dedicated collector CA**. The certificate must have
**exactly one** URI Subject Alternative Name:

```text
spiffe://cloud-runtime-guardian.local/node/worker-1
```

Replace `worker-1` with the exact Kubernetes node name bound to that collector's
bearer token. Never issue certificates for multiple node identities. Certificates
must include the `clientAuth` extended key usage, and the CA must not be a
public, shared or general-purpose cluster CA.

For strict mode, pass `-collector-ca /etc/crg/collector-ca/ca.crt`, set
`CRG_REQUIRE_COLLECTOR_MTLS=1`, and continue to configure
`CRG_K8S_VERIFY=1`, TLS server certificates and `CRG_NODE_CREDENTIALS_FILE`.
The HTTPS listener verifies client certificates during the TLS handshake; the
event endpoint then checks the verified URI SAN against the authenticated
bearer-token node. Admin clients and Kubernetes probes may omit a client cert,
but may not ingest events. The collector accepts `-client-cert`, `-client-key`
and optional `-ca-cert` (PEM). It still requires its independent node token.

Both cert identity and node token are necessary. Rotate leaf certificate/key files atomically: the collector and server re-load the key pair on each NEW TLS handshake. Keep projected Secret paths stable; update the dedicated CA trust bundle through a controlled rolling restart. Rotate node tokens with a server `SIGHUP` after the Secret volume has updated. Existing connections and requests can finish under old credentials; drain them explicitly if immediate revocation is required. Certificate issuance/enrollment and revocation monitoring are **not**
implemented by this application: integrate a trusted enterprise PKI or a
Kubernetes-native certificate issuer rather than storing a root CA private key
in this repository.

The verifier caps concurrent live Kubernetes pod lookups at 16 per server to
bound API-server load. When saturated it returns retryable HTTP 503; collectors
must retain source logs and checkpoint only after acknowledgment. This does
not constitute a fleet-wide QPS guarantee or replace workload caching and
rate-control planning for a real cluster.
