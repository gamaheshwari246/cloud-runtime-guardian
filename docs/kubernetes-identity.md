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

  Every Kubernetes node used by a collector needs a distinct 32+ character random token. The node name must match Tetragon `node_name` and Kubernetes `spec.nodeName`. Use a secret-management process for token distribution and rotation; do not put real secrets in YAML or shell history. Restart the API process after credential-map changes.
- Create Secrets in the chosen namespace (example commands; use your approved secret management system for production):

```sh
kubectl -n YOUR_NAMESPACE create secret generic crg-node-credentials --from-file=credentials.json=./credentials.json
kubectl -n YOUR_NAMESPACE create secret generic crg-api-credentials --from-literal=admin-token=YOUR_LONG_RANDOM_ADMIN_TOKEN
kubectl -n YOUR_NAMESPACE create secret tls crg-tls --cert=server.crt --key=server.key
```

- `deploy/kubernetes/server.yaml` enables `CRG_K8S_VERIFY=1`, mounts the credentials Secret `0440` under a dedicated non-root `fsGroup`, and configures TLS. Kubernetes projected secret symlinks are allowed only when they resolve within that mount. The server refuses to start in strict mode without HTTPS, distinct admin authentication, and a valid kube API/service-account configuration.
- Collector: set `CRG_NODE_TOKEN` and run with `-node <exact node name> -endpoint https://<service>:9443/v1/events`; configure trusted server roots on the collector host. The collector never reads the server's Kubernetes API credential.

## Limitations requiring cluster validation

- Tetragon's connection telemetry depends on the installed tracing policy; check actual `process_exec` and `process_connect` export schemas and events. <https://tetragon.io/docs/concepts/events/>
- The live Kubernetes lookup per event costs API requests; it needs rate, capacity, and denial-of-service testing before large fleets. Caching must account for watch continuity, TTL, UID changes, and deletion, and never silently accept stale membership.
- Token-based node origin is weaker than certificate-bound mTLS node identities. Migration to SPIFFE/SPIRE or scoped mTLS certificates, source-bound boot attestations, and secure node enrollment are future work.
- Existing `/metrics` requires an administrator token and the application still uses a single-node WAL. Automatic containment is disabled.
- Run end-to-end tests on real Linux nodes, restart pods during ingestion, deliberately revoke API RBAC, rotate projected tokens, and verify no stale events are accepted before considering this production-ready.
