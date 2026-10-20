#!/usr/bin/env bash
# Disposable staging-only CNI NetworkPolicy behavior check.
# This tests the CNI's baseline Kubernetes NetworkPolicy semantics; it does
# NOT test Cloud Runtime Guardian's controller or guarantee isolation against
# other allow policies.
set -euo pipefail
if [[ "${CRG_ALLOW_STAGING_CLUSTER_TEST:-}" != "yes" ]]; then
  echo 'Set CRG_ALLOW_STAGING_CLUSTER_TEST=yes only on an authorized staging cluster.' >&2
  exit 2
fi
command -v kubectl >/dev/null || { echo 'kubectl required' >&2; exit 2; }
ctx="$(kubectl config current-context)"
if [[ -z "$ctx" ]]; then echo 'No Kubernetes context selected' >&2; exit 2; fi
ns="crg-acceptance-$(date +%s)-$$"
echo "Cluster context: $ctx; ephemeral namespace: $ns"
kubectl create namespace "$ns" >/dev/null
cleanup() { kubectl delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || :; }
trap cleanup EXIT
kubectl -n "$ns" run web --image=busybox:1.36 --restart=Never --labels='app=web' -- \
  sh -c 'mkdir -p /www && echo verified >/www/index.html && httpd -f -p 8080 -h /www'
kubectl -n "$ns" run client --image=busybox:1.36 --restart=Never --labels='app=client' -- sleep 3600
kubectl -n "$ns" wait --for=condition=Ready pod/web pod/client --timeout=150s
web_ip="$(kubectl -n "$ns" get pod web -o jsonpath='{.status.podIP}')"
url="http://${web_ip}:8080/"
check_allowed() { kubectl -n "$ns" exec client -- wget -q -T 2 -O - "$url" 2>/dev/null | grep -q 'verified'; }
check_denied() { ! kubectl -n "$ns" exec client -- wget -q -T 2 -O - "$url" >/dev/null 2>&1; }
for n in $(seq 1 12); do if check_allowed; then break; fi; sleep 2; done
if ! check_allowed; then echo 'FAIL: baseline connectivity' >&2; exit 1; fi
cat <<'YAML' | kubectl -n "$ns" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-client-egress
spec:
  podSelector:
    matchLabels: {app: client}
  policyTypes: [Egress]
  egress: []
YAML
for n in $(seq 1 12); do if check_denied; then break; fi; sleep 2; done
if ! check_denied; then echo 'FAIL: CNI did not enforce deny-egress policy' >&2; exit 1; fi
cat <<'YAML' | kubectl -n "$ns" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: overlapping-allow-egress
spec:
  podSelector:
    matchLabels: {app: client}
  policyTypes: [Egress]
  egress:
    - {}
YAML
for n in $(seq 1 12); do if check_allowed; then break; fi; sleep 2; done
if ! check_allowed; then echo 'FAIL: expected additive NetworkPolicy allow, investigate CNI policy precedence' >&2; exit 1; fi
echo 'OBSERVED: another matching allow policy bypasses empty-egress policy (not suitable for definitive isolation)'
kubectl -n "$ns" delete networkpolicy overlapping-allow-egress >/dev/null
for n in $(seq 1 12); do if check_denied; then break; fi; sleep 2; done
if ! check_denied; then echo 'FAIL: deny policy not restored after removing overlap' >&2; exit 1; fi
kubectl -n "$ns" delete networkpolicy deny-client-egress >/dev/null
for n in $(seq 1 12); do if check_allowed; then break; fi; sleep 2; done
if ! check_allowed; then echo 'FAIL: connectivity not restored on policy removal' >&2; exit 1; fi
echo 'PASS: baseline, network-policy denial and recovery (staging CNI semantics only)'
# Demonstrate the *additive* policy limitation explicitly: another matching
# allow policy permits the same connection even while deny-client-egress exists.
# This must never be confused with production-quality containment.
