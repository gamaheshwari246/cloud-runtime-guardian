package containment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"cloudruntimeguardian/internal/identity"
	"cloudruntimeguardian/internal/model"
)

// KubernetesBackend applies a pod-wide deny-egress NetworkPolicy, not a
// container-specific rule. It requires a CNI that enforces Kubernetes policies.
// A successfully accepted API request does not prove dataplane enforcement.
type KubernetesBackend struct {
	BaseURL string
	Client  *http.Client
	Token   func() (string, error)
	Pods    identity.Resolver
}

var dnsName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

const labelKey = "security.cloudruntimeguardian.dev/containment"

func NewInClusterBackend(pods identity.Resolver) (*KubernetesBackend, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = "443"
	}
	if host == "" {
		return nil, errors.New("Kubernetes service host missing")
	}
	ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid Kubernetes CA")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second}
	return &KubernetesBackend{BaseURL: "https://" + net.JoinHostPort(host, port), Client: &http.Client{Transport: tr, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Pods: pods,
		Token: func() (string, error) {
			b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
			if err != nil {
				return "", err
			}
			if len(b) < 8 || len(b) > 65536 {
				return "", errors.New("invalid service-account token")
			}
			return strings.TrimSpace(string(b)), nil
		}}, nil
}

func policyName(c model.Containment) string {
	h := sha256.Sum256([]byte(c.ID + "\x00" + c.Workload.PodUID))
	return "crg-egress-" + hex.EncodeToString(h[:12])
}
func labelValue(c model.Containment) string { return strings.TrimPrefix(policyName(c), "crg-egress-") }
func (b *KubernetesBackend) validate(c model.Containment) error {
	if b == nil || b.Client == nil || b.Pods == nil || b.Token == nil || !strings.HasPrefix(b.BaseURL, "https://") {
		return errors.New("Kubernetes backend unconfigured")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Mode != "kubernetes" || !dnsName.MatchString(c.Workload.Namespace) || len(c.Workload.Namespace) > 63 || !dnsName.MatchString(c.Workload.Pod) || len(c.Workload.Pod) > 253 {
		return errors.New("invalid Kubernetes containment target")
	}
	return nil
}
func (b *KubernetesBackend) do(ctx context.Context, method, path string, body any, contentType string) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	u, err := url.Parse(b.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return 0, nil, errors.New("invalid API server URL")
	}
	req, err := http.NewRequestWithContext(ctx, method, b.BaseURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	token, err := b.Token()
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := b.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10+1))
	if err != nil {
		return 0, nil, err
	}
	if len(result) > 256<<10 {
		return 0, nil, errors.New("Kubernetes response too large")
	}
	return resp.StatusCode, result, nil
}
func podPath(c model.Containment) string {
	return "/api/v1/namespaces/" + url.PathEscape(c.Workload.Namespace) + "/pods/" + url.PathEscape(c.Workload.Pod)
}
func policyPath(c model.Containment) string {
	return "/apis/networking.k8s.io/v1/namespaces/" + url.PathEscape(c.Workload.Namespace) + "/networkpolicies"
}
func escapeJSONPointer(k string) string {
	return strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
}

func (b *KubernetesBackend) verifyPod(ctx context.Context, c model.Containment) (identity.Pod, error) {
	pod, err := b.Pods.LookupPod(ctx, c.Workload.Namespace, c.Workload.Pod)
	if err != nil {
		return pod, err
	}
	if pod.UID != c.Workload.PodUID || pod.Deleting || pod.Namespace != c.Workload.Namespace || pod.Name != c.Workload.Pod || pod.Node == "" {
		return pod, errors.New("pod UID or lifecycle changed; refuse enforcement")
	}
	found := false
	for _, id := range pod.ContainerIDs {
		if id == c.Workload.ContainerID {
			found = true
		}
	}
	if !found {
		return pod, errors.New("target container no longer exists in pod")
	}
	return pod, nil
}

func (b *KubernetesBackend) expectedPolicy(c model.Containment) map[string]any {
	return map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
		"metadata": map[string]any{
			"name": policyName(c), "namespace": c.Workload.Namespace,
			"labels":      map[string]string{"app.kubernetes.io/managed-by": "cloud-runtime-guardian"},
			"annotations": map[string]string{"security.cloudruntimeguardian.dev/containment-id": c.ID, "security.cloudruntimeguardian.dev/pod-uid": c.Workload.PodUID, "security.cloudruntimeguardian.dev/expires-at": c.ExpiresAt.Format(time.RFC3339Nano)},
		},
		"spec": map[string]any{"podSelector": map[string]any{"matchLabels": map[string]string{labelKey: labelValue(c)}}, "policyTypes": []string{"Egress"}, "egress": []any{}},
	}
}
func (b *KubernetesBackend) Ensure(ctx context.Context, c model.Containment) error {
	if err := b.validate(c); err != nil {
		return err
	}
	if !time.Now().Before(c.ExpiresAt) {
		return errors.New("containment already expired")
	}
	pod, err := b.verifyPod(ctx, c)
	if err != nil {
		return err
	}
	if marker := pod.Labels[labelKey]; marker != "" && marker != labelValue(c) {
		return errors.New("pod already carries another containment marker")
	}
	// Install the policy before labeling the pod. If the second step fails,
	// a leftover policy matches no new target until a subsequent successful patch.
	expected := b.expectedPolicy(c)
	status, _, err := b.do(ctx, "POST", policyPath(c), expected, "application/json")
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		status, raw, getErr := b.do(ctx, "GET", policyPath(c)+"/"+policyName(c), nil, "")
		if getErr != nil {
			return getErr
		}
		if status != http.StatusOK {
			return fmt.Errorf("verify existing NetworkPolicy: HTTP %d", status)
		}
		var existing struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				PodSelector struct {
					MatchLabels map[string]string `json:"matchLabels"`
				} `json:"podSelector"`
				PolicyTypes []string `json:"policyTypes"`
				Egress      []any    `json:"egress"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &existing); err != nil {
			return err
		}
		annotations := existing.Metadata.Annotations
		if annotations["security.cloudruntimeguardian.dev/containment-id"] != c.ID || annotations["security.cloudruntimeguardian.dev/pod-uid"] != c.Workload.PodUID || annotations["security.cloudruntimeguardian.dev/expires-at"] != c.ExpiresAt.Format(time.RFC3339Nano) ||
			len(existing.Spec.PodSelector.MatchLabels) != 1 || existing.Spec.PodSelector.MatchLabels[labelKey] != labelValue(c) || len(existing.Spec.PolicyTypes) != 1 || existing.Spec.PolicyTypes[0] != "Egress" || len(existing.Spec.Egress) != 0 {
			return errors.New("existing policy conflicts with expected containment; refuse to modify")
		}
	} else if status != http.StatusCreated {
		return fmt.Errorf("create NetworkPolicy: HTTP %d", status)
	}

	// JSON Patch CAS on pod UID ensures a same-name replacement is not labeled.
	// A pod without metadata.labels is rejected; never replace its label map.
	ops := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": c.Workload.PodUID},
		{"op": "add", "path": "/metadata/labels/" + escapeJSONPointer(labelKey), "value": labelValue(c)}}
	status, _, err = b.do(ctx, "PATCH", podPath(c), ops, "application/json-patch+json")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("label target pod (UID CAS): HTTP %d", status)
	}
	return nil
}
func (b *KubernetesBackend) Release(ctx context.Context, c model.Containment) error {
	if err := b.validate(c); err != nil {
		return err
	}
	// Unlabel first for rapid unblocking. If the pod was replaced, do not
	// mutate the new one. The policy is namespaced and owned by this record.
	pod, err := b.Pods.LookupPod(ctx, c.Workload.Namespace, c.Workload.Pod)
	if err == nil && pod.UID == c.Workload.PodUID && pod.Labels[labelKey] == labelValue(c) {
		ops := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": c.Workload.PodUID},
			{"op": "test", "path": "/metadata/labels/" + escapeJSONPointer(labelKey), "value": labelValue(c)},
			{"op": "remove", "path": "/metadata/labels/" + escapeJSONPointer(labelKey)}}
		status, _, patchErr := b.do(ctx, "PATCH", podPath(c), ops, "application/json-patch+json")
		// If another actor removed the marker, DELETE is still safe. 409 or
		// 422 also means UID changed or inconsistent selector: fail and retry.
		if patchErr != nil {
			return patchErr
		}
		if status != http.StatusOK && status != http.StatusConflict && status != http.StatusUnprocessableEntity && status != http.StatusNotFound {
			return fmt.Errorf("remove containment label: HTTP %d", status)
		}
		if status == http.StatusConflict || status == http.StatusUnprocessableEntity {
			return fmt.Errorf("cannot verify containment label removal: HTTP %d", status)
		}
	} else if err != nil && !errors.Is(err, identity.ErrMismatch) {
		return err
	}
	// Missing/deleted/replaced pod: remove only our uniquely identified policy.
	status, raw, err := b.do(ctx, "GET", policyPath(c)+"/"+policyName(c), nil, "")
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status != http.StatusOK {
		return fmt.Errorf("inspect policy before removal: HTTP %d", status)
	}
	var existing struct {
		Metadata struct {
			UID         string            `json:"uid"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &existing); err != nil {
		return err
	}
	if existing.Metadata.UID == "" || existing.Metadata.Annotations["security.cloudruntimeguardian.dev/containment-id"] != c.ID || existing.Metadata.Annotations["security.cloudruntimeguardian.dev/pod-uid"] != c.Workload.PodUID {
		return errors.New("cannot delete policy with conflicting ownership")
	}
	status, _, err = b.do(ctx, "DELETE", policyPath(c)+"/"+policyName(c), map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]string{"uid": existing.Metadata.UID}}, "application/json")
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusAccepted && status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("delete containment policy: HTTP %d", status)
	}
	return nil
}
