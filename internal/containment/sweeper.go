package containment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cloudruntimeguardian/internal/model"
)

// SweepExpired removes only expired, structurally verified policies carrying
// our exact ownership markers. It works independently of the main service,
// allowing a separate Kubernetes CronJob to unstick expired quarantines after
// a server outage. It DOES NOT clear pod labels or mutate journal history;
// the main reconciler handles both on its next successful start.
func (b *KubernetesBackend) SweepExpired(ctx context.Context, now time.Time) (int, error) {
	if b == nil || b.Client == nil || b.Token == nil {
		return 0, errors.New("unconfigured Kubernetes API client")
	}
	removed := 0
	cursor := ""
	for page := 0; page < 200; page++ {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		path := "/apis/networking.k8s.io/v1/networkpolicies?limit=50&labelSelector=" + url.QueryEscape("app.kubernetes.io/managed-by=cloud-runtime-guardian")
		if cursor != "" {
			path += "&continue=" + url.QueryEscape(cursor)
		}
		status, raw, err := b.do(ctx, "GET", path, nil, "")
		if err != nil {
			return removed, err
		}
		if status != http.StatusOK {
			return removed, fmt.Errorf("list containment policies: HTTP %d", status)
		}
		var listed struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []struct {
				Metadata struct {
					Name        string            `json:"name"`
					Namespace   string            `json:"namespace"`
					UID         string            `json:"uid"`
					Labels      map[string]string `json:"labels"`
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
				Spec struct {
					PodSelector struct {
						MatchLabels map[string]string `json:"matchLabels"`
					} `json:"podSelector"`
					PolicyTypes []string          `json:"policyTypes"`
					Egress      []json.RawMessage `json:"egress"`
				} `json:"spec"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &listed); err != nil {
			return removed, fmt.Errorf("invalid NetworkPolicy list: %w", err)
		}
		for _, item := range listed.Items {
			m := item.Metadata
			a := m.Annotations
			if m.Labels["app.kubernetes.io/managed-by"] != "cloud-runtime-guardian" || m.UID == "" || !dnsName.MatchString(m.Namespace) || len(m.Namespace) > 63 {
				continue
			}
			expiry, err := time.Parse(time.RFC3339Nano, a["security.cloudruntimeguardian.dev/expires-at"])
			if err != nil || now.Before(expiry) {
				continue
			}
			id, uid := a["security.cloudruntimeguardian.dev/containment-id"], a["security.cloudruntimeguardian.dev/pod-uid"]
			if id == "" || uid == "" || len(id) > 128 || len(uid) > 128 {
				continue
			}
			c := model.Containment{ID: id, Workload: model.Workload{PodUID: uid}}
			if !strings.HasPrefix(m.Name, "crg-egress-") || m.Name != policyName(c) || len(item.Spec.PodSelector.MatchLabels) != 1 ||
				item.Spec.PodSelector.MatchLabels[labelKey] != labelValue(c) || len(item.Spec.PolicyTypes) != 1 || item.Spec.PolicyTypes[0] != "Egress" || len(item.Spec.Egress) != 0 {
				continue
			}
			deletion := map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]string{"uid": m.UID}}
			endpoint := "/apis/networking.k8s.io/v1/namespaces/" + url.PathEscape(m.Namespace) + "/networkpolicies/" + url.PathEscape(m.Name)
			status, _, err = b.do(ctx, "DELETE", endpoint, deletion, "application/json")
			if err != nil {
				return removed, err
			}
			if status != http.StatusOK && status != http.StatusAccepted && status != http.StatusNoContent && status != http.StatusNotFound {
				return removed, fmt.Errorf("delete expired policy %s/%s: HTTP %d", m.Namespace, m.Name, status)
			}
			removed++
		}
		if listed.Metadata.Continue == "" {
			return removed, nil
		}
		if listed.Metadata.Continue == cursor {
			return removed, errors.New("Kubernetes pagination cursor did not advance")
		}
		cursor = listed.Metadata.Continue
	}
	return removed, errors.New("Kubernetes NetworkPolicy scan exceeded page budget")
}
