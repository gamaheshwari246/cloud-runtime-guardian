package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// KubernetesClient performs a live pod GET for every event. No caching means
// pod UID changes, deletions and scheduling changes immediately fail closed.
// API availability therefore directly affects ingestion availability.
type KubernetesClient struct {
	base      string
	token     string
	tokenPath string
	client    *http.Client
}

func NewKubernetesClient(baseURL, bearerToken string, caPEM []byte) (*KubernetesClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("Kubernetes API URL must be an https origin")
	}
	if len(bearerToken) < 8 || len(caPEM) == 0 {
		return nil, errors.New("Kubernetes token and CA bundle required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid Kubernetes CA bundle")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second}
	hc := &http.Client{Timeout: 3 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &KubernetesClient{base: strings.TrimSuffix(u.String(), "/"), token: bearerToken, client: hc}, nil
}

func NewInClusterClient() (*KubernetesClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = "443"
	}
	if host == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST is missing")
	}
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}
	client, err := NewKubernetesClient("https://"+net.JoinHostPort(host, port), string(token), ca)
	if err != nil {
		return nil, err
	}
	client.tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	return client, nil
}

func (c *KubernetesClient) LookupPod(ctx context.Context, namespace, name string) (Pod, error) {
	if !validDNS.MatchString(namespace) || !validDNS.MatchString(name) {
		return Pod{}, ErrMismatch
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+"/api/v1/namespaces/"+url.PathEscape(namespace)+"/pods/"+url.PathEscape(name), nil)
	if err != nil {
		return Pod{}, fmt.Errorf("%w: request creation", ErrUnavailable)
	}
	token := c.token
	if c.tokenPath != "" {
		raw, err := os.ReadFile(c.tokenPath)
		if err != nil || len(raw) < 8 || len(raw) > 1<<16 {
			return Pod{}, fmt.Errorf("%w: service account token unavailable", ErrUnavailable)
		}
		token = string(raw)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return Pod{}, fmt.Errorf("%w: request failed: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Pod{}, fmt.Errorf("%w: pod not found", ErrMismatch)
	}
	if resp.StatusCode != http.StatusOK {
		return Pod{}, fmt.Errorf("%w: Kubernetes API returned %d", ErrUnavailable, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10+1))
	if err != nil {
		return Pod{}, fmt.Errorf("%w: response read failed", ErrUnavailable)
	}
	if len(raw) > 256<<10 {
		return Pod{}, fmt.Errorf("%w: oversized pod response", ErrUnavailable)
	}
	var p struct {
		Metadata struct {
			UID, Namespace, Name string
			DeletionTimestamp    *time.Time `json:"deletionTimestamp"`
		} `json:"metadata"`
		Spec struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
		Status struct {
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"containerStatuses"`
			InitContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"initContainerStatuses"`
			EphemeralContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"ephemeralContainerStatuses"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return Pod{}, fmt.Errorf("%w: invalid Kubernetes response", ErrUnavailable)
	}
	result := Pod{UID: p.Metadata.UID, Namespace: p.Metadata.Namespace, Name: p.Metadata.Name, Node: p.Spec.NodeName, Deleting: p.Metadata.DeletionTimestamp != nil}
	for _, lst := range [][]struct {
		ContainerID string `json:"containerID"`
	}{p.Status.ContainerStatuses, p.Status.InitContainerStatuses, p.Status.EphemeralContainerStatuses} {
		for _, status := range lst {
			if status.ContainerID != "" {
				result.ContainerIDs = append(result.ContainerIDs, status.ContainerID)
			}
		}
	}
	return result, nil
}
