package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/identity"
	"cloudruntimeguardian/internal/model"
)

type mtlsPods struct{}

func (mtlsPods) LookupPod(_ context.Context, namespace, name string) (identity.Pod, error) {
	return identity.Pod{UID: "pod1", Namespace: namespace, Name: name, Node: "worker-1", ContainerIDs: []string{"containerd://c1"}}, nil
}
func testHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}
func makeCert(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, node string) tls.Certificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://cloud-runtime-guardian.local/node/" + node)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(len(node) + 1)), Subject: pkix.Name{CommonName: "test-collector"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func TestStrictIngestMutualTLSHandshake(t *testing.T) {
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	verifier, err := identity.New(mtlsPods{}, []identity.NodeCredential{{Node: "worker-1", Token: strings.Repeat("T", 36)}})
	if err != nil {
		t.Fatal(err)
	}
	en, err := engine.Open(filepath.Join(t.TempDir(), "ledger.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer en.Close()
	srv := httptest.NewUnstartedServer((&API{Engine: en, Identity: verifier, RequireCollectorMTLS: true, AdminToken: strings.Repeat("A", 32)}).Handler())
	srv.TLS = &tls.Config{ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	e := model.Event{ID: "event1", Type: model.EventProcessExec, OccurredAt: time.Now().UTC(), HostID: testHash("host", "worker-1"), BootID: "boot", Workload: model.Workload{ID: testHash("container", "containerd://c1"), Namespace: "prod", Pod: "payments", PodUID: "pod1", ContainerID: "containerd://c1"}, Process: model.Process{EntityID: "unique", PID: 21, Executable: "/bin/sh"}}
	body, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	try := func(client *http.Client) int {
		t.Helper()
		req, err := http.NewRequest("POST", srv.URL+"/v1/events", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("T", 36))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	noCert := srv.Client()
	if status := try(noCert); status != 401 {
		t.Fatalf("accepted collector without cert: %d", status)
	}
	clientWithCert := func(node string) *http.Client {
		tr := srv.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{makeCert(t, ca, caKey, node)}
		return &http.Client{Transport: tr, Timeout: 5 * time.Second}
	}
	if status := try(clientWithCert("worker-2")); status != 401 {
		t.Fatalf("wrong node client certificate accepted: %d", status)
	}
	if status := try(clientWithCert("worker-1")); status != 202 {
		t.Fatalf("correct node certificate rejected: %d", status)
	}
}
