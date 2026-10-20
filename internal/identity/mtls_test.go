package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestNodeCertificateMustMatchBearerNode(t *testing.T) {
	resolver := &fakeResolver{pod: Pod{UID: "uid-1", Namespace: "finance", Name: "payment-0", Node: "worker-1", ContainerIDs: []string{"containerd://abc"}}}
	verifier, err := New(resolver, []NodeCredential{{Node: "worker-1", Token: strings.Repeat("A", 36)}})
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://cloud-runtime-guardian.local/node/worker-1")
	peer := &x509.Certificate{URIs: []*url.URL{uri}}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}, VerifiedChains: [][]*x509.Certificate{{peer}}}
	auth := "Bearer " + strings.Repeat("A", 36)
	if _, err := verifier.VerifyMTLS(context.Background(), auth, event(), state); err != nil {
		t.Fatal(err)
	}
	wrongURI, _ := url.Parse("spiffe://cloud-runtime-guardian.local/node/worker-2")
	state.PeerCertificates[0] = &x509.Certificate{URIs: []*url.URL{wrongURI}}
	if _, err := verifier.VerifyMTLS(context.Background(), auth, event(), state); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("node mismatch accepted: %v", err)
	}
	state.PeerCertificates[0] = peer
	state.VerifiedChains = nil
	if _, err := verifier.VerifyMTLS(context.Background(), auth, event(), state); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unverified chain accepted: %v", err)
	}
	if _, err := verifier.VerifyMTLS(context.Background(), auth, event(), nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("missing TLS accepted: %v", err)
	}
	state.VerifiedChains = [][]*x509.Certificate{{peer}}
	// A normal peer may supply the intermediate alongside its leaf.
	state.PeerCertificates = []*x509.Certificate{peer, {BasicConstraintsValid: true, IsCA: true}}
	if _, err := verifier.VerifyMTLS(context.Background(), auth, event(), state); err != nil {
		t.Fatalf("client certificate chain rejected: %v", err)
	}
	state.PeerCertificates = []*x509.Certificate{peer}
	if _, err := verifier.VerifyMTLS(context.Background(), "Bearer "+strings.Repeat("B", 36), event(), state); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("incorrect token accepted: %v", err)
	}
}
