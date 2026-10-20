package identity

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"

	"cloudruntimeguardian/internal/model"
)

// VerifyMTLS binds a TLS-verified client certificate identity to the node
// authenticated by its independent bearer token. Both identities must agree.
// The server MUST configure ClientAuth=VerifyClientCertIfGiven with an explicit
// trusted CA, and require this method on collector ingestion endpoints.
func (v *Verifier) VerifyMTLS(ctx context.Context, authorization string, e model.Event, tlsState *tls.ConnectionState) (model.Event, error) {
	if tlsState == nil || len(tlsState.PeerCertificates) < 1 || len(tlsState.VerifiedChains) == 0 {
		return e, fmt.Errorf("%w: verified collector client certificate required", ErrUnauthenticated)
	}
	node, err := v.authenticate(authorization)
	if err != nil {
		return e, err
	}
	expected := "spiffe://cloud-runtime-guardian.local/node/" + url.PathEscape(node)
	match := len(tlsState.PeerCertificates[0].URIs) == 1
	for _, u := range tlsState.PeerCertificates[0].URIs {
		if u.String() != expected {
			match = false
		}
	}
	if !match {
		return e, fmt.Errorf("%w: collector certificate node identity mismatch", ErrUnauthenticated)
	}
	return v.Verify(ctx, authorization, e)
}
