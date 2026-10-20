// Package tlscerts loads a rotated PEM keypair for each new TLS handshake.
// No certificate material is cached, so deleting or corrupting the source
// makes NEW handshakes fail closed instead of serving an expired credential.
package tlscerts

import "crypto/tls"

func Server(certPath, keyPath string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		return &pair, nil
	}
}
func Collector(certPath, keyPath string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		return &pair, nil
	}
}
