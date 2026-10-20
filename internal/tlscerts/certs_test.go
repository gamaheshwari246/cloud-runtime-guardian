package tlscerts

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePair(t *testing.T, certPath, keyPath string, serial int64) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	// Atomic rename mirrors a projected Kubernetes Secret update.
	if err := os.WriteFile(certPath+".new", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+".new", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(certPath+".new", certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(keyPath+".new", keyPath); err != nil {
		t.Fatal(err)
	}
}
func TestCertificateReloadAndFailClosed(t *testing.T) {
	certPath, keyPath := filepath.Join(t.TempDir(), "cert.pem"), filepath.Join(t.TempDir(), "key.pem")
	writePair(t, certPath, keyPath, 1)
	getServer, getClient := Server(certPath, keyPath), Collector(certPath, keyPath)
	for _, get := range []func() (*tls.Certificate, error){func() (*tls.Certificate, error) { return getServer(nil) }, func() (*tls.Certificate, error) { return getClient(nil) }} {
		c, err := get()
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil || leaf.SerialNumber.Int64() != 1 {
			t.Fatalf("initial cert: %v %v", leaf, err)
		}
	}
	writePair(t, certPath, keyPath, 2)
	c, err := getServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil || leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("rotated cert: %v %v", leaf, err)
	}
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if _, err := getClient(nil); err == nil {
		t.Fatal("accepted missing certificate after rotation")
	}
}
