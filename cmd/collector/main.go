// collector bridges a local Tetragon JSON export to the durable event API.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cloudruntimeguardian/internal/collector"
	"cloudruntimeguardian/internal/tlscerts"
)

func main() {
	export := flag.String("export", "/var/log/tetragon/tetragon.log", "local append-only Tetragon JSONL export")
	checkpoint := flag.String("checkpoint", "./data/tetragon-checkpoint.json", "durable source offset checkpoint")
	node := flag.String("node", "", "exact node_name from Tetragon (required)")
	endpoint := flag.String("endpoint", "http://127.0.0.1:8080/v1/events", "events API endpoint")
	follow := flag.Bool("follow", true, "follow appended records until shutdown")
	clientCert := flag.String("client-cert", "", "PEM collector client certificate for mutual TLS")
	clientKey := flag.String("client-key", "", "PEM collector client private key for mutual TLS")
	caCert := flag.String("ca-cert", "", "optional PEM CA for the ingestion server")
	flag.Parse()
	if *node == "" {
		log.Fatal("-node is required")
	}
	parsed, err := url.Parse(*endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		log.Fatal("-endpoint must be an http(s) URL")
	}
	if parsed.Scheme == "http" && !strings.EqualFold(parsed.Hostname(), "localhost") && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" {
		log.Fatal("remote ingestion requires HTTPS")
	}
	if (*clientCert == "") != (*clientKey == "") {
		log.Fatal("-client-cert and -client-key are required together")
	}
	if (*clientCert != "" || *caCert != "") && parsed.Scheme != "https" {
		log.Fatal("collector TLS credentials require an HTTPS endpoint")
	}
	var httpClient *http.Client
	if *clientCert != "" || *caCert != "" {
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
		if *clientCert != "" {
			if _, err := tls.LoadX509KeyPair(*clientCert, *clientKey); err != nil {
				log.Fatalf("read client certificate: %v", err)
			}
			transport.TLSClientConfig.GetClientCertificate = tlscerts.Collector(*clientCert, *clientKey)
		}
		if *caCert != "" {
			raw, err := os.ReadFile(*caCert)
			if err != nil {
				log.Fatalf("read ingestion CA: %v", err)
			}
			roots, err := x509.SystemCertPool()
			if err != nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(raw) {
				log.Fatal("invalid ingestion CA PEM")
			}
			transport.TLSClientConfig.RootCAs = roots
		}
		httpClient = &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	boot, err := collector.ReadBootID()
	if err != nil {
		log.Fatalf("read Linux boot ID: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = collector.Run(ctx, collector.Config{ExportPath: *export, CheckpointPath: *checkpoint, NodeName: *node, BootID: boot, Follow: *follow, PollInterval: time.Second},
		collector.HTTPSender{URL: *endpoint, Token: collectorToken(), Client: httpClient})
	if err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "collector stopped:", err)
		os.Exit(1)
	}
}

func collectorToken() string {
	if t := os.Getenv("CRG_NODE_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("CRG_API_TOKEN")
}
