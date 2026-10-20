package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/httpapi"
	"cloudruntimeguardian/internal/identity"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listening address; non-loopback requires CRG_API_TOKEN")
	data := flag.String("data", "./data/journal.jsonl", "durable journal location")
	maxEvents := flag.Int("max-events", engine.DefaultMaxEvents, "maximum persisted events per journal before manual archival")
	tlsCert := flag.String("tls-cert", "", "PEM TLS certificate for HTTPS listener")
	tlsKey := flag.String("tls-key", "", "PEM TLS private key for HTTPS listener")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("invalid -addr: %v", err)
	}
	ip := net.ParseIP(host)
	local := host == "localhost" || (ip != nil && ip.IsLoopback())
	legacy := os.Getenv("CRG_API_TOKEN")
	ingest := os.Getenv("CRG_INGEST_TOKEN")
	admin := os.Getenv("CRG_ADMIN_TOKEN")
	for _, credential := range []string{legacy, ingest, admin} {
		if credential != "" && len(credential) < 24 {
			log.Fatal("API credentials must be at least 24 characters")
		}
	}
	strict := os.Getenv("CRG_K8S_VERIFY") == "1"
	if strict && (admin == "" || ingest != "" || legacy != "") {
		log.Fatal("strict Kubernetes mode requires only CRG_ADMIN_TOKEN; collector credentials come from CRG_NODE_CREDENTIALS_FILE")
	}
	if !strict && (ingest != "" || admin != "") && (ingest == "" || admin == "" || ingest == admin) {
		log.Fatal("CRG_INGEST_TOKEN and CRG_ADMIN_TOKEN must be distinct and both configured")
	}
	if !local {
		if admin == "" || (!strict && (ingest == "" || ingest == admin)) {
			log.Fatal("non-loopback listener needs distinct CRG_INGEST_TOKEN and CRG_ADMIN_TOKEN")
		}
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatal("non-loopback listener requires -tls-cert and -tls-key")
		}
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("-tls-cert and -tls-key must be supplied together")
	}
	if *maxEvents < 1 || *maxEvents > 1_000_000 {
		log.Fatal("-max-events must be between 1 and 1000000")
	}
	var verifier *identity.Verifier
	if strict {
		if local || *tlsCert == "" {
			log.Fatal("strict Kubernetes identity mode requires non-loopback HTTPS")
		}
		credentialsFile := os.Getenv("CRG_NODE_CREDENTIALS_FILE")
		if credentialsFile == "" {
			log.Fatal("CRG_NODE_CREDENTIALS_FILE is required")
		}
		credentials, err := identity.LoadCredentials(credentialsFile)
		if err != nil {
			log.Fatalf("load node credentials: %v", err)
		}
		client, err := identity.NewInClusterClient()
		if err != nil {
			log.Fatalf("initialize Kubernetes identity client: %v", err)
		}
		verifier, err = identity.New(client, credentials)
		if err != nil {
			log.Fatalf("initialize identity verifier: %v", err)
		}
	} else if os.Getenv("CRG_K8S_VERIFY") != "" && os.Getenv("CRG_K8S_VERIFY") != "0" {
		log.Fatal("CRG_K8S_VERIFY must be 0 or 1")
	}
	en, err := engine.Open(*data, *maxEvents)
	if err != nil {
		log.Fatalf("open journal: %v", err)
	}
	defer en.Close()

	srv := &http.Server{
		Addr: *addr, Handler: (&httpapi.API{Engine: en, Token: legacy, IngestToken: ingest, AdminToken: admin, Identity: verifier}).Handler(),
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 16,
	}
	stop, stopNotify := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopNotify()
	go func() {
		<-stop.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	log.Printf("listening on %s (journal=%s, capacity=%d, authenticated=%t, tls=%t, enforcement=disabled)", *addr, *data, *maxEvents, legacy != "" || ingest != "" || admin != "", *tlsCert != "")
	var serveErr error
	if *tlsCert != "" {
		serveErr = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		serveErr = srv.ListenAndServe()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Fatal(serveErr)
	}
}
