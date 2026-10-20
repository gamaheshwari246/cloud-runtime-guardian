package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloudruntimeguardian/internal/containment"
	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/httpapi"
	"cloudruntimeguardian/internal/identity"
	"cloudruntimeguardian/internal/tlscerts"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listening address; non-loopback requires CRG_API_TOKEN")
	data := flag.String("data", "./data/journal.jsonl", "durable journal location")
	maxEvents := flag.Int("max-events", engine.DefaultMaxEvents, "maximum persisted events per journal before manual archival")
	tlsCert := flag.String("tls-cert", "", "PEM TLS certificate for HTTPS listener")
	tlsKey := flag.String("tls-key", "", "PEM TLS private key for HTTPS listener")
	collectorCA := flag.String("collector-ca", "", "optional PEM CA bundle for collector mutual TLS")
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
	requireCollectorMTLS := os.Getenv("CRG_REQUIRE_COLLECTOR_MTLS") == "1"
	if os.Getenv("CRG_REQUIRE_COLLECTOR_MTLS") != "" && os.Getenv("CRG_REQUIRE_COLLECTOR_MTLS") != "0" && !requireCollectorMTLS {
		log.Fatal("CRG_REQUIRE_COLLECTOR_MTLS must be 0 or 1")
	}
	if requireCollectorMTLS && (!strict || *collectorCA == "" || *tlsCert == "") {
		log.Fatal("mTLS requires strict Kubernetes mode, TLS listener and -collector-ca")
	}
	if *collectorCA != "" && !requireCollectorMTLS {
		log.Fatal("-collector-ca requires CRG_REQUIRE_COLLECTOR_MTLS=1")
	}

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
	var verifierClient *identity.KubernetesClient
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
		verifierClient = client
		verifier, err = identity.New(client, credentials)
		if err != nil {
			log.Fatalf("initialize identity verifier: %v", err)
		}
	} else if os.Getenv("CRG_K8S_VERIFY") != "" && os.Getenv("CRG_K8S_VERIFY") != "0" {
		log.Fatal("CRG_K8S_VERIFY must be 0 or 1")
	}
	mode := os.Getenv("CRG_CONTAINMENT_MODE")
	if mode != "" && mode != "simulate" && mode != "kubernetes" {
		log.Fatal("CRG_CONTAINMENT_MODE must be empty, simulate or kubernetes")
	}
	if mode == "kubernetes" && !strict {
		log.Fatal("Kubernetes containment requires strict node and workload identity verification")
	}
	// Standard Kubernetes NetworkPolicies are additive. An empty egress
	// rule cannot guarantee isolation if another selected policy permits
	// egress. Keep this backend restricted to explicitly authorized labs.
	if mode == "kubernetes" && os.Getenv("CRG_EXPERIMENTAL_K8S_CONTAINMENT") != "1" {
		log.Fatal("Kubernetes NetworkPolicy containment is experimental; require CRG_EXPERIMENTAL_K8S_CONTAINMENT=1 for staging only")
	}
	if mode == "simulate" && !local {
		log.Fatal("simulation mode is allowed only on loopback")
	}
	if mode != "" && admin == "" {
		log.Fatal("containment requires a dedicated administrator credential")
	}
	// SIGHUP rotates node tokens atomically without interrupting in-flight requests.
	// Kubernetes Secret volume projections update symlinks; each reload resolves
	// and validates the complete replacement before it can become active.
	if strict {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		go func() {
			for range hup {
				updated, err := identity.LoadCredentials(os.Getenv("CRG_NODE_CREDENTIALS_FILE"))
				if err == nil {
					err = verifier.ReplaceCredentials(updated)
				}
				if err != nil {
					log.Printf("collector credential rotation rejected: %v", err)
				} else {
					log.Printf("collector credentials rotated successfully")
				}
			}
		}()
	}
	stop, stopNotify := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopNotify()
	en, err := engine.Open(*data, *maxEvents)
	if err != nil {
		log.Fatalf("open journal: %v", err)
	}
	defer en.Close()
	// Never disable an active containment merely by changing configuration.
	// Such a restart could leave external NetworkPolicies in place indefinitely.
	for _, c := range en.ListContainments() {
		if c.State != "released" && c.Mode != mode {
			log.Fatal("unresolved containment requires its original backend mode until release")
		}
	}
	// Reconciliation must stop before the single-writer ledger is closed.
	workerCtx, stopWorker := context.WithCancel(stop)
	var workerDone chan struct{}
	if mode != "" {
		var backend containment.Backend
		if mode == "simulate" {
			backend = &containment.Simulator{}
		} else {
			backend, err = containment.NewInClusterBackend(verifierClient)
			if err != nil {
				log.Fatalf("initialize Kubernetes containment backend: %v", err)
			}
		}
		controller := &containment.Controller{Engine: en, Backend: backend, Mode: mode}
		workerDone = make(chan struct{})
		go func() {
			defer close(workerDone)
			controller.Run(workerCtx, 5*time.Second, func(err error) { log.Printf("containment reconciliation: %v", err) })
		}()
	}

	srv := &http.Server{
		Addr: *addr, Handler: (&httpapi.API{Engine: en, Token: legacy, IngestToken: ingest, AdminToken: admin, Identity: verifier, ContainmentMode: mode, RequireCollectorMTLS: requireCollectorMTLS}).Handler(),
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 16,
	}
	go func() {
		<-stop.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if *tlsCert != "" {
		tlsConfig.GetCertificate = tlscerts.Server(*tlsCert, *tlsKey)
	}
	if requireCollectorMTLS {
		caPEM, err := os.ReadFile(*collectorCA)
		if err != nil {
			log.Fatalf("read collector CA: %v", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			log.Fatal("collector CA contains no valid certificates")
		}
		tlsConfig.ClientCAs = roots
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven // admin/health clients may omit cert; event handler requires it
	}
	srv.TLSConfig = tlsConfig
	log.Printf("listening on %s (journal=%s, capacity=%d, authenticated=%t, tls=%t, containment-mode=%s)", *addr, *data, *maxEvents, legacy != "" || ingest != "" || admin != "", *tlsCert != "", mode)
	var serveErr error
	if *tlsCert != "" {
		serveErr = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		serveErr = srv.ListenAndServe()
	}
	stopWorker()
	if workerDone != nil {
		<-workerDone
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Printf("server failed: %v", serveErr)
		os.Exit(1)
	}
}
