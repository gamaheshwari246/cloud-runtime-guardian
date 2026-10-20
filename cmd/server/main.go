package main

import (
	"context"
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
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listening address; non-loopback requires CRG_API_TOKEN")
	data := flag.String("data", "./data/journal.jsonl", "durable journal location")
	maxEvents := flag.Int("max-events", engine.DefaultMaxEvents, "maximum persisted events per journal before manual archival")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("invalid -addr: %v", err)
	}
	ip := net.ParseIP(host)
	local := host == "localhost" || (ip != nil && ip.IsLoopback())
	token := os.Getenv("CRG_API_TOKEN")
	if !local && len(token) < 24 {
		log.Fatal("refusing non-loopback listening without CRG_API_TOKEN of at least 24 characters")
	}
	if token != "" && len(token) < 24 {
		log.Fatal("CRG_API_TOKEN must have at least 24 characters")
	}
	if *maxEvents < 1 {
		log.Fatal("-max-events must be positive")
	}
	en, err := engine.Open(*data, *maxEvents)
	if err != nil {
		log.Fatalf("open journal: %v", err)
	}
	defer en.Close()

	srv := &http.Server{
		Addr: *addr, Handler: (&httpapi.API{Engine: en, Token: token}).Handler(),
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
	log.Printf("listening on %s (journal=%s, capacity=%d, auth=%t, enforcement=disabled)", *addr, *data, *maxEvents, token != "")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
