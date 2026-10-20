// collector bridges a local Tetragon JSON export to the durable event API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cloudruntimeguardian/internal/collector"
)

func main() {
	export := flag.String("export", "/var/log/tetragon/tetragon.log", "local append-only Tetragon JSONL export")
	checkpoint := flag.String("checkpoint", "./data/tetragon-checkpoint.json", "durable source offset checkpoint")
	node := flag.String("node", "", "exact node_name from Tetragon (required)")
	endpoint := flag.String("endpoint", "http://127.0.0.1:8080/v1/events", "events API endpoint")
	follow := flag.Bool("follow", true, "follow appended records until shutdown")
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
	boot, err := collector.ReadBootID()
	if err != nil {
		log.Fatalf("read Linux boot ID: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = collector.Run(ctx, collector.Config{ExportPath: *export, CheckpointPath: *checkpoint, NodeName: *node, BootID: boot, Follow: *follow, PollInterval: time.Second},
		collector.HTTPSender{URL: *endpoint, Token: collectorToken()})
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
