// Command loadtest exercises ingestion correctness and latency against an
// explicitly selected staging endpoint. Never target an unapproved service.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cloudruntimeguardian/internal/model"
)

// Histogram has bounded memory even for multi-day soak runs. Buckets are in
// milliseconds; the last bucket includes all measurements >= 10 seconds.
const buckets = 10001

type histogram struct{ values [buckets]atomic.Uint64 }

func (h *histogram) observe(d time.Duration) {
	i := int(d.Milliseconds())
	if i < 0 {
		i = 0
	}
	if i >= buckets {
		i = buckets - 1
	}
	h.values[i].Add(1)
}
func (h *histogram) percentile(p float64, total uint64) time.Duration {
	if total == 0 {
		return 0
	}
	target := uint64(math.Ceil(float64(total) * p))
	var n uint64
	for i := 0; i < buckets; i++ {
		n += h.values[i].Load()
		if n >= target {
			return time.Duration(i) * time.Millisecond
		}
	}
	return time.Duration(buckets-1) * time.Millisecond
}

type result struct {
	Requests        uint64  `json:"requests"`
	Succeeded       uint64  `json:"succeeded"`
	Failed          uint64  `json:"failed"`
	P50Millis       int64   `json:"p50_ms"`
	P95Millis       int64   `json:"p95_ms"`
	P99Millis       int64   `json:"p99_ms"`
	ErrorRate       float64 `json:"error_rate"`
	AchievedRPS     float64 `json:"achieved_rps"`
	DurationSeconds float64 `json:"duration_seconds"`
	Passed          bool    `json:"passed"`
}

func event(sequence uint64, namespace string, clock time.Time) model.Event {
	pair := sequence / 2
	e := model.Event{
		ID:         fmt.Sprintf("soak-%s-%d", namespace, sequence),
		OccurredAt: clock, HostID: "loadnode", BootID: "loadboot",
		Workload: model.Workload{ID: fmt.Sprintf("load-workload-%d", pair%256)},
		Process:  model.Process{EntityID: fmt.Sprintf("load-process-%d", pair), PID: int(pair%30000) + 1},
	}
	if sequence%2 == 0 {
		e.Type = model.EventProcessExec
		e.Process.Executable = "/usr/bin/true"
	} else {
		e.Type = model.EventNetworkConnect
		e.Network = &model.Network{DestinationIP: "198.51.100.20", DestinationPort: 443, Protocol: "tcp"}
	}
	return e
}

func run(ctx context.Context, client *http.Client, endpoint, token, namespace string, workers, rps int, duration time.Duration, maxError float64, maxP99 time.Duration) (result, error) {
	var out result
	if workers < 1 || workers > 512 || rps < 1 || rps > 100000 || duration <= 0 || maxError < 0 || maxError > 1 || maxP99 < time.Millisecond {
		return out, errors.New("invalid load configuration")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Path != "/v1/events" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return out, errors.New("endpoint must be absolute /v1/events URL")
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return out, errors.New("non-loopback targets require https")
		}
	}
	feedCtx, stopFeeding := context.WithTimeout(ctx, duration)
	defer stopFeeding()
	var seq, successful, failed atomic.Uint64
	var h histogram
	// Limit in-flight requests with a fixed worker pool. No unbounded queue.
	tickets := make(chan struct{})
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range tickets {
				id := seq.Add(1) - 1
				raw, _ := json.Marshal(event(id, namespace, time.Now().UTC()))
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
				if err != nil {
					failed.Add(1)
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				started := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					failed.Add(1)
					continue
				}
				_, drainErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
				resp.Body.Close()
				if resp.StatusCode == http.StatusAccepted && drainErr == nil {
					successful.Add(1)
					h.observe(time.Since(started))
				} else {
					failed.Add(1)
				}
			}
		}()
	}
	// time.Ticker enforces aggregate target RPS. At high rates the bounded
	// channel provides backpressure instead of growing an in-memory queue.
	interval := time.Second / time.Duration(rps)
	if interval < time.Nanosecond {
		interval = time.Nanosecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-feedCtx.Done():
			break loop
		case <-ticker.C:
			select {
			case tickets <- struct{}{}:
			case <-feedCtx.Done():
				break loop
			}
		}
	}
	close(tickets)
	wg.Wait()
	actual := time.Since(start)
	out.Requests = successful.Load() + failed.Load()
	out.Succeeded = successful.Load()
	out.Failed = failed.Load()
	if out.Requests == 0 {
		return out, errors.New("no requests were executed")
	}
	out.P50Millis = h.percentile(0.50, out.Succeeded).Milliseconds()
	out.P95Millis = h.percentile(0.95, out.Succeeded).Milliseconds()
	out.P99Millis = h.percentile(0.99, out.Succeeded).Milliseconds()
	out.ErrorRate = float64(out.Failed) / float64(out.Requests)
	out.DurationSeconds = actual.Seconds()
	out.AchievedRPS = float64(out.Requests) / out.DurationSeconds
	out.Passed = out.ErrorRate <= maxError && time.Duration(out.P99Millis)*time.Millisecond <= maxP99
	return out, nil
}
func main() {
	endpoint := flag.String("endpoint", "http://127.0.0.1:8080/v1/events", "staging events endpoint")
	duration := flag.Duration("duration", 15*time.Second, "test duration")
	workers := flag.Int("workers", 8, "bounded concurrency")
	rps := flag.Int("rps", 100, "target requests per second")
	maxError := flag.Float64("max-error-rate", 0.01, "maximum acceptable request failure fraction")
	maxP99 := flag.Duration("max-p99", 500*time.Millisecond, "maximum acceptable p99 response latency")
	ca := flag.String("ca", "", "custom server CA PEM")
	namespace := flag.String("run-id", fmt.Sprintf("%d", time.Now().UnixNano()), "unique run identifier to prevent event ID collisions")
	flag.Parse()
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,48}$`).MatchString(*namespace) {
		fmt.Fprintln(os.Stderr, "invalid run identifier")
		os.Exit(2)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = *workers
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			fmt.Fprintln(os.Stderr, "invalid CA")
			os.Exit(2)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	out, err := run(ctx, client, *endpoint, os.Getenv("CRG_LOAD_TOKEN"), *namespace, *workers, *rps, *duration, *maxError, *maxP99)
	_ = json.NewEncoder(os.Stdout).Encode(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !out.Passed {
		os.Exit(1)
	}
}
