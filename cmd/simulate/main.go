package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"cloudruntimeguardian/internal/model"
)

func main() {
	target := flag.String("url", "http://127.0.0.1:8080", "local HTTP service URL")
	token := flag.String("token", "", "optional bearer token")
	reverse := flag.Bool("out-of-order", true, "post connection before shell execution")
	flag.Parse()
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		log.Fatal(err)
	}
	uid := hex.EncodeToString(raw[:])
	now := time.Now().UTC()
	base := model.Event{HostID: "demo-host", BootID: "boot-" + uid, Workload: model.Workload{
		ID: "payments-" + uid, Namespace: "demo", Pod: "payments-0", ContainerID: "container-" + uid},
		Process: model.Process{PID: 4201, EntityID: "proc-shell-" + uid},
	}
	shell := base
	shell.ID = "evt-exec-" + uid
	shell.Type = model.EventProcessExec
	shell.OccurredAt = now.Add(-20 * time.Second)
	shell.Process.Executable = "/bin/sh"
	connect := base
	connect.ID = "evt-connect-" + uid
	connect.Type = model.EventNetworkConnect
	connect.OccurredAt = now.Add(-10 * time.Second)
	connect.Network = &model.Network{DestinationIP: "1.1.1.1", DestinationPort: 443, Protocol: "tcp"}
	events := []model.Event{shell, connect}
	if *reverse {
		events = []model.Event{connect, shell}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, e := range events {
		b, _ := json.Marshal(e)
		req, err := http.NewRequest("POST", strings.TrimSuffix(*target, "/")+"/v1/events", bytes.NewReader(b))
		if err != nil {
			log.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if *token != "" {
			req.Header.Set("Authorization", "Bearer "+*token)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		response, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		fmt.Printf("POST %s => %d %s", e.Type, resp.StatusCode, response)
		if resp.StatusCode != 202 {
			log.Fatal("unexpected ingestion status")
		}
	}
	req, _ := http.NewRequest("GET", strings.TrimSuffix(*target, "/")+"/v1/incidents?limit=5", nil)
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	var result struct {
		Total     int              `json:"total"`
		Incidents []model.Incident `json:"incidents"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != 200 || !containsDemoIncident(result.Incidents, shell.ID, connect.ID) {
		log.Fatalf("demo incident absent: %s", b)
	}
	fmt.Println("PASS: suspicious execution + external connection correlated into an incident")
}
func containsDemoIncident(items []model.Incident, shell, conn string) bool {
	for _, i := range items {
		if len(i.Evidence) == 2 && i.Evidence[0].EventID == shell && i.Evidence[1].EventID == conn {
			return true
		}
	}
	return false
}
