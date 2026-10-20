// The sweeper is an independent expiry backstop for Kubernetes deployments.
// Use a distinct ServiceAccount with read/list and delete permissions limited
// to NetworkPolicies; never allow this command to create or label workloads.
package main

import (
	"context"
	"log"
	"time"

	"cloudruntimeguardian/internal/containment"
)

func main() {
	backend, err := containment.NewInClusterBackend(nil)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	removed, err := backend.SweepExpired(ctx, time.Now().UTC())
	if err != nil {
		log.Fatalf("expired policy cleanup incomplete (removed %d): %v", removed, err)
	}
	log.Printf("expired NetworkPolicies removed=%d", removed)
}
