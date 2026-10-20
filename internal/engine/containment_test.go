package engine

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"cloudruntimeguardian/internal/model"
)

func targetEvents() (model.Event, model.Event) {
	sh, conn := testEvents()
	sh.Workload = model.Workload{ID: "verified-workload", Namespace: "payments", Pod: "pay-1", PodUID: "pod-immutable-uid", ContainerID: "containerd://abc"}
	conn.Workload = sh.Workload
	return sh, conn
}
func TestContainmentPersistsLifecycleAndIdempotence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	e, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	sh, conn := targetEvents()
	mustIngest(t, e, sh)
	mustIngest(t, e, conn)
	incidents, _ := e.List(1, 0)
	id := incidents[0].ID
	start := time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC)
	c, created, err := e.RequestContainment("req-1", id, "Manual test quarantine", 5*time.Minute, "simulate", start)
	if err != nil || !created || c.State != "requested" {
		t.Fatalf("request: %+v %v", c, err)
	}
	if again, created, err := e.RequestContainment("req-1", id, "Manual test quarantine", 5*time.Minute, "simulate", start.Add(time.Second)); err != nil || created || again != c {
		t.Fatalf("retry: %+v %v", again, err)
	}
	if _, _, err = e.RequestContainment("req-2", id, "Manual test quarantine", 5*time.Minute, "simulate", start); !errors.Is(err, ErrActiveContainment) {
		t.Fatalf("double containment: %v", err)
	}
	if _, err = e.MarkContainmentReleased(c.ID, start); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid state transition: %v", err)
	}
	if _, err = e.MarkContainmentApplied(c.ID, start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.RequestRelease(c.ID, start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.MarkContainmentReleased(c.ID, start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	result, ok := recovered.GetContainment(c.ID)
	if !ok || result.State != "released" || result.Workload.PodUID != sh.Workload.PodUID {
		t.Fatalf("bad replay %+v", result)
	}
	if again, created, err := recovered.RequestContainment(c.ID, id, "Manual test quarantine", 5*time.Minute, "simulate", start); err != nil || created || again.State != "released" {
		t.Fatalf("idempotence after restart: %+v %v", again, err)
	}
}
func TestContainmentRejectedWithoutVerifiedIdentity(t *testing.T) {
	e, _ := openTest(t)
	sh, conn := testEvents()
	mustIngest(t, e, sh)
	mustIngest(t, e, conn)
	incidents, _ := e.List(1, 0)
	if _, _, err := e.RequestContainment("r1", incidents[0].ID, "Need ten characters", time.Minute, "kubernetes", time.Now()); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("unverified workload accepted: %v", err)
	}
	if len(e.ListContainments()) != 0 {
		t.Fatal("unexpected containment written")
	}
}
func TestContainmentRejectsReuseAcrossModesAndDurations(t *testing.T) {
	e, _ := openTest(t)
	sh, conn := targetEvents()
	mustIngest(t, e, sh)
	mustIngest(t, e, conn)
	incidents, _ := e.List(1, 0)
	id := incidents[0].ID
	if _, _, err := e.RequestContainment("r", id, "Manual security action", time.Hour, "kubernetes", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.RequestContainment("r", id, "Manual security action", time.Minute, "kubernetes", time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatal("idempotency key collision not rejected", err)
	}
	if _, _, err := e.RequestContainment("r", id, "Manual security action", time.Hour, "simulate", time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatal("mode mismatch not rejected", err)
	}
}
