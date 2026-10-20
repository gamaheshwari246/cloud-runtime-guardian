package containment

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/model"
)

func prepare(t *testing.T) (*engine.Engine, string, time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	en, err := engine.Open(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = en.Close() })
	start := time.Now().UTC().Truncate(time.Second)
	base := model.Event{HostID: "node1", BootID: "boot1", Workload: model.Workload{ID: "stable", Pod: "payment", Namespace: "qa", PodUID: "pod-uid", ContainerID: "containerd://abc"}, Process: model.Process{EntityID: "process1", PID: 10}}
	sh := base
	sh.ID = "shell"
	sh.Type = model.EventProcessExec
	sh.Process.Executable = "/bin/sh"
	sh.OccurredAt = start
	conn := base
	conn.ID = "conn"
	conn.Type = model.EventNetworkConnect
	conn.Network = &model.Network{DestinationIP: "8.8.8.8", DestinationPort: 443, Protocol: "tcp"}
	conn.OccurredAt = start.Add(time.Second)
	if _, err := en.Ingest(sh); err != nil {
		t.Fatal(err)
	}
	if _, err := en.Ingest(conn); err != nil {
		t.Fatal(err)
	}
	incidents, _ := en.List(1, 0)
	c, _, err := en.RequestContainment("req-1", incidents[0].ID, "Confirmed simulated response", time.Minute, "simulate", start)
	if err != nil {
		t.Fatal(err)
	}
	return en, c.ID, start
}

type flakyBackend struct {
	simulator Simulator
	fail      int
}

func (b *flakyBackend) Ensure(ctx context.Context, c model.Containment) error {
	if b.fail > 0 {
		b.fail--
		return errors.New("transient API error")
	}
	return b.simulator.Ensure(ctx, c)
}
func (b *flakyBackend) Release(ctx context.Context, c model.Containment) error {
	if b.fail > 0 {
		b.fail--
		return errors.New("transient API error")
	}
	return b.simulator.Release(ctx, c)
}

func TestReconcileRetryExpiryAndRelease(t *testing.T) {
	en, id, start := prepare(t)
	b := &flakyBackend{fail: 1}
	c := &Controller{Engine: en, Backend: b, Mode: "simulate", Now: func() time.Time { return start.Add(2 * time.Second) }}
	if err := c.Reconcile(context.Background()); err == nil {
		t.Fatal("should surface backend error")
	}
	if state, _ := en.GetContainment(id); state.State != "requested" {
		t.Fatal("failed apply recorded as applied")
	}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, _ := en.GetContainment(id); state.State != "applied" || !b.simulator.Active(id) {
		t.Fatal("policy not recorded")
	}
	c.Now = func() time.Time { return start.Add(61 * time.Second) }
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, _ := en.GetContainment(id); state.State != "released" || b.simulator.Active(id) {
		t.Fatalf("ttl failed %+v", state)
	}
}
func TestReleaseFailsAndRetries(t *testing.T) {
	en, id, start := prepare(t)
	b := &flakyBackend{}
	c := &Controller{Engine: en, Backend: b, Mode: "simulate", Now: func() time.Time { return start.Add(3 * time.Second) }}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := en.RequestRelease(id, start.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	b.fail = 1
	if err := c.Reconcile(context.Background()); err == nil {
		t.Fatal("release failure hidden")
	}
	if state, _ := en.GetContainment(id); state.State != "release_requested" || !b.simulator.Active(id) {
		t.Fatal("release wrongly acknowledged")
	}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, _ := en.GetContainment(id); state.State != "released" || b.simulator.Active(id) {
		t.Fatal("release retry failed")
	}
}
