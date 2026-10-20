package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"cloudruntimeguardian/internal/model"
)

var baseTime = time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)

func testEvents() (model.Event, model.Event) {
	base := model.Event{HostID: "node-1", BootID: "boot-A", Workload: model.Workload{ID: "payments", Namespace: "test", Pod: "pay-1"}, Process: model.Process{EntityID: "proc-unique-1", PID: 42}}
	shell := base
	shell.ID = "evt-shell"
	shell.Type = model.EventProcessExec
	shell.Process.Executable = "/bin/sh"
	shell.OccurredAt = baseTime
	conn := base
	conn.ID = "evt-conn"
	conn.Type = model.EventNetworkConnect
	conn.OccurredAt = baseTime.Add(10 * time.Second)
	conn.Network = &model.Network{DestinationIP: "1.1.1.1", DestinationPort: 443, Protocol: "tcp"}
	return shell, conn
}
func openTest(t *testing.T) (*Engine, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	en, err := Open(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { en.Close() })
	return en, path
}
func mustIngest(t *testing.T, en *Engine, e model.Event) {
	t.Helper()
	created, err := en.Ingest(e)
	if err != nil || !created {
		t.Fatalf("ingest %s created=%v err=%v", e.ID, created, err)
	}
}
func TestCorrelatesInEitherArrivalOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint("reverse-", reverse), func(t *testing.T) {
			en, _ := openTest(t)
			shell, conn := testEvents()
			if reverse {
				mustIngest(t, en, conn)
				mustIngest(t, en, shell)
			} else {
				mustIngest(t, en, shell)
				mustIngest(t, en, conn)
			}
			got, count := en.List(100, 0)
			if count != 1 || len(got) != 1 {
				t.Fatalf("want 1 incident; got %d", count)
			}
			in := got[0]
			if in.RuleID != model.RuleShellEgress || in.Evidence[0].EventID != shell.ID || in.Evidence[1].EventID != conn.ID {
				t.Fatalf("wrong incident: %+v", in)
			}
		})
	}
}
func TestNoCrossBoundaryCorrelation(t *testing.T) {
	for _, scenario := range []string{"host", "boot", "workload", "process", "earlier", "too-late", "internal-ip", "non-shell", "unrelated-pid"} {
		t.Run(scenario, func(t *testing.T) {
			en, _ := openTest(t)
			shell, conn := testEvents()
			switch scenario {
			case "host":
				conn.HostID = "node-2"
			case "boot":
				conn.BootID = "boot-B"
			case "workload":
				conn.Workload.ID = "unrelated"
			case "process":
				conn.Process.EntityID = "different-process"
			case "earlier":
				conn.OccurredAt = baseTime.Add(-time.Second)
			case "too-late":
				conn.OccurredAt = baseTime.Add(model.Window + time.Second)
			case "internal-ip":
				conn.Network.DestinationIP = "10.3.0.5"
			case "non-shell":
				shell.Process.Executable = "/usr/bin/ls"
			case "unrelated-pid":
				conn.Process.PID = 42
				conn.Process.EntityID = "reused-identifier-is-different"
			}
			mustIngest(t, en, shell)
			mustIngest(t, en, conn)
			if got := en.Stats().Incidents; got != 0 {
				t.Fatalf("false positive: %d incidents", got)
			}
		})
	}
}
func TestImmediateChildProcessJoin(t *testing.T) {
	en, _ := openTest(t)
	shell, conn := testEvents()
	conn.Process.EntityID = "child-proc"
	conn.Process.ParentEntityID = shell.Process.EntityID
	mustIngest(t, en, conn)
	mustIngest(t, en, shell)
	if got := en.Stats().Incidents; got != 1 {
		t.Fatalf("child linkage failed: %d", got)
	}
}
func TestRetryConflictAndRecovery(t *testing.T) {
	en, path := openTest(t)
	shell, conn := testEvents()
	mustIngest(t, en, shell)
	mustIngest(t, en, conn)
	if created, err := en.Ingest(shell); err != nil || created {
		t.Fatalf("retry created=%v err=%v", created, err)
	}
	conflict := shell
	conflict.Process.Executable = "/bin/bash"
	if _, err := en.Ingest(conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("expect conflict, got %v", err)
	}
	if err := en.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Stats().Events != 2 || reopened.Stats().Incidents != 1 {
		t.Fatalf("restart lost state: %+v", reopened.Stats())
	}
	if created, err := reopened.Ingest(shell); err != nil || created {
		t.Fatalf("restart retry created=%v err=%v", created, err)
	}
}
func TestDurableDryRunNoEnforcement(t *testing.T) {
	en, path := openTest(t)
	shell, conn := testEvents()
	mustIngest(t, en, shell)
	mustIngest(t, en, conn)
	items, _ := en.List(1, 0)
	id := items[0].ID
	req := model.ResponseAction{RequestID: "req-1", IncidentID: id, Action: "block_workload_egress", Reason: "Test detection; approval pending"}
	r, created, err := en.DryRunResponse(req)
	if err != nil || !created || r.Mode != "dry_run" || r.EnforcementApplied {
		t.Fatalf("unsafe action: %+v %v", r, err)
	}
	_, created, err = en.DryRunResponse(req)
	if err != nil || created {
		t.Fatalf("response not idempotent: %v %v", created, err)
	}
	modified := req
	modified.Reason = "another reason"
	if _, _, err = en.DryRunResponse(modified); !errors.Is(err, ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	if err := en.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	inc, ok := reopened.Get(id)
	if !ok || len(inc.Responses) != 1 || inc.Responses[0].EnforcementApplied {
		t.Fatalf("unsafe replay: %+v", inc)
	}
}
func TestMaximumEventsBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	en, err := Open(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer en.Close()
	shell, conn := testEvents()
	mustIngest(t, en, shell)
	if _, err := en.Ingest(conn); !errors.Is(err, ErrFull) {
		t.Fatalf("want capacity error, got %v", err)
	}
	if created, err := en.Ingest(shell); err != nil || created {
		t.Fatalf("duplicate should be accepted even when full")
	}
}
func TestConcurrentIngestion(t *testing.T) {
	en, _ := openTest(t)
	shell, conn := testEvents()
	var wg sync.WaitGroup
	errs := make(chan error, 60)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sh := shell
			co := conn
			sh.ID = fmt.Sprintf("shell-%d", i)
			co.ID = fmt.Sprintf("conn-%d", i)
			sh.Process.EntityID = fmt.Sprintf("proc-%d", i)
			co.Process.EntityID = sh.Process.EntityID
			if _, err := en.Ingest(co); err != nil {
				errs <- err
			}
			if _, err := en.Ingest(sh); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := en.Stats(); got.Events != 40 || got.Incidents != 20 {
		t.Fatalf("concurrent result %+v", got)
	}
}
func TestTruncatedTailRecoveredAndCommittedCorruptionRejected(t *testing.T) {
	en, path := openTest(t)
	shell, _ := testEvents()
	mustIngest(t, en, shell)
	en.Close()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"version":1,"kind":"event","event":`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	recovered, err := Open(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Stats().Events != 1 {
		t.Fatalf("torn record replayed")
	}
	recovered.Close()
	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not-json\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Open(path, 1000); err == nil {
		t.Fatal("corrupted committed record was ignored")
	}
}

func TestProcessIndexDoesNotCrossEntities(t *testing.T) {
	en, _ := openTest(t)
	shell, conn := testEvents()
	for i := 0; i < 200; i++ {
		other := conn
		other.ID = fmt.Sprintf("unrelated-%03d", i)
		other.Process.EntityID = fmt.Sprintf("other-proc-%03d", i)
		other.Process.ParentEntityID = ""
		mustIngest(t, en, other)
	}
	mustIngest(t, en, shell)
	if _, count := en.List(10, 0); count != 0 {
		t.Fatalf("unrelated entities produced %d incidents", count)
	}
	// A child process that sent a connection before the shell's event
	// arrived must still link to the parent shell by stable entity ID.
	child := conn
	child.ID = "conn-child"
	child.Process.EntityID = "child-proc"
	child.Process.ParentEntityID = shell.Process.EntityID
	mustIngest(t, en, child)
	if _, count := en.List(10, 0); count != 1 {
		t.Fatalf("child correlation expected 1 incident, got %d", count)
	}
}

func TestDryRunResponseCapacityAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.journal")
	en, err := Open(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	shell, conn := testEvents()
	mustIngest(t, en, shell)
	mustIngest(t, en, conn)
	entries, _ := en.List(1, 0)
	if len(entries) != 1 {
		t.Fatal("missing incident")
	}
	action := model.ResponseAction{IncidentID: entries[0].ID, Action: "block_workload_egress", Reason: "test proposal", RequestID: "r-1"}
	if _, created, err := en.DryRunResponse(action); err != nil || !created {
		t.Fatalf("first response: %v", err)
	}
	action.RequestID = "r-2"
	if _, created, err := en.DryRunResponse(action); err != nil || !created {
		t.Fatalf("second response: %v", err)
	}
	action.RequestID = "r-3"
	if _, _, err := en.DryRunResponse(action); !errors.Is(err, ErrFull) {
		t.Fatalf("expected capacity error, got %v", err)
	}
	if err := en.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if stats := reopened.Stats(); stats.DryRunResponses != 2 {
		t.Fatalf("responses lost on restart: %+v", stats)
	}
}
