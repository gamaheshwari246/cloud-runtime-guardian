package engine

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"cloudruntimeguardian/internal/model"
)

// This intentionally includes fsync cost; it is not a memory-only throughput
// benchmark and is a useful regression baseline on the tester's own disk.
func BenchmarkDurableIngestNoMatch(b *testing.B) {
	en, err := Open(filepath.Join(b.TempDir(), "journal.jsonl"), b.N+1)
	if err != nil {
		b.Fatal(err)
	}
	defer en.Close()
	e := model.Event{
		ID: "placeholder", Type: model.EventProcessExec,
		OccurredAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
		HostID:     "host", BootID: "boot", Workload: model.Workload{ID: "workload"},
		Process: model.Process{EntityID: "same-process", PID: 123, Executable: "/bin/true"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ID = fmt.Sprintf("event-%d", i)
		if _, err := en.Ingest(e); err != nil {
			b.Fatal(err)
		}
	}
}
