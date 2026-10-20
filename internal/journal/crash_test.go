package journal

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"cloudruntimeguardian/internal/model"
)

// A separate process is killed without running defers or Close. Its fully
// fsynced record must survive and the advisory file lock must be released.
func TestKilledWriterRecovery(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux file-lock and SIGKILL semantics")
	}
	if path := os.Getenv("CRG_CRASH_TEST_PATH"); path != "" {
		j, _, err := Open(path, 100)
		if err != nil {
			panic(err)
		}
		if err := j.Append(Entry{Kind: "event", Event: &model.Event{ID: "committed-before-kill"}}); err != nil {
			panic(err)
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		panic("SIGKILL failed")
	}
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	child := exec.Command(os.Args[0], "-test.run=^TestKilledWriterRecovery$")
	child.Env = append(os.Environ(), "CRG_CRASH_TEST_PATH="+path)
	if output, err := child.CombinedOutput(); err == nil {
		t.Fatalf("child unexpectedly exited successfully: %s", output)
	}
	j, entries, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if len(entries) != 1 || entries[0].Event.ID != "committed-before-kill" {
		t.Fatalf("lost fsynced event: %+v", entries)
	}
	if err := j.Append(Entry{Kind: "event", Event: &model.Event{ID: "after-recovery"}}); err != nil {
		t.Fatal(err)
	}
}

// Kill after enough fsynced appends to force multiple WAL rotations. The HEAD
// high-watermark and all acknowledged records must survive a SIGKILL.
func TestKilledWriterAfterSegmentRotation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux file-lock and SIGKILL semantics")
	}
	if path := os.Getenv("CRG_SEGMENT_CRASH_PATH"); path != "" {
		j, _, err := OpenWithSegmentBytes(path, 200, 65536)
		if err != nil {
			panic(err)
		}
		for i := 0; i < 7; i++ {
			if err := j.Append(bulkEntry(i)); err != nil {
				panic(err)
			}
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		panic("SIGKILL failed")
	}
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	child := exec.Command(os.Args[0], "-test.run=^TestKilledWriterAfterSegmentRotation$")
	child.Env = append(os.Environ(), "CRG_SEGMENT_CRASH_PATH="+path)
	if output, err := child.CombinedOutput(); err == nil {
		t.Fatalf("unexpected child success: %s", output)
	}
	j, entries, err := OpenWithSegmentBytes(path, 200, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if len(entries) != 7 {
		t.Fatalf("lost fsynced event after rotation: got %d", len(entries))
	}
	if err := j.Append(Entry{Kind: "event", Event: &model.Event{ID: "post-crash"}}); err != nil {
		t.Fatal(err)
	}
}
