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
