package collector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// A rotation can occur between collector invocations. The old inode must be
// drained from the retained archive before the new live file is read.
func TestResumeAcrossRenameRotation(t *testing.T) {
	cfg, path := setup(t)
	var received []string
	send := SenderFunc(func(_ context.Context, b []byte) error {
		var e struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(b, &e); err != nil {
			return err
		}
		received = append(received, e.ID)
		return nil
	})
	write(t, path, testExec+"\n")
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	// An event was added to the old file after the previous checkpoint.
	f, err := os.OpenFile(path+".1", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(testConnect + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	write(t, path, testExec+"\n")
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if len(received) != 3 {
		t.Fatalf("expected 3 events, got %d", len(received))
	}
	for i := range received {
		for j := i + 1; j < len(received); j++ {
			if received[i] == received[j] {
				t.Fatalf("duplicate ID after rotation: %s", received[i])
			}
		}
	}
	cp, exists, err := load(cfg.CheckpointPath)
	if err != nil || !exists || cp.Offset != int64(len(testExec)+1) {
		t.Fatalf("bad new-file checkpoint: %+v, %v", cp, err)
	}
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if len(received) != 3 {
		t.Fatalf("duplicate replayed events: %d", len(received))
	}
}

func TestRotationMustPreserveIncompleteLines(t *testing.T) {
	cfg, path := setup(t)
	write(t, path, testExec+"\n"+testExec)
	count := 0
	send := SenderFunc(func(context.Context, []byte) error { count++; return nil })
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	write(t, path, testConnect+"\n")
	if err := Run(context.Background(), cfg, send); err == nil || !strings.Contains(err.Error(), "incomplete line") {
		t.Fatalf("expected incomplete-line error: %v", err)
	}
	if count != 1 {
		t.Fatalf("partial line was processed, sends: %d", count)
	}
}

func TestRotationRejectsAmbiguousArchives(t *testing.T) {
	cfg, path := setup(t)
	write(t, path, testExec+"\n")
	send := SenderFunc(func(context.Context, []byte) error { return nil })
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	write(t, path+".2", testConnect+"\n")
	write(t, path, testExec+"\n")
	if err := Run(context.Background(), cfg, send); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("unexpected success with hidden intermediate rotation: %v", err)
	}
}

func TestRotationNewCheckpointSurvivesFailedSend(t *testing.T) {
	cfg, path := setup(t)
	write(t, path, testExec+"\n")
	okSender := SenderFunc(func(context.Context, []byte) error { return nil })
	if err := Run(context.Background(), cfg, okSender); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	write(t, path, testConnect+"\n")
	failSender := SenderFunc(func(context.Context, []byte) error { return errors.New("injection: unavailable") })
	if err := Run(context.Background(), cfg, failSender); err == nil {
		t.Fatal("expected send failure")
	}
	cp, exists, err := load(cfg.CheckpointPath)
	if err != nil || !exists || cp.Offset != 0 {
		t.Fatalf("rotation checkpoint should be at byte zero: %+v, %v", cp, err)
	}
	// We can now remove the old export because its data is durably acknowledged.
	if err := os.Remove(path + ".1"); err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := Run(context.Background(), cfg, SenderFunc(func(context.Context, []byte) error { count++; return nil })); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected recovered event: got %d", count)
	}
}

func TestCollectorRejectsExportSymlink(t *testing.T) {
	cfg, path := setup(t)
	target := path + ".target"
	write(t, target, testExec+"\n")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := Run(context.Background(), cfg, SenderFunc(func(context.Context, []byte) error { return nil })); err == nil {
		t.Fatal("expected symlink rejection")
	}
}
