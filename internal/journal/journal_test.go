package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExclusiveWriterLockAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	one, _, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Open(path, 100)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("expected lock error: %v", err)
	}
	if err := one.Close(); err != nil {
		t.Fatal(err)
	}
	two, _, err := Open(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
}

func TestSymlinkAndPermissionsRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	sym := filepath.Join(dir, "symlink")
	if err := os.Symlink(target, sym); err != nil {
		t.Fatal(err)
	}
	if j, _, err := Open(sym, 100); err == nil {
		j.Close()
		t.Fatal("symlink allowed")
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	if j, _, err := Open(target, 100); err == nil {
		j.Close()
		t.Fatal("insecure permissions allowed")
	}
	if err := os.Chmod(target, 0600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hardlink")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	if j, _, err := Open(target, 100); err == nil {
		j.Close()
		t.Fatal("hard linked journal allowed")
	}
}

func TestTornTailIsTruncatedAndSynced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	content := []byte(`{"version":1,"kind":"event","event":{}}` + "\n" + `{"version":1`)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	j, entries, err := Open(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d records", len(entries))
	}
	j.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"version":1,"kind":"event","event":{}}`+"\n" {
		t.Fatalf("truncated to %q", b)
	}
}

func TestMalformedAndOversizeFailClosed(t *testing.T) {
	tests := []string{
		`{"version":1,"kind":"event","event":{},"unexpected":true}` + "\n",
		`{"version":1,"kind":"unknown"}` + "\n",
		strings.Repeat("x", 64*1024+1) + "\n",
	}
	for i, data := range tests {
		path := filepath.Join(t.TempDir(), "journal")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if j, _, err := Open(path, 3); err == nil {
			j.Close()
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestReplayCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	records := strings.Repeat(`{"version":1,"kind":"event","event":{}}`+"\n", 3)
	if err := os.WriteFile(path, []byte(records), 0600); err != nil {
		t.Fatal(err)
	}
	if j, _, err := Open(path, 2); err == nil {
		j.Close()
		t.Fatal("capacity exceeded")
	}
	j, entries, err := Open(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if len(entries) != 3 {
		t.Fatal(len(entries))
	}
}
