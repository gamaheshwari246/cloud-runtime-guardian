package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloudruntimeguardian/internal/model"
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

func TestExternalMutationFailsClosed(t *testing.T) {
	for _, mutation := range []string{"rename-replace", "truncate", "external-append", "chmod", "hardlink"} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ledger.jsonl")
			j, _, err := Open(path, 100)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			if err := j.Append(Entry{Kind: "event", Event: &model.Event{}}); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "rename-replace":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "truncate":
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			case "external-append":
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write([]byte("other process\\n"))
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			case "chmod":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".linked"); err != nil {
					t.Fatal(err)
				}
			}
			if err := j.Append(Entry{Kind: "event", Event: &model.Event{}}); err == nil {
				t.Fatal("accepted write after external mutation")
			}
			if j.Healthy() {
				t.Fatal("journal did not enter failed state")
			}
			if err := j.Append(Entry{Kind: "event", Event: &model.Event{}}); err == nil {
				t.Fatal("poisoned journal accepted write")
			}
		})
	}
}

func TestRejectsTrailingJSONAndGarbage(t *testing.T) {
	for _, suffix := range []string{` {"version":1}`, ` garbage`} {
		path := filepath.Join(t.TempDir(), "ledger")
		content := `{"version":1,"kind":"event","event":{}}` + suffix + "\n"
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if j, _, err := Open(path, 10); err == nil {
			j.Close()
			t.Fatalf("unexpectedly accepted %q", suffix)
		}
	}
}
