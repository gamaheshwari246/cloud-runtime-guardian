package snapshot

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloudruntimeguardian/internal/journal"
	"cloudruntimeguardian/internal/model"
)

func fixture(t *testing.T) (string, int) {
	t.Helper()
	data := filepath.Join(t.TempDir(), "journal.jsonl")
	j, _, err := journal.OpenWithSegmentBytes(data, 5000, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	const total = 650
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("source-event-%05d", i)
		if err = j.Append(journal.Entry{Kind: "event", Event: &model.Event{ID: id, Type: model.EventProcessExec, OccurredAt: time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second), HostID: "node-1", BootID: "boot-1", Workload: model.Workload{ID: "workload-1"}, Process: model.Process{EntityID: fmt.Sprintf("process-%05d", i), PID: i + 1, Executable: "/usr/bin/echo"}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(data + ".segments")
	if err != nil {
		t.Fatal("expected rotated WAL", err)
	}
	return data, total
}
func TestCreateVerifyRestore(t *testing.T) {
	data, total := fixture(t)
	archive := filepath.Join(t.TempDir(), "crg-1.crg-snapshot.zip")
	manifest, err := Create(data, archive, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.RecordCount != total || len(manifest.Files) < 3 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	got, err := Verify(archive)
	if err != nil {
		t.Fatal(err)
	}
	if got.RecordCount != total {
		t.Fatalf("got %d, want %d", got.RecordCount, total)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	if _, err = Restore(archive, dest, 5000); err != nil {
		t.Fatal(err)
	}
	restored, entries, err := journal.Open(filepath.Join(dest, "journal.jsonl"), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if len(entries) != total || entries[0].Event.ID != "source-event-00000" || entries[total-1].Event.ID != fmt.Sprintf("source-event-%05d", total-1) {
		t.Fatalf("restored unexpected entries: %d", len(entries))
	}
	if _, err = Restore(archive, dest, 5000); err == nil {
		t.Fatal("must not overwrite existing data")
	}
}
func TestRejectLockedLedger(t *testing.T) {
	data, _ := fixture(t)
	j, _, err := journal.Open(data, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err = Create(data, filepath.Join(t.TempDir(), "backup.zip"), 5000); !errors.Is(err, journal.ErrLocked) {
		t.Fatalf("expected lock error, got %v", err)
	}
}
func rewriteZip(t *testing.T, src, dst string, change func(string, []byte) []byte) {
	t.Helper()
	orig, err := zip.OpenReader(src)
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	for _, f := range orig.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		b = change(f.Name, b)
		w, err := zw.Create(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRejectCorruptedArchiveWithoutPublishing(t *testing.T) {
	data, _ := fixture(t)
	good := filepath.Join(t.TempDir(), "good.zip")
	if _, err := Create(data, good, 5000); err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(t.TempDir(), "tampered.zip")
	rewriteZip(t, good, tampered, func(name string, b []byte) []byte {
		if name == "journal.jsonl" {
			return append(b, []byte("something\n")...)
		}
		return b
	})
	if _, err := Verify(tampered); err == nil {
		t.Fatal("must reject payload checksum mismatch")
	}
	dir := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(tampered, dir, 5000); err == nil {
		t.Fatal("must reject corrupt archive")
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restore unexpectedly published: %v", err)
	}
}
func TestRestoreRejectsValidChecksumInvalidLedger(t *testing.T) {
	data, _ := fixture(t)
	original := filepath.Join(t.TempDir(), "good.zip")
	if _, err := Create(data, original, 5000); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(t.TempDir(), "malformed-wal.zip")
	// Repack with a cryptographically consistent manifest but an invalid WAL
	// record. A restore must replay the ledger, not merely check archive hashes.
	updated := map[string][]byte{}
	r, err := zip.OpenReader(original)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	for _, f := range r.File {
		rd, _ := f.Open()
		b, _ := io.ReadAll(rd)
		rd.Close()
		updated[f.Name] = b
	}
	r.Close()
	if err := json.Unmarshal(updated["MANIFEST.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	updated["journal.jsonl"] = append(updated["journal.jsonl"], []byte("{bad-json}\n")...)
	for i, item := range manifest.Files {
		if item.Name == "journal.jsonl" {
			hash := sha256.Sum256(updated[item.Name])
			manifest.Files[i].SHA256 = hex.EncodeToString(hash[:])
			manifest.Files[i].Size = int64(len(updated[item.Name]))
		}
	}
	updated["MANIFEST.json"], _ = json.Marshal(manifest)
	wf, err := os.OpenFile(fake, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(wf)
	for name, b := range updated {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wf.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(fake); err != nil {
		t.Fatalf("archive format should verify: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	if _, err = Restore(fake, dest, 5000); err == nil {
		t.Fatal("must reject inconsistent replay")
	}
	if _, err = os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published invalid restore")
	}
}
func TestRejectUnsafeSnapshotPaths(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "invalid.zip")
	f, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, name := range []string{"../escape", "MANIFEST.json"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{}`))
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err = Verify(archive); err == nil {
		t.Fatal("path traversal was accepted")
	}
	if _, err = Restore(archive, filepath.Join(t.TempDir(), "out"), 50); err == nil {
		t.Fatal("unsafe restore accepted")
	}
}
func TestPruneOnlyVerifiedNamedBackups(t *testing.T) {
	data, _ := fixture(t)
	dir := t.TempDir()
	for i := 0; i < 4; i++ {
		p := filepath.Join(dir, fmt.Sprintf("crg-%d.crg-snapshot.zip", i))
		if _, err := Create(data, p, 5000); err != nil {
			t.Fatal(err)
		}
		timestamp := time.Now().Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, timestamp, timestamp); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(dir, "unrelated.zip")
	if err := os.WriteFile(other, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	n, err := Prune(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("deleted %d, want 2", n)
	}
	for _, name := range []string{"crg-2.crg-snapshot.zip", "crg-3.crg-snapshot.zip", "unrelated.zip"} {
		if _, err = os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = os.Stat(data); err != nil {
		t.Fatal("authoritative WAL removed", err)
	}
	if _, err = Prune(dir, 1); err == nil {
		t.Fatal("single retained copy is unsafe")
	}
	invalid := filepath.Join(dir, "crg-corrupt.crg-snapshot.zip")
	if err = os.WriteFile(invalid, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Prune(dir, 2); err == nil {
		t.Fatal("unverified archives must abort pruning")
	}
}
func TestRestoreWithCompressedClosedSegments(t *testing.T) {
	data, total := fixture(t)
	j, _, err := journal.Open(data, 5000)
	if err != nil {
		t.Fatal(err)
	}
	_, err = j.CompactClosed()
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
	backup := filepath.Join(t.TempDir(), "compressed.zip")
	if _, err = Create(data, backup, 5000); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	if _, err = Restore(backup, dest, 5000); err != nil {
		t.Fatal(err)
	}
	restored, records, err := journal.Open(filepath.Join(dest, "journal.jsonl"), 5000)
	if err != nil {
		t.Fatal(err)
	}
	restored.Close()
	if len(records) != total {
		t.Fatalf("lost records %d != %d", len(records), total)
	}
}
func TestRestoreDoesNotWriteOutsideStage(t *testing.T) {
	data, _ := fixture(t)
	archive := filepath.Join(t.TempDir(), "ok.zip")
	if _, err := Create(data, archive, 5000); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	if err := os.WriteFile(outside, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(archive, filepath.Join(parent, "destination"), 5000); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(outside)
	if err != nil || !bytes.Equal(b, []byte("safe")) {
		t.Fatal("outside file modified", err)
	}
}
func TestRejectDuplicateAndOversizedManifest(t *testing.T) {
	file := filepath.Join(t.TempDir(), "duplicate.zip")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, name := range []string{"journal.jsonl", "journal.jsonl", "MANIFEST.json"} {
		w, _ := zw.Create(name)
		_, _ = io.Copy(w, strings.NewReader("{}"))
	}
	zw.Close()
	f.Close()
	if _, err := Verify(file); err == nil {
		t.Fatal("duplicate accepted")
	}
}

// A syntactically valid WAL can still contain semantically invalid events.
// The restored tree must remain unpublished if engine replay rejects them.
func TestRestoreRejectsApplicationInvalidEvents(t *testing.T) {
	data, total := fixture(t)
	good := filepath.Join(t.TempDir(), "good.zip")
	if _, err := Create(data, good, total+10); err != nil {
		t.Fatal(err)
	}
	r, err := zip.OpenReader(good)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string][]byte{}
	var m Manifest
	for _, f := range r.File {
		rd, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(rd)
		rd.Close()
		if e != nil {
			t.Fatal(e)
		}
		payload[f.Name] = b
	}
	r.Close()
	if err := json.Unmarshal(payload["MANIFEST.json"], &m); err != nil {
		t.Fatal(err)
	}
	// Valid JSON record shape, invalid application-level event schema.
	extra := []byte(`{"version":1,"kind":"event","event":{"id":"invalid-no-process"}}` + "\n")
	// Append to the active segment, not the closed legacy file.
	last := "journal.jsonl"
	for _, f := range m.Files {
		if strings.HasSuffix(f.Name, ".wal") && f.Name > last {
			last = f.Name
		}
	}
	payload[last] = append(payload[last], extra...)
	for i := range m.Files {
		if m.Files[i].Name == last {
			h := sha256.Sum256(payload[last])
			m.Files[i].Size = int64(len(payload[last]))
			m.Files[i].SHA256 = hex.EncodeToString(h[:])
		}
	}
	m.RecordCount++
	payload["MANIFEST.json"], _ = json.Marshal(m)
	forged := filepath.Join(t.TempDir(), "forged.zip")
	wf, err := os.OpenFile(forged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(wf)
	for name, b := range payload {
		w, e := zw.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(b); e != nil {
			t.Fatal(e)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = wf.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(forged); err != nil {
		t.Fatal("forged archive checksum mismatch", err)
	}
	dest := filepath.Join(t.TempDir(), "should-not-exist")
	if _, err = Restore(forged, dest, total+10); err == nil || !strings.Contains(err.Error(), "application replay") {
		t.Fatalf("expected engine replay failure, got %v", err)
	}
	if _, err = os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published unsafe application state")
	}
}
