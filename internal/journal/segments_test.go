package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloudruntimeguardian/internal/model"
)

func bulkEntry(i int) Entry {
	return Entry{Kind: "event", Event: &model.Event{ID: strings.Repeat(string(rune('a'+i%26)), 25000)}}
}
func appendBulk(t *testing.T, j *Journal, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		if err := j.Append(bulkEntry(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}
func TestSegmentReplayAndLosslessCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.jsonl")
	// Legacy format remains at the original path for migration compatibility.
	legacy := []byte(`{"version":1,"kind":"event","event":{"id":"old"}}` + "\n")
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	j, old, err := OpenWithSegmentBytes(path, 100, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 1 || old[0].Event.ID != "old" {
		t.Fatalf("legacy replay failed: %+v", old)
	}
	appendBulk(t, j, 7)
	if j.segmentNumber < 3 {
		t.Fatalf("expected at least three segments, got %d", j.segmentNumber)
	}
	if n, err := j.CompactClosed(); err != nil || n < 2 {
		t.Fatalf("compress: %d, %v", n, err)
	}
	if _, err := os.Stat(walPath(path+".segments", 1) + ".gz"); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, got, err := OpenWithSegmentBytes(path, 100, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 {
		t.Fatalf("unexpected count %d", len(got))
	}
	if got[0].Event.ID != "old" {
		t.Fatal("lost legacy entry")
	}
	if err := j.Append(Entry{Kind: "event", Event: &model.Event{ID: "after-reopen"}}); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, got, err = OpenWithSegmentBytes(path, 100, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if len(got) != 9 || got[8].Event.ID != "after-reopen" {
		t.Fatalf("lost replay ordering: %d", len(got))
	}
	if n, err := j.CompactClosed(); err != nil || n != 0 {
		t.Fatalf("repeat compaction: %d, %v", n, err)
	}
}
func TestMissingMiddleOrNewestSegmentFailsClosed(t *testing.T) {
	for _, which := range []uint64{1, 3} {
		t.Run(string(rune('0'+which)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "log")
			j, _, err := OpenWithSegmentBytes(path, 100, 65536)
			if err != nil {
				t.Fatal(err)
			}
			appendBulk(t, j, 7)
			last := j.segmentNumber
			j.Close()
			n := which
			if n == 3 {
				n = last
			}
			if err := os.Remove(walPath(path+".segments", n)); err != nil {
				t.Fatal(err)
			}
			if recovered, _, err := OpenWithSegmentBytes(path, 100, 65536); err == nil {
				recovered.Close()
				t.Fatal("deleted segment not detected")
			}
		})
	}
}
func TestTornActiveTailButNotClosedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	j, _, err := OpenWithSegmentBytes(path, 100, 65536)
	if err != nil {
		t.Fatal(err)
	}
	appendBulk(t, j, 7)
	active := j.activePath
	j.Close()
	f, err := os.OpenFile(active, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte(`{"version":1,"kind":"event"`))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	j, got, err := OpenWithSegmentBytes(path, 100, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 {
		t.Fatalf("got %d", len(got))
	}
	j.Close()
	// Corrupting the tail of a closed segment is never silently truncated.
	first := walPath(path+".segments", 1)
	f, err = os.OpenFile(first, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("partial"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if x, _, err := OpenWithSegmentBytes(path, 100, 65536); err == nil {
		x.Close()
		t.Fatal("accepted torn closed segment")
	}
}
func TestCrashWindowsOrphanAndDuplicateArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	j, _, err := OpenWithSegmentBytes(path, 100, 65536)
	if err != nil {
		t.Fatal(err)
	}
	appendBulk(t, j, 7)
	last := j.segmentNumber
	if _, err = j.CompactClosed(); err != nil {
		t.Fatal(err)
	}
	j.Close()
	// A crash between archive rename and unlink leaves two equivalent copies.
	one := walPath(path+".segments", 1)
	if _, err := os.Stat(one + ".gz"); err != nil {
		t.Fatal(err)
	}
	// Compression is already durable and the old WAL was removed. A deliberate
	// mismatch between matching archive/plain paths is always rejected.
	if err = os.WriteFile(one, []byte("different"), 0600); err != nil {
		t.Fatal(err)
	}
	if x, _, err := OpenWithSegmentBytes(path, 100, 65536); err == nil {
		x.Close()
		t.Fatal("conflicting archive accepted")
	}
	if err = os.Remove(one); err != nil {
		t.Fatal(err)
	}
	// A newly-created but empty, not-yet-manifested next WAL may be adopted.
	orphan := walPath(path+".segments", last+1)
	if err = os.WriteFile(orphan, nil, 0600); err != nil {
		t.Fatal(err)
	}
	x, _, err := OpenWithSegmentBytes(path, 100, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if x.segmentNumber != last+1 {
		t.Fatal("orphan was not adopted")
	}
	x.Close()
	// But a data-bearing orphan must not be adopted.
	next := walPath(path+".segments", last+2)
	if err = os.WriteFile(next, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if x, _, err := OpenWithSegmentBytes(path, 100, 65536); err == nil {
		x.Close()
		t.Fatal("adopted nonempty orphan")
	}
}
func TestWriterLockSpansSegments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	j, _, err := OpenWithSegmentBytes(path, 100, 65536)
	if err != nil {
		t.Fatal(err)
	}
	appendBulk(t, j, 5)
	if other, _, err := OpenWithSegmentBytes(path, 100, 65536); !errors.Is(err, ErrLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("other writer allowed %v", err)
	}
	j.Close()
}
