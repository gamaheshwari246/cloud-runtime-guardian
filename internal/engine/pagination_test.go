package engine

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"cloudruntimeguardian/internal/incidentindex"
	"cloudruntimeguardian/internal/model"
)

func ingestIncident(t *testing.T, en *Engine, n int, when time.Time) {
	t.Helper()
	shell, conn := testEvents()
	shell.ID = fmt.Sprintf("shell-%06d", n)
	conn.ID = fmt.Sprintf("conn-%06d", n)
	shell.Process.EntityID = fmt.Sprintf("proc-%06d", n)
	conn.Process.EntityID = shell.Process.EntityID
	shell.OccurredAt = when
	conn.OccurredAt = when.Add(10 * time.Second)
	mustIngest(t, en, shell)
	mustIngest(t, en, conn)
}

func TestIndexedPaginationStableAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	en, err := Open(path, 500)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 31; i++ {
		ingestIncident(t, en, i, at.Add(time.Duration(i/3)*time.Minute))
	}
	first, total, next, err := en.ListCursor(9, "")
	if err != nil || total != 31 || len(first) != 9 || next == "" {
		t.Fatalf("first: %v %d %d %q", err, total, len(first), next)
	}
	existing := make(map[string]bool)
	for _, in := range first {
		existing[in.ID] = true
	}
	// New incidents sort before the cursor, but may not shift this page.
	ingestIncident(t, en, 999, at.Add(24*time.Hour))
	second, _, cursor, err := en.ListCursor(9, next)
	if err != nil || len(second) != 9 || cursor == "" {
		t.Fatalf("next: %v %d %q", err, len(second), cursor)
	}
	for _, in := range second {
		if existing[in.ID] {
			t.Fatal("duplicate across pages")
		}
		existing[in.ID] = true
	}
	byOffset, gotTotal := en.List(9, 1)
	if gotTotal != 32 || len(byOffset) != 9 || byOffset[0].ID != first[0].ID {
		t.Fatalf("offset mismatch: %d %+v", gotTotal, byOffset)
	}
	if err := en.Close(); err != nil {
		t.Fatal(err)
	}
	en, err = Open(path, 500)
	if err != nil {
		t.Fatal(err)
	}
	defer en.Close()
	again, _, _, err := en.ListCursor(9, next)
	if err != nil || len(again) != len(second) {
		t.Fatal("recovery page mismatch", err)
	}
	for i := range second {
		if second[i].ID != again[i].ID {
			t.Fatalf("restart changed page %d", i)
		}
	}
	if _, _, _, err := en.ListCursor(10, "!notbase64"); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("accepted invalid cursor", err)
	}
	if _, _, _, err := en.ListCursor(0, ""); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("accepted invalid limit", err)
	}
}

func TestCursorAfterAllRows(t *testing.T) {
	en, _ := openTest(t)
	shell, conn := testEvents()
	mustIngest(t, en, shell)
	mustIngest(t, en, conn)
	first, total, next, err := en.ListCursor(1, "")
	if err != nil || total != 1 || next != "" || len(first) != 1 {
		t.Fatal("wrong final cursor")
	}
	if _, _, _, err := en.ListCursor(1, encodeCursor(incidentKey(first[0]))); err != nil {
		t.Fatal(err)
	}
}
func incidentKey(in model.Incident) incidentindex.Key {
	return incidentindex.Key{At: in.FirstSeen, ID: in.ID}
}
