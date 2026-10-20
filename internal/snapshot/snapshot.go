// Package snapshot creates verified offline backups of an append-only ledger.
// Snapshots do not prune WAL history or change event idempotency semantics.
package snapshot

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/journal"
)

const (
	formatVersion         = 1
	maxFiles              = 10000
	maxManifest           = 8 << 20
	maxFileSize     int64 = 2 << 30
	maxArchiveBytes int64 = 8 << 30
)

var segmentName = regexp.MustCompile(`^segments/(HEAD|[0-9]{16}\.wal(\.gz)?)$`)
var backupName = regexp.MustCompile(`^crg-[a-zA-Z0-9_-]+\.crg-snapshot\.zip$`)

type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Version     int       `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	RecordCount int       `json:"record_count"`
	Files       []File    `json:"files"`
}

func allowed(name string) bool {
	return name == "journal.jsonl" || segmentName.MatchString(name)
}

func privateOpen(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, fmt.Errorf("unsafe file %s (must be private regular file)", path)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("hardlink not allowed: %s", path)
	}
	return f, nil
}
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func paths(data string) ([]string, error) {
	names := []string{"journal.jsonl"}
	dir := data + ".segments"
	st, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return names, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe WAL directory")
	}
	children, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		name := child.Name()
		if name == "HEAD.tmp" || strings.HasSuffix(name, ".wal.gz.tmp") {
			continue
		} // nonauthoritative interrupted writes
		rel := "segments/" + name
		if !allowed(rel) {
			return nil, fmt.Errorf("unexpected WAL file: %s", name)
		}
		names = append(names, rel)
	}
	sort.Strings(names)
	if len(names) > maxFiles {
		return nil, errors.New("too many backup files")
	}
	return names, nil
}
func sourcePath(data, rel string) string {
	if rel == "journal.jsonl" {
		return data
	}
	return filepath.Join(data+".segments", strings.TrimPrefix(rel, "segments/"))
}
func validateName(name string) error {
	if !allowed(name) || filepath.IsAbs(name) || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return fmt.Errorf("invalid snapshot entry: %q", name)
	}
	return nil
}

// Create takes the ledger's exclusive lock and writes an fsynced temporary ZIP,
// then atomically publishes the backup. Destination must not already exist.
func Create(data, destination string, capacity int) (_ Manifest, err error) {
	if destination == "" || data == "" {
		return Manifest{}, errors.New("ledger and destination required")
	}
	if _, err = os.Lstat(destination); err == nil {
		return Manifest{}, errors.New("backup already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	if _, err = os.Lstat(data); err != nil {
		return Manifest{}, fmt.Errorf("ledger missing: %w", err)
	}
	j, entries, err := journal.Open(data, capacity)
	if err != nil {
		return Manifest{}, err
	}
	defer j.Close()
	files, err := paths(data)
	if err != nil {
		return Manifest{}, err
	}
	dir := filepath.Dir(destination)
	temp, err := os.CreateTemp(dir, ".crg-backup-*.tmp")
	if err != nil {
		return Manifest{}, err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0600); err != nil {
		temp.Close()
		return Manifest{}, err
	}
	defer temp.Close()
	zw := zip.NewWriter(temp)
	m := Manifest{Version: formatVersion, CreatedAt: time.Now().UTC(), RecordCount: len(entries), Files: make([]File, 0, len(files))}
	var total int64
	for _, name := range files {
		f, e := privateOpen(sourcePath(data, name))
		if e != nil {
			zw.Close()
			return Manifest{}, e
		}
		before, e := f.Stat()
		if e != nil {
			f.Close()
			zw.Close()
			return Manifest{}, e
		}
		if before.Size() > maxFileSize || total > maxArchiveBytes-before.Size() {
			f.Close()
			zw.Close()
			return Manifest{}, errors.New("snapshot size limit exceeded")
		}
		writer, e := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if e != nil {
			f.Close()
			zw.Close()
			return Manifest{}, e
		}
		hash := sha256.New()
		n, e := io.Copy(io.MultiWriter(writer, hash), io.LimitReader(f, before.Size()+1))
		after, e2 := f.Stat()
		closeErr := f.Close()
		if e != nil || e2 != nil || closeErr != nil {
			zw.Close()
			return Manifest{}, fmt.Errorf("reading %s: %v %v %v", name, e, e2, closeErr)
		}
		if n != before.Size() || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
			zw.Close()
			return Manifest{}, fmt.Errorf("source changed while backing up: %s", name)
		}
		m.Files = append(m.Files, File{Name: name, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil))})
		total += n
	}
	mw, err := zw.Create("MANIFEST.json")
	if err == nil {
		err = json.NewEncoder(mw).Encode(m)
	}
	if err != nil {
		zw.Close()
		return Manifest{}, err
	}
	if err = zw.Close(); err != nil {
		return Manifest{}, err
	}
	if err = temp.Sync(); err != nil {
		return Manifest{}, err
	}
	if err = temp.Close(); err != nil {
		return Manifest{}, err
	}
	if _, err = os.Lstat(destination); err == nil {
		return Manifest{}, errors.New("destination appeared during backup")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	// Hard-link publication is no-replace on a single filesystem. An interrupted
	// link/remove leaves an independently valid archive, never a partial backup.
	if err = os.Link(temp.Name(), destination); err != nil {
		return Manifest{}, err
	}
	if err = syncDir(dir); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func readManifest(zr *zip.Reader) (Manifest, map[string]*zip.File, error) {
	var m Manifest
	if len(zr.File) < 2 || len(zr.File) > maxFiles+1 {
		return m, nil, errors.New("invalid ZIP entry count")
	}
	files := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		if f.Name != "MANIFEST.json" {
			if err := validateName(f.Name); err != nil {
				return m, nil, err
			}
		}
		if _, ok := files[f.Name]; ok {
			return m, nil, errors.New("duplicate archive entry")
		}
		if f.Mode()&os.ModeSymlink != 0 || !f.Mode().IsRegular() && f.Mode() != 0 {
			return m, nil, errors.New("non-file archive entry")
		}
		files[f.Name] = f
	}
	mf, ok := files["MANIFEST.json"]
	if !ok || mf.UncompressedSize64 > maxManifest {
		return m, nil, errors.New("missing or oversized manifest")
	}
	r, err := mf.Open()
	if err != nil {
		return m, nil, err
	}
	dec := json.NewDecoder(io.LimitReader(r, maxManifest+1))
	dec.DisallowUnknownFields()
	err = dec.Decode(&m)
	var trailing any
	if err == nil && dec.Decode(&trailing) != io.EOF {
		err = errors.New("manifest has trailing data")
	}
	closeErr := r.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return m, nil, err
	}
	if m.Version != formatVersion || m.RecordCount < 0 || m.CreatedAt.IsZero() || len(m.Files) != len(files)-1 || len(m.Files) < 1 || len(m.Files) > maxFiles {
		return m, nil, errors.New("invalid snapshot manifest")
	}
	seen := map[string]bool{}
	hasBase := false
	var total int64
	for _, item := range m.Files {
		if err = validateName(item.Name); err != nil {
			return m, nil, err
		}
		if seen[item.Name] {
			return m, nil, errors.New("duplicate manifest file")
		}
		seen[item.Name] = true
		if item.Name == "journal.jsonl" {
			hasBase = true
		}
		f, ok := files[item.Name]
		if !ok || item.Size < 0 || item.Size > maxFileSize || f.UncompressedSize64 != uint64(item.Size) || len(item.SHA256) != 64 {
			return m, nil, errors.New("invalid file manifest metadata")
		}
		if _, e := hex.DecodeString(item.SHA256); e != nil {
			return m, nil, e
		}
		if total > maxArchiveBytes-item.Size {
			return m, nil, errors.New("snapshot exceeds byte limit")
		}
		total += item.Size
	}
	if !hasBase {
		return m, nil, errors.New("journal missing from manifest")
	}
	return m, files, nil
}

func verifyPayloads(m Manifest, files map[string]*zip.File) error {
	for _, item := range m.Files {
		r, err := files[item.Name].Open()
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(r, item.Size+1))
		closeErr := r.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if n != item.Size || hex.EncodeToString(h.Sum(nil)) != item.SHA256 {
			return fmt.Errorf("snapshot digest mismatch: %s", item.Name)
		}
	}
	return nil
}

func openArchive(path string) (*os.File, *zip.Reader, error) {
	f, err := privateOpen(path)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if st.Size() > maxArchiveBytes || st.Size() <= 0 {
		f.Close()
		return nil, nil, errors.New("archive size invalid")
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, zr, nil
}

// Verify checks archive structure, per-file SHA-256, and ZIP CRCs.
func Verify(path string) (Manifest, error) {
	f, zr, err := openArchive(path)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	m, files, err := readManifest(zr)
	if err != nil {
		return Manifest{}, err
	}
	if err = verifyPayloads(m, files); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Restore verifies the archive, extracts into a private sibling directory,
// replays the ledger, and publishes only a complete verified destination.
// Target directory must not exist; no existing ledger is overwritten.
func Restore(archive, destDir string, capacity int) (Manifest, error) {
	if destDir == "" || capacity < 1 {
		return Manifest{}, errors.New("destination directory and positive capacity required")
	}
	if _, err := os.Lstat(destDir); err == nil {
		return Manifest{}, errors.New("restore destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	f, zr, err := openArchive(archive)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	m, files, err := readManifest(zr)
	if err != nil {
		return Manifest{}, err
	}
	if err = verifyPayloads(m, files); err != nil {
		return Manifest{}, err
	}
	parent := filepath.Dir(destDir)
	stage, err := os.MkdirTemp(parent, ".crg-restore-*")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(stage)
	if err = os.Chmod(stage, 0700); err != nil {
		return Manifest{}, err
	}
	out := map[string]*os.File{}
	closeAll := func() {
		for _, f := range out {
			_ = f.Close()
		}
	}
	defer closeAll()
	for _, item := range m.Files {
		target := filepath.Join(stage, filepath.FromSlash(item.Name))
		if strings.HasPrefix(item.Name, "segments/") {
			target = filepath.Join(stage, "journal.jsonl.segments", strings.TrimPrefix(item.Name, "segments/"))
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return Manifest{}, err
		}
		wf, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return Manifest{}, e
		}
		out[item.Name] = wf
		r, e := files[item.Name].Open()
		if e != nil {
			return Manifest{}, e
		}
		h := sha256.New()
		n, e := io.Copy(io.MultiWriter(wf, h), io.LimitReader(r, item.Size+1))
		closeErr := r.Close()
		if e == nil {
			e = closeErr
		}
		if e == nil && (n != item.Size || hex.EncodeToString(h.Sum(nil)) != item.SHA256) {
			e = fmt.Errorf("digest mismatch extracting %s", item.Name)
		}
		if e == nil {
			e = wf.Sync()
		}
		if e == nil {
			e = wf.Close()
		}
		delete(out, item.Name)
		if e != nil {
			return Manifest{}, e
		}
	}
	if err = syncDir(stage); err != nil {
		return Manifest{}, err
	}
	if _, err = os.Stat(filepath.Join(stage, "journal.jsonl.segments")); err == nil {
		if err = syncDir(filepath.Join(stage, "journal.jsonl.segments")); err != nil {
			return Manifest{}, err
		}
	}
	ledger, entries, err := journal.Open(filepath.Join(stage, "journal.jsonl"), capacity)
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot journal replay rejected: %w", err)
	}
	if len(entries) != m.RecordCount {
		ledger.Close()
		return Manifest{}, errors.New("snapshot record count differs from replay")
	}
	if err = ledger.Close(); err != nil {
		return Manifest{}, err
	}
	// Journal syntax alone is insufficient: validate event/response schemas,
	// idempotency replay and deterministic incident reconstruction too.
	validated, validateErr := engine.Open(filepath.Join(stage, "journal.jsonl"), capacity)
	if validateErr != nil {
		return Manifest{}, fmt.Errorf("snapshot application replay rejected: %w", validateErr)
	}
	if err = validated.Close(); err != nil {
		return Manifest{}, err
	}
	if _, err = os.Lstat(destDir); err == nil {
		return Manifest{}, errors.New("restore destination appeared")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	if err = os.Rename(stage, destDir); err != nil {
		return Manifest{}, err
	}
	if err = syncDir(parent); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Prune removes only named, individually verified backup files, retaining at
// least two of the newest. It never deletes WAL or event data.
func Prune(dir string, keep int) (int, error) {
	if keep < 2 {
		return 0, errors.New("keep must be at least 2")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	type archive struct {
		name string
		mod  time.Time
	}
	var items []archive
	for _, entry := range entries {
		if !backupName.MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		st, err := os.Lstat(path)
		if err != nil {
			return 0, err
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return 0, fmt.Errorf("unsafe backup: %s", path)
		}
		if _, err = Verify(path); err != nil {
			return 0, fmt.Errorf("backup %s failed verification: %w", path, err)
		}
		items = append(items, archive{entry.Name(), st.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].mod.Equal(items[j].mod) {
			return items[i].name > items[j].name
		}
		return items[i].mod.After(items[j].mod)
	})
	removed := 0
	for _, item := range items[min(keep, len(items)):] {
		if err = os.Remove(filepath.Join(dir, item.name)); err != nil {
			return removed, err
		}
		if err = syncDir(dir); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
