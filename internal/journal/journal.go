// Package journal implements a single-writer, fsynced append-only ledger.
// Legacy JSONL files remain the first (locked) segment; newer segments use
// numbered WAL files. All committed records remain replayable indefinitely.
package journal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"cloudruntimeguardian/internal/model"
)

const (
	maxLineBytes              = 64 * 1024
	DefaultSegmentBytes int64 = 8 << 20
)

var ErrLocked = errors.New("journal already has a writer")

type Entry struct {
	Version     int                   `json:"version"`
	Kind        string                `json:"kind"`
	Event       *model.Event          `json:"event,omitempty"`
	Response    *model.ResponseAction `json:"response,omitempty"`
	Containment *model.Containment    `json:"containment,omitempty"`
}

type Journal struct {
	base          *os.File // locked legacy path (also serializes all segment operations)
	file          *os.File // currently writable WAL, or base for legacy-only journals
	path          string
	activePath    string
	baseSize      int64
	expectedSize  int64
	segmentNumber uint64
	segmentBytes  int64
	failed        bool
}

func Open(path string, maxRecords int) (*Journal, []Entry, error) {
	return OpenWithSegmentBytes(path, maxRecords, DefaultSegmentBytes)
}

// OpenWithSegmentBytes permits deterministic tiny segments in tests. Segment
// size applies to new writes; an existing legacy file may be larger.
func OpenWithSegmentBytes(path string, maxRecords int, segmentBytes int64) (*Journal, []Entry, error) {
	if maxRecords < 1 || path == "" || segmentBytes < maxLineBytes || segmentBytes > (1<<30) {
		return nil, nil, errors.New("journal path, positive replay capacity, and segment size 64KiB..1GiB required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	base, err := secureOpen(path, syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*Journal, []Entry, error) { _ = base.Close(); return nil, nil, err }
	if err := syscall.Flock(int(base.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fail(ErrLocked)
		}
		return fail(fmt.Errorf("lock journal: %w", err))
	}
	if err := syncDir(dir); err != nil {
		return fail(err)
	}
	j := &Journal{base: base, file: base, path: path, activePath: path, segmentBytes: segmentBytes}
	segments, err := discoverSegments(path)
	if err != nil {
		return fail(err)
	}
	entries := make([]Entry, 0)
	if err := readSegment(base, len(segments) == 0, &entries, maxRecords); err != nil {
		return fail(fmt.Errorf("legacy segment: %w", err))
	}
	j.baseSize, err = base.Seek(0, io.SeekEnd)
	if err != nil {
		return fail(err)
	}
	j.expectedSize = j.baseSize
	for i, seg := range segments {
		last := i == len(segments)-1
		flags := syscall.O_RDONLY
		if last && !seg.compressed {
			flags = syscall.O_RDWR
		}
		f, err := secureOpen(seg.path, flags, 0)
		if err != nil {
			return fail(err)
		}
		if seg.compressed {
			zr, gzErr := openGzip(f)
			if gzErr != nil {
				_ = f.Close()
				return fail(gzErr)
			}
			err = readStream(zr, false, nil, &entries, maxRecords)
			if closeErr := zr.Close(); err == nil {
				err = closeErr
			}
		} else {
			err = readSegment(f, last, &entries, maxRecords)
		}
		if err != nil {
			_ = f.Close()
			return fail(fmt.Errorf("segment %d: %w", seg.number, err))
		}
		if last {
			if seg.compressed {
				_ = f.Close()
				return fail(errors.New("last WAL segment may not be archived"))
			}
			j.file = f
			j.activePath = seg.path
			j.segmentNumber = seg.number
			j.expectedSize, err = f.Seek(0, io.SeekEnd)
			if err != nil {
				_ = f.Close()
				return fail(err)
			}
		} else {
			_ = f.Close()
		}
	}

	if j.file == base {
		if _, err = base.Seek(0, io.SeekEnd); err != nil {
			return fail(err)
		}
	}
	return j, entries, nil
}

func validateRecord(line []byte) (Entry, error) {
	var e Entry
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, err
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return e, errors.New("unexpected trailing JSON or garbage")
	}
	if e.Version != 1 || (e.Kind != "event" && e.Kind != "response" && e.Kind != "containment") ||
		(e.Kind == "event" && (e.Event == nil || e.Response != nil || e.Containment != nil)) ||
		(e.Kind == "response" && (e.Response == nil || e.Event != nil || e.Containment != nil)) ||
		(e.Kind == "containment" && (e.Containment == nil || e.Event != nil || e.Response != nil)) {
		return e, errors.New("unsupported journal record")
	}
	return e, nil
}

// readSegment repairs only an incomplete tail in the active, uncompressed
// segment. Earlier segments and gzip archives must have a complete tail.
func readSegment(f *os.File, repair bool, entries *[]Entry, maxRecords int) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return readStream(f, repair, f, entries, maxRecords)
}
func readStream(r io.Reader, repair bool, writable *os.File, entries *[]Entry, maxRecords int) error {
	rd := bufio.NewReaderSize(r, maxLineBytes)
	var offset int64
	for {
		line, err := rd.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxLineBytes {
			return fmt.Errorf("record at offset %d exceeds %d bytes", offset, maxLineBytes)
		}
		if err == io.EOF {
			if len(line) > 0 {
				if !repair || writable == nil {
					return fmt.Errorf("incomplete record at byte %d in closed segment", offset)
				}
				if err = writable.Truncate(offset); err != nil {
					return err
				}
				if err = writable.Sync(); err != nil {
					return err
				}
			}
			break
		}
		if err != nil {
			return err
		}
		e, err := validateRecord(line)
		if err != nil {
			return fmt.Errorf("invalid record at byte %d: %w", offset, err)
		}
		if entries != nil {
			if len(*entries) >= maxRecords {
				return fmt.Errorf("journal replay exceeds %d records", maxRecords)
			}
			*entries = append(*entries, e)
		}
		offset += int64(len(line))
	}
	return nil
}

// Append acknowledges a record only after its bytes have been fsynced. Any
// uncertain I/O failure poisons the writer until it is reopened and replayed.
func (j *Journal) Append(e Entry) error {
	if j.failed {
		return errors.New("journal is in a failed state; restart required")
	}
	e.Version = 1
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b)+1 > maxLineBytes {
		return errors.New("journal entry exceeds size limit")
	}
	b = append(b, '\n')
	if err = j.checkIdentity(); err != nil {
		j.failed = true
		return fmt.Errorf("journal identity changed: %w", err)
	}
	if j.expectedSize+int64(len(b)) > j.segmentBytes && j.expectedSize > 0 {
		if err = j.rotate(); err != nil {
			j.failed = true
			return fmt.Errorf("WAL rotation failed (restart required): %w", err)
		}
	}
	n, err := j.file.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = j.file.Sync()
	}
	if err != nil {
		j.failed = true
		return fmt.Errorf("journal commit failed (restart required): %w", err)
	}
	j.expectedSize += int64(len(b))
	if j.file == j.base {
		j.baseSize = j.expectedSize
	}
	return nil
}

func checkFile(path string, f *os.File, expectedSize int64) error {
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return errors.New("journal pathname no longer names the opened file")
	}
	if current.Mode().Perm()&0077 != 0 {
		return errors.New("insecure journal permissions")
	}
	if stat, ok := opened.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return errors.New("journal hardlink count changed")
	}
	if opened.Size() != expectedSize {
		return fmt.Errorf("journal externally modified (size %d expected %d)", opened.Size(), expectedSize)
	}
	return nil
}
func (j *Journal) checkIdentity() error {
	if err := checkFile(j.path, j.base, j.baseSize); err != nil {
		return err
	}
	if j.file != j.base {
		return checkFile(j.activePath, j.file, j.expectedSize)
	}
	return nil
}
func (j *Journal) Healthy() bool { return !j.failed }
func (j *Journal) Close() error {
	if j.file != j.base {
		err := j.file.Close()
		err2 := j.base.Close()
		if err != nil {
			return err
		}
		return err2
	}
	return j.base.Close()
}
