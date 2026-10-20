// Package journal provides a single-writer, crash-tolerant JSONL ledger.
// It is deliberately a bounded single-node store, not a distributed database.
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

const maxLineBytes = 64 * 1024

var ErrLocked = errors.New("journal already has a writer")

type Entry struct {
	Version  int                   `json:"version"`
	Kind     string                `json:"kind"`
	Event    *model.Event          `json:"event,omitempty"`
	Response *model.ResponseAction `json:"response,omitempty"`
}

type Journal struct {
	file   *os.File
	failed bool
}

// Open locks the opened inode, refuses symlinks/hard links or loose file modes,
// and refuses corrupt complete records. The only truncated bytes are a final
// incomplete record that never reached a newline commit boundary.
func Open(path string, maxRecords int) (*Journal, []Entry, error) {
	if maxRecords < 1 {
		return nil, nil, errors.New("positive replay record capacity required")
	}
	if path == "" {
		return nil, nil, errors.New("journal path required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	closeOnError := func(err error) (*Journal, []Entry, error) { _ = f.Close(); return nil, nil, err }
	info, err := f.Stat()
	if err != nil {
		return closeOnError(err)
	}
	if !info.Mode().IsRegular() {
		return closeOnError(errors.New("journal must be a regular file"))
	}
	if info.Mode().Perm()&0077 != 0 {
		return closeOnError(errors.New("journal file must not be accessible to group or others"))
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return closeOnError(errors.New("journal must not have hard links"))
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return closeOnError(ErrLocked)
		}
		return closeOnError(fmt.Errorf("lock journal: %w", err))
	}
	// Durably record file creation in the directory before acknowledging any
	// new event. Also safe when the file already existed.
	d, err := os.Open(dir)
	if err != nil {
		return closeOnError(err)
	}
	err = d.Sync()
	_ = d.Close()
	if err != nil {
		return closeOnError(fmt.Errorf("sync journal directory: %w", err))
	}

	rd := bufio.NewReaderSize(f, maxLineBytes)
	var entries []Entry
	var offset int64
	for {
		line, readErr := rd.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) {
			return closeOnError(fmt.Errorf("journal record at byte %d exceeds %d bytes", offset, maxLineBytes))
		}
		if readErr == io.EOF {
			if len(line) != 0 {
				if err := f.Truncate(offset); err != nil {
					return closeOnError(err)
				}
				if err := f.Sync(); err != nil {
					return closeOnError(err)
				}
			}
			break
		}
		if readErr != nil {
			return closeOnError(readErr)
		}
		if len(line) > maxLineBytes {
			return closeOnError(fmt.Errorf("journal record at byte %d exceeds %d bytes", offset, maxLineBytes))
		}
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(line)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return closeOnError(fmt.Errorf("corrupt journal record at byte %d: %w", offset, err))
		}
		if e.Version != 1 || (e.Kind != "event" && e.Kind != "response") ||
			(e.Kind == "event" && (e.Event == nil || e.Response != nil)) ||
			(e.Kind == "response" && (e.Response == nil || e.Event != nil)) {
			return closeOnError(fmt.Errorf("unsupported or malformed journal record at byte %d", offset))
		}
		if len(entries) >= maxRecords {
			return closeOnError(fmt.Errorf("journal replay exceeds %d records", maxRecords))
		}
		entries = append(entries, e)
		offset += int64(len(line))
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return closeOnError(err)
	}
	return &Journal{file: f}, entries, nil
}

// Append returns only after the record is written and fsynced. Once an append
// fails, the ledger is poisoned and must be reopened/replayed; retrying an
// uncertain append in-process could create undetected duplicates.
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
	return nil
}

// Healthy must be checked under the engine mutex.
func (j *Journal) Healthy() bool { return !j.failed }
func (j *Journal) Close() error  { return j.file.Close() }
