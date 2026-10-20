// Package journal provides a crash-tolerant, append-only JSONL ledger for the MVP.
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

	"cloudruntimeguardian/internal/model"
)

const maxLineBytes = 64 * 1024

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

// Open replays committed newline-terminated records. An incomplete final record
// is discarded; malformed complete records cause startup to fail rather than
// silently losing audit data.
func Open(path string) (*Journal, []Entry, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, nil, err
	}
	closeOnError := func(err error) (*Journal, []Entry, error) { f.Close(); return nil, nil, err }
	rd := bufio.NewReader(f)
	var entries []Entry
	var offset int64
	for {
		line, readErr := rd.ReadBytes('\n')
		if readErr == io.EOF {
			// A non-terminated tail may be a torn write, even if it happens to
			// contain valid JSON. Only records ending in '\n' are committed.
			if len(line) != 0 {
				if err := f.Truncate(offset); err != nil {
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
		offset += int64(len(line))
		var e Entry
		if err := json.Unmarshal(bytes.TrimSpace(line), &e); err != nil {
			return closeOnError(fmt.Errorf("corrupt committed journal at byte %d: %w", offset-int64(len(line)), err))
		}
		if e.Version != 1 || (e.Kind != "event" && e.Kind != "response") ||
			(e.Kind == "event" && (e.Event == nil || e.Response != nil)) ||
			(e.Kind == "response" && (e.Response == nil || e.Event != nil)) {
			return closeOnError(errors.New("unsupported or malformed committed journal record"))
		}
		entries = append(entries, e)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return closeOnError(err)
	}
	return &Journal{file: f}, entries, nil
}

// Append returns only after fdatasync-equivalent durability via Sync. Once a
// write fails the process must restart and replay before accepting new writes.
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

func (j *Journal) Close() error { return j.file.Close() }
