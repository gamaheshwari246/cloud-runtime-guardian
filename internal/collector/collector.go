// Package collector forwards a Tetragon JSONL export with crash-safe checkpoints.
// Rename-based rotation can be resumed if the old file is still retained.
package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const maxLine = 256 << 10

// Checkpoint is bound to a filesystem identity, so a log replacement can
// never silently skip a new file's first records.
type Checkpoint struct {
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	Offset   int64  `json:"offset"`
	NodeName string `json:"node_name"`
	BootID   string `json:"boot_id"`
}

func identity(fi os.FileInfo) (Checkpoint, error) {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Checkpoint{}, errors.New("filesystem identity unavailable")
	}
	if !fi.Mode().IsRegular() {
		return Checkpoint{}, errors.New("export must be a regular file")
	}
	return Checkpoint{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func load(path string) (Checkpoint, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, err
	}
	var cp Checkpoint
	if err := json.Unmarshal(b, &cp); err != nil {
		return cp, false, fmt.Errorf("corrupt checkpoint: %w", err)
	}
	if cp.Inode == 0 || cp.Offset < 0 || cp.NodeName == "" || cp.BootID == "" {
		return cp, false, errors.New("invalid checkpoint")
	}
	return cp, true, nil
}

func save(path string, cp Checkpoint) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type Sender interface {
	Send(context.Context, []byte) error
}

type HTTPSender struct {
	URL, Token string
	Client     *http.Client
}

// Send retries only transient conditions. A 409 or 4xx schema error is
// surfaced for an operator rather than silently discarded.
func (s HTTPSender) Send(ctx context.Context, b []byte) error {
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	delay := 200 * time.Millisecond
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if s.Token != "" {
			req.Header.Set("Authorization", "Bearer "+s.Token)
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
				return nil
			}
			if resp.StatusCode != 429 && resp.StatusCode < 500 {
				return fmt.Errorf("ingestion rejected with HTTP %d", resp.StatusCode)
			}
			err = fmt.Errorf("transient ingestion HTTP %d", resp.StatusCode)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if delay < 5*time.Second {
			delay *= 2
		}
	}
}

type Config struct {
	ExportPath, CheckpointPath, NodeName, BootID string
	// ArchiveGlob is used only to locate the checkpointed file after a
	// rename-based rotation. The default is ExportPath + ".*".
	ArchiveGlob  string
	Follow       bool
	PollInterval time.Duration
}

// Run never acknowledges a record until the API has acknowledged its durable
// append. It checkpoints skipped unrelated events, but never malformed target
// events. Rename-based rotation is recoverable if retained exports remain
// accessible; copytruncate and missing archives fail closed.
func nextLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > maxLine {
			return nil, fmt.Errorf("line exceeds %d bytes", maxLine)
		}
		line = append(line, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, err
	}
}

// ReadBootID checks the running host's kernel boot epoch. It is important
// that a file exported on a different node not be consumed using this ID.
func ReadBootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", errors.New("empty Linux boot ID")
	}
	return id, nil
}
