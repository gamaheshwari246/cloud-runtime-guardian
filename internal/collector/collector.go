// Package collector forwards one append-only JSONL export with crash-safe
// checkpoints. Rotation or truncation fails closed until an operator intervenes.
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"cloudruntimeguardian/internal/tetragon"
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
	Follow                                       bool
	PollInterval                                 time.Duration
}

// Run never acknowledges a record until the API has acknowledged its durable
// append. It checkpoints skipped unrelated events, but never malformed target
// events. The input file must not rotate or truncate; both cause an error.
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

func Run(ctx context.Context, cfg Config, sender Sender) error {
	if cfg.ExportPath == "" || cfg.CheckpointPath == "" || cfg.NodeName == "" || cfg.BootID == "" {
		return errors.New("export, checkpoint, node name and boot ID are required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	f, err := os.Open(cfg.ExportPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	current, err := identity(fi)
	if err != nil {
		return err
	}
	cp, exists, err := load(cfg.CheckpointPath)
	if err != nil {
		return err
	}
	if exists {
		if cp.NodeName != cfg.NodeName || cp.BootID != cfg.BootID {
			return errors.New("source node or boot changed; refusing to misattribute replay")
		}
		if cp.Device != current.Device || cp.Inode != current.Inode {
			return errors.New("export identity changed since checkpoint; refusing to skip or replay without operator action")
		}
		current.Offset = cp.Offset
	}
	current.NodeName, current.BootID = cfg.NodeName, cfg.BootID
	if fi.Size() < current.Offset {
		return errors.New("export truncated below checkpoint; refusing to skip data")
	}
	if _, err := f.Seek(current.Offset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(f, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := nextLine(reader)
		if errors.Is(err, io.EOF) {
			// A partial line is not committed; seek back before polling.
			if _, err := f.Seek(current.Offset, io.SeekStart); err != nil {
				return err
			}
			reader.Reset(f)
			if !cfg.Follow {
				return nil
			}
			pathFi, statErr := os.Stat(cfg.ExportPath)
			if statErr != nil {
				return fmt.Errorf("export path changed: %w", statErr)
			}
			newID, statErr := identity(pathFi)
			if statErr != nil {
				return statErr
			}
			if newID.Inode != current.Inode || newID.Device != current.Device || pathFi.Size() < current.Offset {
				return errors.New("export rotated or truncated; input requires operator recovery")
			}
			timer := time.NewTimer(cfg.PollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if err != nil {
			return err
		}
		if len(line) > maxLine {
			return fmt.Errorf("oversized export line at offset %d", current.Offset)
		}
		raw := bytes.TrimSpace(line)
		event, err := tetragon.Convert(raw, cfg.NodeName, cfg.BootID, strconv.FormatUint(current.Device, 10)+":"+strconv.FormatUint(current.Inode, 10), current.Offset)
		if err != nil && !errors.Is(err, tetragon.ErrUnsupported) {
			return fmt.Errorf("export offset %d: %w", current.Offset, err)
		}
		if err == nil {
			b, marshalErr := json.Marshal(event)
			if marshalErr != nil {
				return marshalErr
			}
			if err := sender.Send(ctx, b); err != nil {
				return fmt.Errorf("send at export offset %d: %w", current.Offset, err)
			}
		}
		current.Offset += int64(len(line))
		if err := save(cfg.CheckpointPath, current); err != nil {
			return fmt.Errorf("checkpoint commit: %w", err)
		}
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
