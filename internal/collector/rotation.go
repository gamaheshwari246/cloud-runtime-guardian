package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"cloudruntimeguardian/internal/tetragon"
)

func Run(ctx context.Context, cfg Config, sender Sender) error {
	if cfg.ExportPath == "" || cfg.CheckpointPath == "" || cfg.NodeName == "" || cfg.BootID == "" || sender == nil {
		return errors.New("export, checkpoint, node name, boot ID and sender are required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.ArchiveGlob == "" {
		cfg.ArchiveGlob = cfg.ExportPath + ".*"
	}
	cp, exists, err := load(cfg.CheckpointPath)
	if err != nil {
		return err
	}
	if exists && (cp.NodeName != cfg.NodeName || cp.BootID != cfg.BootID) {
		return errors.New("source node or boot changed; refusing to misattribute replay")
	}
	f, current, err := findSource(cfg, cp, exists)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if exists {
		current.Offset = cp.Offset
	}
	current.NodeName, current.BootID = cfg.NodeName, cfg.BootID
	if err := seekSource(f, current.Offset); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(f, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, readErr := nextLine(reader)
		if errors.Is(readErr, io.EOF) {
			// The last line was incomplete, so rewind to the last durable
			// offset. The next poll may complete the same line.
			if err := seekSource(f, current.Offset); err != nil {
				return err
			}
			reader.Reset(f)
			next, nextID, switched, err := rotatedSuccessor(cfg.ExportPath, current)
			if err != nil {
				return err
			}
			if switched {
				if len(line) != 0 {
					_ = next.Close()
					return errors.New("rotated export ends with an incomplete line; refusing to lose an event")
				}
				if err := verifySingleTransition(cfg.ArchiveGlob, current); err != nil {
					_ = next.Close()
					return err
				}
				// All complete records in the old inode have been committed.
				// Persist the new inode before consuming its first event; a
				// crash here resumes from byte zero of the replacement file.
				nextID.NodeName, nextID.BootID = cfg.NodeName, cfg.BootID
				if err := save(cfg.CheckpointPath, nextID); err != nil {
					_ = next.Close()
					return fmt.Errorf("rotation checkpoint: %w", err)
				}
				_ = f.Close()
				f, current = next, nextID
				reader.Reset(f)
				continue
			}
			if !cfg.Follow {
				return nil
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
		if readErr != nil {
			return readErr
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

// seekSource also detects copytruncate and refuses to resume beyond EOF. An
// overwrite of equal length cannot be detected using only file metadata; the
// Tetragon exporter must use rename/create rotation, never copytruncate.
func seekSource(f *os.File, offset int64) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() < offset {
		return fmt.Errorf("export truncated: size %d below checkpoint %d", fi.Size(), offset)
	}
	_, err = f.Seek(offset, io.SeekStart)
	return err
}

// openRegular does not follow symlinks. Identity comes from the opened fd,
// not a path-based stat that could race a replacement.
func openRegular(path string) (*os.File, Checkpoint, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, Checkpoint{}, err
	}
	if !fi.Mode().IsRegular() {
		return nil, Checkpoint{}, fmt.Errorf("export %q must be a regular, non-symlink file", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, Checkpoint{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err = f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, Checkpoint{}, err
	}
	id, err := identity(fi)
	if err != nil {
		_ = f.Close()
		return nil, Checkpoint{}, err
	}
	return f, id, nil
}

func sameFile(a, b Checkpoint) bool { return a.Device == b.Device && a.Inode == b.Inode }

// findSource searches archives only if an existing checkpoint points at an
// inode no longer at the active path. Exactly one retained matching archive
// must exist. Missing archives mean possible data loss and fail closed.
func findSource(cfg Config, cp Checkpoint, exists bool) (*os.File, Checkpoint, error) {
	f, id, err := openRegular(cfg.ExportPath)
	if err == nil && (!exists || sameFile(id, cp)) {
		return f, id, nil
	}
	if err == nil {
		_ = f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, Checkpoint{}, err
	}
	if !exists {
		return nil, Checkpoint{}, fmt.Errorf("active export unavailable: %w", os.ErrNotExist)
	}
	paths, err := filepath.Glob(cfg.ArchiveGlob)
	if err != nil {
		return nil, Checkpoint{}, err
	}
	var match *os.File
	var found Checkpoint
	for _, path := range paths {
		candidate, candidateID, err := openRegular(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if match != nil {
				_ = match.Close()
			}
			return nil, Checkpoint{}, err
		}
		if sameFile(candidateID, cp) {
			if match != nil {
				_ = candidate.Close()
				_ = match.Close()
				return nil, Checkpoint{}, errors.New("multiple paths match checkpointed export inode")
			}
			match, found = candidate, candidateID
		} else {
			_ = candidate.Close()
		}
	}
	if match == nil {
		return nil, Checkpoint{}, errors.New("checkpoint source inode is missing; retained rotated log required for recovery")
	}
	if err := verifySingleTransition(cfg.ArchiveGlob, cp); err != nil {
		_ = match.Close()
		return nil, Checkpoint{}, err
	}
	return match, found, nil
}

// In absence of a rotation manifest, exactly one archive may be present during
// a transition. Multiple archives could hide unconsumed intermediate files;
// do not jump to the current file and silently discard their records. Operators
// must supply a narrow archive glob and retain the current rotated file.
func verifySingleTransition(pattern string, old Checkpoint) error {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	var count, matching int
	for _, path := range paths {
		fi, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("archive %q is not a regular file", path)
		}
		id, err := identity(fi)
		if err != nil {
			return err
		}
		count++
		if sameFile(id, old) {
			matching++
		}
	}
	if count != 1 || matching != 1 {
		return fmt.Errorf("ambiguous rotation: expected one retained archive matching checkpoint, found %d archives and %d matches", count, matching)
	}
	return nil
}

// rotatedSuccessor inspects the active path at EOF and opens the next file.
// It refuses path-based truncation and active-log replacement with symlinks.
func rotatedSuccessor(path string, current Checkpoint) (*os.File, Checkpoint, bool, error) {
	f, id, err := openRegular(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, Checkpoint{}, false, nil // rename/create gap
	}
	if err != nil {
		return nil, Checkpoint{}, false, err
	}
	if sameFile(id, current) {
		defer f.Close()
		if err := seekSource(f, current.Offset); err != nil {
			return nil, Checkpoint{}, false, err
		}
		return nil, Checkpoint{}, false, nil
	}
	return f, id, true, nil
}
