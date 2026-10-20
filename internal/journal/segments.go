package journal

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type diskSegment struct {
	number     uint64
	path       string
	compressed bool
}

func secureOpen(path string, flags int, perm uint32) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, perm)
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
		return nil, errors.New("journal file must be regular and private")
	}
	if x, ok := st.Sys().(*syscall.Stat_t); ok && x.Nlink != 1 {
		f.Close()
		return nil, errors.New("journal hardlinks forbidden")
	}
	return f, nil
}
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func walPath(dir string, n uint64) string { return filepath.Join(dir, fmt.Sprintf("%016d.wal", n)) }
func readHead(dir string) (uint64, error) {
	f, err := secureOpen(filepath.Join(dir, "HEAD"), syscall.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return 0, err
	}
	if len(b) > 32 || !bytes.HasPrefix(b, []byte("last=")) || !bytes.HasSuffix(b, []byte("\n")) {
		return 0, errors.New("corrupt WAL HEAD")
	}
	n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(string(b), "last=")), 10, 64)
	if err != nil || n == 0 {
		return 0, errors.New("invalid WAL HEAD")
	}
	return n, nil
}
func writeHead(dir string, n uint64) error {
	temp := filepath.Join(dir, "HEAD.tmp")
	// A prior crash may have left a non-authoritative temp file. Never follow it.
	if fi, err := os.Lstat(temp); err == nil {
		if !fi.Mode().IsRegular() {
			return errors.New("unsafe HEAD temporary file")
		}
		if err = os.Remove(temp); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := secureOpen(temp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600)
	if err != nil {
		return err
	}
	b := []byte(fmt.Sprintf("last=%d\n", n))
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temp, filepath.Join(dir, "HEAD")); err != nil {
		return err
	}
	return syncDir(dir)
}
func discoverSegments(path string) ([]diskSegment, error) {
	dir := path + ".segments"
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("WAL directory must be private and not a symlink")
	}
	children, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type pair struct{ wal, gz string }
	found := map[uint64]*pair{}
	for _, child := range children {
		name := child.Name()
		if name == "HEAD" || name == "HEAD.tmp" || strings.HasSuffix(name, ".wal.gz.tmp") {
			continue
		}
		gz := strings.HasSuffix(name, ".wal.gz")
		trimmed := strings.TrimSuffix(name, ".gz")
		if !strings.HasSuffix(trimmed, ".wal") {
			return nil, fmt.Errorf("unexpected file in WAL directory: %s", name)
		}
		numText := strings.TrimSuffix(trimmed, ".wal")
		n, e := strconv.ParseUint(numText, 10, 64)
		if e != nil || n == 0 || fmt.Sprintf("%016d", n) != numText {
			return nil, fmt.Errorf("invalid WAL name: %s", name)
		}
		if found[n] == nil {
			found[n] = &pair{}
		}
		if gz {
			found[n].gz = filepath.Join(dir, name)
		} else {
			found[n].wal = filepath.Join(dir, name)
		}
	}
	if len(found) == 0 {
		if _, err := os.Lstat(filepath.Join(dir, "HEAD")); err == nil {
			return nil, errors.New("WAL HEAD exists but all segments are missing")
		}
		return nil, nil
	}
	head, err := readHead(dir)
	if errors.Is(err, os.ErrNotExist) { // safe recovery only for an initial, empty orphan
		if len(found) != 1 || found[1] == nil || found[1].wal == "" {
			return nil, errors.New("WAL HEAD missing")
		}
		st, e := os.Stat(found[1].wal)
		if e != nil || st.Size() != 0 {
			return nil, errors.New("nonempty segment without HEAD")
		}
		if err = writeHead(dir, 1); err != nil {
			return nil, err
		}
		head = 1
	} else if err != nil {
		return nil, err
	}
	// Crash window: file created+fsynced, but HEAD has not yet advanced.
	// Adopt one *empty* orphan only, never data-bearing files.
	if len(found) == int(head)+1 && found[head+1] != nil && found[head+1].wal != "" {
		st, e := os.Stat(found[head+1].wal)
		if e != nil || st.Size() != 0 {
			return nil, errors.New("uncommitted WAL segment contains data")
		}
		if err = writeHead(dir, head+1); err != nil {
			return nil, err
		}
		head++
	}
	if len(found) != int(head) {
		return nil, fmt.Errorf("WAL segment gap: HEAD=%d files=%d", head, len(found))
	}
	keys := make([]uint64, 0, len(found))
	for n := range found {
		keys = append(keys, n)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	segments := make([]diskSegment, 0, len(keys))
	for i, n := range keys {
		if n != uint64(i+1) {
			return nil, fmt.Errorf("missing WAL segment %d", i+1)
		}
		item := found[n]
		if item.wal != "" && item.gz != "" {
			if err := compareArchive(item.wal, item.gz); err != nil {
				return nil, fmt.Errorf("conflicting WAL archive %d: %w", n, err)
			}
			// After a crash following rename but before deletion, prefer the still
			// uncompressed file. The operator may finish compaction later.
		}
		if item.wal != "" {
			segments = append(segments, diskSegment{n, item.wal, false})
		} else if item.gz != "" {
			segments = append(segments, diskSegment{n, item.gz, true})
		} else {
			return nil, fmt.Errorf("missing WAL segment %d", n)
		}
	}
	return segments, nil
}
func openGzip(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) }
func compareArchive(path, gzPath string) error {
	original, err := secureOpen(path, syscall.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer original.Close()
	comp, err := secureOpen(gzPath, syscall.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer comp.Close()
	zr, err := gzip.NewReader(comp)
	if err != nil {
		return err
	}
	defer zr.Close()
	a, b := sha256.New(), sha256.New()
	na, err := io.Copy(a, original)
	if err != nil {
		return err
	}
	nb, err := io.Copy(b, zr)
	if err != nil {
		return err
	}
	if na != nb || !bytes.Equal(a.Sum(nil), b.Sum(nil)) {
		return errors.New("compressed and plain WAL differ")
	}
	return nil
}

func (j *Journal) rotate() error {
	dir := j.path + ".segments"
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("WAL directory is unsafe")
	}
	if err = syncDir(filepath.Dir(dir)); err != nil {
		return err
	}
	next := j.segmentNumber + 1
	f, err := secureOpen(walPath(dir, next), syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = syncDir(dir); err != nil {
		f.Close()
		return err
	}
	if err = writeHead(dir, next); err != nil {
		f.Close()
		return err
	}
	if j.file != j.base {
		if err = j.file.Close(); err != nil {
			f.Close()
			return err
		}
	}
	j.file = f
	j.activePath = walPath(dir, next)
	j.segmentNumber = next
	j.expectedSize = 0
	return nil
}

// CompactClosed losslessly gzip-compresses closed numbered WAL segments. It
// never truncates history, expires event IDs, or touches the active segment.
// It is safe to repeat after a crash at any rename/unlink boundary.
func (j *Journal) CompactClosed() (int, error) {
	if j.failed {
		return 0, errors.New("unhealthy journal")
	}
	if err := j.checkIdentity(); err != nil {
		j.failed = true
		return 0, err
	}
	if j.segmentNumber < 2 {
		return 0, nil
	}
	dir := j.path + ".segments"
	count := 0
	for n := uint64(1); n < j.segmentNumber; n++ {
		path := walPath(dir, n)
		archive := path + ".gz"
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return count, err
		}
		if _, err = os.Lstat(archive); err == nil {
			if err = compareArchive(path, archive); err != nil {
				return count, err
			}
		} else if errors.Is(err, os.ErrNotExist) {
			original, err := secureOpen(path, syscall.O_RDONLY, 0)
			if err != nil {
				return count, err
			}
			tmp := archive + ".tmp"
			if _, err = os.Lstat(tmp); err == nil {
				if err = os.Remove(tmp); err != nil {
					original.Close()
					return count, err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				original.Close()
				return count, err
			}
			dst, err := secureOpen(tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600)
			if err != nil {
				original.Close()
				return count, err
			}
			zw := gzip.NewWriter(dst)
			_, err = io.Copy(zw, original)
			if err == nil {
				err = zw.Close()
			} else {
				_ = zw.Close()
			}
			if err == nil {
				err = dst.Sync()
			}
			cerr := dst.Close()
			original.Close()
			if err != nil {
				return count, err
			}
			if cerr != nil {
				return count, cerr
			}
			if err = os.Rename(tmp, archive); err != nil {
				return count, err
			}
			if err = syncDir(dir); err != nil {
				return count, err
			}
			if err = compareArchive(path, archive); err != nil {
				return count, err
			}
		} else {
			return count, err
		}
		if err = os.Remove(path); err != nil {
			return count, err
		}
		if err = syncDir(dir); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
