package observability

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// defaultMaxFileSize is the single-file cap before rotation (20 MB).
	defaultMaxFileSize = 20 * 1024 * 1024

	// defaultMaxFiles is the number of compressed rotated files to keep.
	// Together with the current file that is 8 files ≈ 160 MB max on disk.
	defaultMaxFiles = 7

	// channelBuffer is the max number of pending log lines in memory.
	// At ~512 B per record this is ≈ 2 MB.
	channelBuffer = 4096

	// flushInterval is the periodic write-through interval for INFO/DEBUG.
	flushInterval = 200 * time.Millisecond
)

// AsyncWriter is an io.WriteCloser that enqueues writes and drains them in a
// background goroutine. It supports automatic file rotation with gzip
// compression of rotated files.
//
// Write never blocks: records are dropped (with a stderr warning) if the
// internal channel is full. ERROR/FATAL callers should call Flush to drain
// the queue before exiting.
type AsyncWriter struct {
	ch     chan []byte   // serialised log lines
	done   chan struct{} // closed when the writer goroutine exits
	urgent chan struct{} // non-blocking signal: drain now

	mu      sync.Mutex
	file    *os.File
	written int64 // bytes written to the current file

	dir      string
	maxSize  int64
	maxFiles int
}

// NewAsyncWriter creates and starts an AsyncWriter that appends to
// <dir>/current.jsonl. The directory is created if it does not exist.
func NewAsyncWriter(dir string) (*AsyncWriter, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create log dir %s: %w", dir, err)
	}
	w := &AsyncWriter{
		ch:       make(chan []byte, channelBuffer),
		done:     make(chan struct{}),
		urgent:   make(chan struct{}, 1),
		dir:      dir,
		maxSize:  defaultMaxFileSize,
		maxFiles: defaultMaxFiles,
	}
	if err := w.openFileLocked(); err != nil {
		return nil, err
	}
	go w.run()
	return w, nil
}

// openFileLocked opens (or creates) current.jsonl in append mode.
// Must be called with w.mu held.
func (w *AsyncWriter) openFileLocked() error {
	path := filepath.Join(w.dir, "current.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", path, err)
	}
	info, _ := f.Stat()
	w.file = f
	if info != nil {
		w.written = info.Size()
	}
	return nil
}

// Write enqueues p for asynchronous writing. Never blocks; drops records with
// a stderr warning when the channel is full.
func (w *AsyncWriter) Write(p []byte) (int, error) {
	// Copy p since slog reuses the underlying buffer after Write returns.
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case w.ch <- b:
	default:
		fmt.Fprintf(os.Stderr, "aikey-proxy: log channel full, dropping record\n")
	}
	return len(p), nil
}

// Flush signals the writer goroutine for an urgent drain and waits up to
// timeout for the channel to empty. Use before process exit for ERROR/FATAL.
func (w *AsyncWriter) Flush(timeout time.Duration) {
	select {
	case w.urgent <- struct{}{}:
	default:
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(w.ch) == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Close drains the channel, syncs, and closes the underlying file.
// After Close the writer must not be used.
func (w *AsyncWriter) Close() error {
	close(w.ch)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Sync()
		return w.file.Close()
	}
	return nil
}

// run is the background writer goroutine.
func (w *AsyncWriter) run() {
	defer close(w.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case b, ok := <-w.ch:
			if !ok {
				// Channel closed — drain whatever is buffered then exit.
				w.drainAll()
				return
			}
			w.writeBytes(b)

		case <-ticker.C:
			// Periodic sync to ensure data is visible on disk.
			w.mu.Lock()
			if w.file != nil {
				_ = w.file.Sync()
			}
			w.mu.Unlock()

		case <-w.urgent:
			// Drain as many pending records as possible right now.
			n := len(w.ch)
			for i := 0; i < n; i++ {
				select {
				case b := <-w.ch:
					w.writeBytes(b)
				default:
					goto doneUrgent
				}
			}
		doneUrgent:
			w.mu.Lock()
			if w.file != nil {
				_ = w.file.Sync()
			}
			w.mu.Unlock()
		}
	}
}

// drainAll empties the channel after it has been closed.
func (w *AsyncWriter) drainAll() {
	for {
		select {
		case b := <-w.ch:
			w.writeBytes(b)
		default:
			w.mu.Lock()
			if w.file != nil {
				_ = w.file.Sync()
			}
			w.mu.Unlock()
			return
		}
	}
}

// writeBytes appends b to the current log file and rotates if the file
// exceeds maxSize.
func (w *AsyncWriter) writeBytes(b []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return
	}
	n, err := w.file.Write(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aikey-proxy: log write error: %v\n", err)
		return
	}
	w.written += int64(n)
	if w.written >= w.maxSize {
		w.rotateLocked()
	}
}

// rotateLocked renames current.jsonl to a numbered gzip archive and opens a
// fresh file. Must be called with w.mu held.
func (w *AsyncWriter) rotateLocked() {
	if w.file != nil {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.file = nil
	}

	current := filepath.Join(w.dir, "current.jsonl")

	// Shift numbered archives: .N.gz → .(N+1).gz, oldest → deleted.
	for i := w.maxFiles; i >= 1; i-- {
		src := filepath.Join(w.dir, fmt.Sprintf("current.jsonl.%d.gz", i))
		dst := filepath.Join(w.dir, fmt.Sprintf("current.jsonl.%d.gz", i+1))
		if _, err := os.Stat(src); err == nil {
			if i == w.maxFiles {
				_ = os.Remove(src) // oldest, drop it
			} else {
				_ = os.Rename(src, dst)
			}
		}
	}

	// Compress current file → current.jsonl.1.gz
	dest := filepath.Join(w.dir, "current.jsonl.1.gz")
	if err := gzipFile(current, dest); err != nil {
		fmt.Fprintf(os.Stderr, "aikey-proxy: log rotation error: %v\n", err)
	}
	_ = os.Remove(current)

	if err := w.openFileLocked(); err != nil {
		fmt.Fprintf(os.Stderr, "aikey-proxy: failed to reopen log file after rotation: %v\n", err)
	}
	w.written = 0
}

// gzipFile compresses src into dst.
func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	if _, err = io.Copy(gz, in); err != nil {
		return err
	}
	return gz.Close()
}
