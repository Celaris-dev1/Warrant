package ledger

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SpoolingClient wraps a Recorder (normally *Client) with a durable local
// file spool: a record that cannot be delivered right away (the Ledger is
// down, the network is flaky) is appended to a spool file and retried in
// the background until it is accepted, so records are never silently
// dropped. The spool file survives process restarts.
type SpoolingClient struct {
	Upstream Recorder
	Dir      string

	mu       sync.Mutex
	interval time.Duration // retry period; default 5s
	file     *os.File

	closeOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
}

// SetInterval changes the background retry period (safe for concurrent use,
// including while the loop is running; tests use this instead of writing a
// field directly, which would race with the loop goroutine's read of it).
func (sc *SpoolingClient) SetInterval(d time.Duration) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.interval = d
}

func (sc *SpoolingClient) getInterval() time.Duration {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.interval
}

// spoolEntry is one line of the spool file.
type spoolEntry struct {
	Record Record `json:"record"`
}

// NewSpoolingClient opens (creating if needed) a spool file under dir and
// starts a background goroutine that flushes pending records to upstream.
func NewSpoolingClient(upstream Recorder, dir string) (*SpoolingClient, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ledger spool: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "spool.jsonl"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("ledger spool: %w", err)
	}
	sc := &SpoolingClient{Upstream: upstream, Dir: dir, interval: 5 * time.Second, file: f,
		stop: make(chan struct{}), done: make(chan struct{})}
	go sc.loop()
	return sc, nil
}

// Record tries to deliver immediately; on failure (or if there is already a
// backlog, to preserve ordering) it appends to the spool and returns nil —
// the caller's write is never lost, only delayed.
func (sc *SpoolingClient) Record(ctx context.Context, r Record) error {
	if sc.backlog() {
		return sc.append(r)
	}
	if err := sc.Upstream.Record(ctx, r); err != nil {
		return sc.append(r)
	}
	return nil
}

func (sc *SpoolingClient) backlog() bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	fi, err := sc.file.Stat()
	return err == nil && fi.Size() > 0
}

func (sc *SpoolingClient) append(r Record) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	b, err := json.Marshal(spoolEntry{Record: r})
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := sc.file.Write(b); err != nil {
		return err
	}
	return sc.file.Sync()
}

// loop periodically attempts to drain the spool. It rechecks the interval
// each cycle (via getInterval, which locks) so SetInterval can safely
// change the retry period while the loop is running, without a data race.
func (sc *SpoolingClient) loop() {
	defer close(sc.done)
	for {
		select {
		case <-sc.stop:
			return
		case <-time.After(sc.getInterval()):
			sc.drain()
		}
	}
}

// drain replays every spooled record in order; on the first failure it
// rewrites the spool with the remaining (undelivered) records and stops,
// so nothing is delivered out of order and nothing is lost.
func (sc *SpoolingClient) drain() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	path := sc.file.Name()
	if fi, err := sc.file.Stat(); err != nil || fi.Size() == 0 {
		return
	}
	if _, err := sc.file.Seek(0, 0); err != nil {
		return
	}
	sc2 := bufio.NewScanner(sc.file)
	sc2.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var remaining []spoolEntry
	failed := false
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for sc2.Scan() {
		line := sc2.Bytes()
		if len(line) == 0 {
			continue
		}
		var e spoolEntry
		if err := json.Unmarshal(line, &e); err != nil {
			log.Printf("ledger spool: dropping corrupt entry: %v", err)
			continue
		}
		if failed {
			remaining = append(remaining, e)
			continue
		}
		if err := sc.Upstream.Record(ctx, e.Record); err != nil {
			failed = true
			remaining = append(remaining, e)
		}
	}

	// Rewrite the spool file with whatever is left (possibly empty).
	tmp := path + ".tmp"
	nf, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(nf)
	for _, e := range remaining {
		b, _ := json.Marshal(e)
		w.Write(b) //nolint:errcheck
		w.WriteByte('\n') //nolint:errcheck
	}
	if err := w.Flush(); err != nil {
		nf.Close()
		return
	}
	if err := nf.Sync(); err != nil {
		nf.Close()
		return
	}
	nf.Close()
	if err := os.Rename(tmp, path); err != nil {
		return
	}
	sc.file.Close()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	sc.file = f
}

// Pending returns the number of records currently sitting in the spool,
// waiting for redelivery. Mainly for tests/observability.
func (sc *SpoolingClient) Pending() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if _, err := sc.file.Seek(0, 0); err != nil {
		return 0
	}
	s := bufio.NewScanner(sc.file)
	s.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	n := 0
	for s.Scan() {
		if len(s.Bytes()) > 0 {
			n++
		}
	}
	sc.file.Seek(0, 2) //nolint:errcheck // back to end for future appends
	return n
}

// Flush forces one synchronous drain attempt (tests / graceful shutdown).
func (sc *SpoolingClient) Flush() { sc.drain() }

// Close stops the background retry loop.
func (sc *SpoolingClient) Close() error {
	sc.closeOnce.Do(func() { close(sc.stop) })
	<-sc.done
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.file.Close()
}
