package ledger

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// flaky fails every Record call until Up is set true.
type flaky struct {
	mu  sync.Mutex
	Up  bool
	got []Record
}

func (f *flaky) Record(_ context.Context, r Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Up {
		return errors.New("ledger down")
	}
	f.got = append(f.got, r)
	return nil
}

func (f *flaky) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func mustRec(id string) Record {
	return Record{Chain: "warrant", Type: "warrant.token.issued",
		ActorChain: []Actor{{Kind: "human", ID: "alice"}}, Payload: map[string]any{"id": id}}
}

func TestSpoolingClientNeverDropsWhileDown(t *testing.T) {
	dir := t.TempDir()
	up := &flaky{}
	sc, err := NewSpoolingClient(up, dir)
	if err != nil {
		t.Fatal(err)
	}
	sc.Interval = time.Hour // control draining manually
	defer sc.Close()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := sc.Record(ctx, mustRec(string(rune('a'+i)))); err != nil {
			t.Fatalf("Record should never fail (spooled): %v", err)
		}
	}
	if got := sc.Pending(); got != 5 {
		t.Fatalf("pending = %d, want 5", got)
	}
	if up.count() != 0 {
		t.Fatalf("upstream got %d records while down, want 0", up.count())
	}

	// Ledger comes back; a manual flush should drain everything, in order.
	up.mu.Lock()
	up.Up = true
	up.mu.Unlock()
	sc.Flush()

	if got := sc.Pending(); got != 0 {
		t.Fatalf("pending after flush = %d, want 0", got)
	}
	if up.count() != 5 {
		t.Fatalf("upstream got %d records after flush, want 5", up.count())
	}
	for i, r := range up.got {
		if r.Payload["id"] != string(rune('a'+i)) {
			t.Fatalf("out of order delivery at %d: %v", i, r.Payload["id"])
		}
	}
}

func TestSpoolingClientSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	up := &flaky{}
	sc, err := NewSpoolingClient(up, dir)
	if err != nil {
		t.Fatal(err)
	}
	sc.Interval = time.Hour
	ctx := context.Background()
	if err := sc.Record(ctx, mustRec("x")); err != nil {
		t.Fatal(err)
	}
	if err := sc.Close(); err != nil {
		t.Fatal(err)
	}

	// "Restart": reopen against the same dir; the spooled record must
	// still be there and still deliverable.
	sc2, err := NewSpoolingClient(up, dir)
	if err != nil {
		t.Fatal(err)
	}
	sc2.Interval = time.Hour
	defer sc2.Close()
	if got := sc2.Pending(); got != 1 {
		t.Fatalf("pending after restart = %d, want 1", got)
	}
	up.mu.Lock()
	up.Up = true
	up.mu.Unlock()
	sc2.Flush()
	if up.count() != 1 {
		t.Fatalf("upstream got %d records after restart+flush, want 1", up.count())
	}
}

func TestSpoolingClientBackgroundLoopDrains(t *testing.T) {
	dir := t.TempDir()
	up := &flaky{}
	sc, err := NewSpoolingClient(up, dir)
	if err != nil {
		t.Fatal(err)
	}
	sc.Interval = 20 * time.Millisecond
	defer sc.Close()
	ctx := context.Background()
	if err := sc.Record(ctx, mustRec("bg")); err != nil {
		t.Fatal(err)
	}
	up.mu.Lock()
	up.Up = true
	up.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if up.count() == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background loop never drained the spool")
}
