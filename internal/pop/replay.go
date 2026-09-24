package pop

import (
	"sync"
	"time"
)

// MemoryReplayStore is a simple in-memory ReplayStore, good for a single
// warrantd/PEP process. Entries are pruned lazily on Seen once expired, so
// memory use is bounded by the number of distinct proofs seen within
// MaxTTL.
type MemoryReplayStore struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiry
}

// NewMemoryReplayStore returns an empty store.
func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{seen: map[string]time.Time{}}
}

// Seen reports whether jti has already been recorded (and not yet expired),
// and records it if not.
func (s *MemoryReplayStore) Seen(jti string, expires time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if exp, ok := s.seen[jti]; ok && exp.After(now) {
		return true
	}
	s.seen[jti] = expires
	if len(s.seen)%256 == 0 {
		for k, exp := range s.seen {
			if !exp.After(now) {
				delete(s.seen, k)
			}
		}
	}
	return false
}
