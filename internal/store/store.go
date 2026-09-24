// Package store persists workloads, issued tokens, revocations, call
// counters and consumed approvals. Postgres in production; an in-memory
// implementation backs unit tests and `-store=memory` dev mode.
package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Workload is a registered workload (an agent kind) attested by a secret.
type Workload struct {
	Name       string    `json:"name"`
	SecretHash string    `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
}

// TokenRecord is the broker's record of an issued capability token.
type TokenRecord struct {
	ID          string    `json:"id"`
	Parent      string    `json:"parent,omitempty"`
	ParentActor string    `json:"parent_actor,omitempty"`
	GoalID      string    `json:"goal_id,omitempty"`
	Subject     string    `json:"subject"`
	Human       string    `json:"human"`
	Depth       int       `json:"depth"`
	MaxCalls    int       `json:"max_calls"`
	ScopeLimits []int     `json:"scope_limits"`
	Expires     time.Time `json:"expires"`
	Claims      []byte    `json:"-"` // JSON claims
}

// ErrExhausted is returned by Consume when a budget is used up.
type ErrExhausted struct{ Which string }

func (e ErrExhausted) Error() string { return "call budget exhausted: " + e.Which }

// ErrNotFound is returned for unknown ids.
var ErrNotFound = errors.New("not found")

// Store is the persistence interface.
type Store interface {
	PutWorkload(ctx context.Context, w Workload) error
	GetWorkload(ctx context.Context, name string) (Workload, error)
	PutToken(ctx context.Context, t TokenRecord) error
	GetToken(ctx context.Context, id string) (TokenRecord, error)
	Children(ctx context.Context, id string) ([]TokenRecord, error)
	Revoke(ctx context.Context, id, reason string) error
	// FirstRevoked returns the first id in ids that is revoked, or "".
	FirstRevoked(ctx context.Context, ids []string) (string, error)
	// Consume atomically charges one call against token id's scope scopeIdx
	// and against the whole-token budget of every id in lineage (ancestors
	// + id). Nothing is charged if any budget is exhausted.
	Consume(ctx context.Context, id string, scopeIdx int, lineage []string) error
	// Usage returns total calls and per-scope calls for a token.
	Usage(ctx context.Context, id string) (int, map[int]int, error)
	// UseApproval marks a single-use approval consumed; false if already used.
	UseApproval(ctx context.Context, id string, expires time.Time) (bool, error)
}

// Memory is an in-memory Store.
type Memory struct {
	mu        sync.Mutex
	workloads map[string]Workload
	tokens    map[string]TokenRecord
	revoked   map[string]string
	total     map[string]int
	perScope  map[string]map[int]int
	approvals map[string]bool
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{workloads: map[string]Workload{}, tokens: map[string]TokenRecord{}, revoked: map[string]string{},
		total: map[string]int{}, perScope: map[string]map[int]int{}, approvals: map[string]bool{}}
}

func (m *Memory) PutWorkload(_ context.Context, w Workload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.workloads[w.Name] = w
	return nil
}

func (m *Memory) GetWorkload(_ context.Context, name string) (Workload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.workloads[name]
	if !ok {
		return w, ErrNotFound
	}
	return w, nil
}

func (m *Memory) PutToken(_ context.Context, t TokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.ID] = t
	return nil
}

func (m *Memory) GetToken(_ context.Context, id string) (TokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return t, ErrNotFound
	}
	return t, nil
}

func (m *Memory) Children(_ context.Context, id string) ([]TokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []TokenRecord
	for _, t := range m.tokens {
		if t.Parent == id {
			out = append(out, t)
		}
	}
	return out, nil
}

func (m *Memory) Revoke(_ context.Context, id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[id] = reason
	return nil
}

func (m *Memory) FirstRevoked(_ context.Context, ids []string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if _, ok := m.revoked[id]; ok {
			return id, nil
		}
	}
	return "", nil
}

func (m *Memory) Consume(_ context.Context, id string, scopeIdx int, lineage []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return ErrNotFound
	}
	if scopeIdx < 0 || scopeIdx >= len(t.ScopeLimits) {
		return ErrExhausted{Which: "scope index out of range"}
	}
	if m.perScope[id][scopeIdx] >= t.ScopeLimits[scopeIdx] {
		return ErrExhausted{Which: "scope max_calls"}
	}
	for _, a := range lineage {
		at, ok := m.tokens[a]
		if !ok {
			return ErrNotFound
		}
		if m.total[a] >= at.MaxCalls {
			return ErrExhausted{Which: "token max_calls of " + a}
		}
	}
	for _, a := range lineage {
		m.total[a]++
	}
	if m.perScope[id] == nil {
		m.perScope[id] = map[int]int{}
	}
	m.perScope[id][scopeIdx]++
	return nil
}

func (m *Memory) Usage(_ context.Context, id string) (int, map[int]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ps := map[int]int{}
	for k, v := range m.perScope[id] {
		ps[k] = v
	}
	return m.total[id], ps, nil
}

func (m *Memory) UseApproval(_ context.Context, id string, _ time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.approvals[id] {
		return false, nil
	}
	m.approvals[id] = true
	return true, nil
}
