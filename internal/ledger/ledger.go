// Package ledger is a minimal client for the Ledger HTTP API
// (POST /v1/records). When LEDGER_URL is unset it is a no-op recorder.
package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Actor is one element of an actor chain; the first must be kind "human".
type Actor struct {
	Kind         string `json:"kind"`
	ID           string `json:"id"`
	Model        string `json:"model,omitempty"`
	ModelVersion string `json:"model_version,omitempty"`
}

// Record is the request body for POST /v1/records.
type Record struct {
	Chain         string         `json:"chain"`
	Type          string         `json:"type"`
	GoalID        string         `json:"goal_id,omitempty"`
	ActorChain    []Actor        `json:"actor_chain"`
	PolicyVersion string         `json:"policy_version,omitempty"`
	Payload       map[string]any `json:"payload"`
}

// Recorder emits records.
type Recorder interface {
	Record(ctx context.Context, r Record) error
}

// Noop discards records.
type Noop struct{}

func (Noop) Record(context.Context, Record) error { return nil }

// Client posts to a Ledger server.
type Client struct {
	URL, Token string
	HTTP       *http.Client
}

// FromEnv returns a Client if LEDGER_URL is set, else Noop.
func FromEnv() Recorder {
	u := os.Getenv("LEDGER_URL")
	if u == "" {
		return Noop{}
	}
	return &Client{URL: u, Token: os.Getenv("LEDGER_TOKEN"), HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func (c *Client) Record(ctx context.Context, r Record) error {
	if len(r.ActorChain) == 0 || r.ActorChain[0].Kind != "human" {
		return fmt.Errorf("ledger: actor_chain must start with a human")
	}
	b, _ := json.Marshal(r)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/records", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("ledger: status %d", resp.StatusCode)
	}
	return nil
}

// Memory captures records (tests).
type Memory struct {
	mu      sync.Mutex
	Records []Record
}

func (m *Memory) Record(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Records = append(m.Records, r)
	return nil
}

// Types returns the record types captured so far.
func (m *Memory) Types() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, r := range m.Records {
		out = append(out, r.Type)
	}
	return out
}
