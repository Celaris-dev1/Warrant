package store

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/token"
)

func stores(t *testing.T) map[string]Store {
	out := map[string]Store{"memory": NewMemory()}
	if url := os.Getenv("WARRANT_TEST_DATABASE_URL"); url != "" {
		p, err := OpenPostgres(context.Background(), url)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.DB.Close)
		out["postgres"] = p
	} else {
		t.Log("WARRANT_TEST_DATABASE_URL unset: skipping postgres store")
	}
	return out
}

func TestConsumeChargesLineage(t *testing.T) {
	ctx := context.Background()
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			root, child := token.NewID(), token.NewID()
			exp := time.Now().Add(time.Hour)
			must(t, s.PutToken(ctx, TokenRecord{ID: root, Subject: "a", Human: "h", MaxCalls: 3, ScopeLimits: []int{3}, Expires: exp, Claims: []byte("{}")}))
			must(t, s.PutToken(ctx, TokenRecord{ID: child, Parent: root, Subject: "b", Human: "h", Depth: 1, MaxCalls: 3, ScopeLimits: []int{2}, Expires: exp, Claims: []byte("{}")}))
			must(t, s.Consume(ctx, child, 0, []string{root, child}))
			must(t, s.Consume(ctx, child, 0, []string{root, child}))
			if err := s.Consume(ctx, child, 0, []string{root, child}); err == nil {
				t.Fatal("child scope budget not enforced")
			}
			must(t, s.Consume(ctx, root, 0, []string{root}))
			if err := s.Consume(ctx, root, 0, []string{root}); err == nil {
				t.Fatal("root total budget (shared with child) not enforced")
			}
			total, _, _ := s.Usage(ctx, root)
			if total != 3 {
				t.Fatalf("root total = %d", total)
			}
			must(t, s.Revoke(ctx, root, "test"))
			if r, _ := s.FirstRevoked(ctx, []string{root, child}); r != root {
				t.Fatalf("revocation lookup = %q", r)
			}
			id := token.NewID()
			ok, _ := s.UseApproval(ctx, id, exp)
			again, _ := s.UseApproval(ctx, id, exp)
			if !ok || again {
				t.Fatal("approval must be single-use")
			}
			kids, _ := s.Children(ctx, root)
			if len(kids) != 1 || kids[0].ID != child {
				t.Fatalf("children = %+v", kids)
			}
		})
	}
}

func TestConsumeConcurrentNeverOverspends(t *testing.T) {
	ctx := context.Background()
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			id := token.NewID()
			must(t, s.PutToken(ctx, TokenRecord{ID: id, Subject: "a", Human: "h", MaxCalls: 10, ScopeLimits: []int{100}, Expires: time.Now().Add(time.Hour), Claims: []byte("{}")}))
			var wg sync.WaitGroup
			var mu sync.Mutex
			ok := 0
			for i := 0; i < 40; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if s.Consume(ctx, id, 0, []string{id}) == nil {
						mu.Lock()
						ok++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			if ok != 10 {
				t.Fatalf("%d calls succeeded, want exactly 10", ok)
			}
		})
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
