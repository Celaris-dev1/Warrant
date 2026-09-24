package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema is applied idempotently on startup.
const Schema = `
CREATE TABLE IF NOT EXISTS warrant_workloads (
  name TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS warrant_tokens (
  id TEXT PRIMARY KEY, parent TEXT, parent_actor TEXT, goal_id TEXT, subject TEXT NOT NULL, human TEXT NOT NULL, depth INT NOT NULL,
  max_calls INT NOT NULL, scope_limits INT[] NOT NULL, expires TIMESTAMPTZ NOT NULL, claims JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS warrant_tokens_parent ON warrant_tokens(parent);
CREATE INDEX IF NOT EXISTS warrant_tokens_goal ON warrant_tokens(goal_id);
ALTER TABLE warrant_tokens ADD COLUMN IF NOT EXISTS parent_actor TEXT;
ALTER TABLE warrant_tokens ADD COLUMN IF NOT EXISTS goal_id TEXT;
CREATE TABLE IF NOT EXISTS warrant_revocations (
  id TEXT PRIMARY KEY, reason TEXT NOT NULL, revoked_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS warrant_counters (
  token_id TEXT NOT NULL, scope_idx INT NOT NULL, calls INT NOT NULL DEFAULT 0,
  PRIMARY KEY (token_id, scope_idx));
CREATE TABLE IF NOT EXISTS warrant_approvals_used (
  id TEXT PRIMARY KEY, expires TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ NOT NULL DEFAULT now());
`

// scope_idx -1 in warrant_counters holds the whole-token total.
const totalIdx = -1

// Postgres is a pgx-backed Store.
type Postgres struct{ DB *pgxpool.Pool }

// OpenPostgres connects and migrates.
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, Schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Postgres{DB: db}, nil
}

func (p *Postgres) PutWorkload(ctx context.Context, w Workload) error {
	_, err := p.DB.Exec(ctx, `INSERT INTO warrant_workloads(name,secret_hash) VALUES($1,$2)
	  ON CONFLICT (name) DO UPDATE SET secret_hash=EXCLUDED.secret_hash`, w.Name, w.SecretHash)
	return err
}

func (p *Postgres) GetWorkload(ctx context.Context, name string) (Workload, error) {
	var w Workload
	err := p.DB.QueryRow(ctx, `SELECT name,secret_hash,created_at FROM warrant_workloads WHERE name=$1`, name).
		Scan(&w.Name, &w.SecretHash, &w.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, ErrNotFound
	}
	return w, err
}

func (p *Postgres) PutToken(ctx context.Context, t TokenRecord) error {
	var parent, parentActor, goalID *string
	if t.Parent != "" {
		parent = &t.Parent
	}
	if t.ParentActor != "" {
		parentActor = &t.ParentActor
	}
	if t.GoalID != "" {
		goalID = &t.GoalID
	}
	_, err := p.DB.Exec(ctx, `INSERT INTO warrant_tokens(id,parent,parent_actor,goal_id,subject,human,depth,max_calls,scope_limits,expires,claims)
	  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.ID, parent, parentActor, goalID, t.Subject, t.Human, t.Depth, t.MaxCalls, t.ScopeLimits, t.Expires, t.Claims)
	return err
}

const tokCols = `id,COALESCE(parent,''),COALESCE(parent_actor,''),COALESCE(goal_id,''),subject,human,depth,max_calls,scope_limits,expires,claims`

func scanTok(r pgx.Row) (TokenRecord, error) {
	var t TokenRecord
	var limits []int32
	err := r.Scan(&t.ID, &t.Parent, &t.ParentActor, &t.GoalID, &t.Subject, &t.Human, &t.Depth, &t.MaxCalls, &limits, &t.Expires, &t.Claims)
	for _, l := range limits {
		t.ScopeLimits = append(t.ScopeLimits, int(l))
	}
	return t, err
}

func (p *Postgres) GetToken(ctx context.Context, id string) (TokenRecord, error) {
	t, err := scanTok(p.DB.QueryRow(ctx, `SELECT `+tokCols+` FROM warrant_tokens WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func (p *Postgres) Children(ctx context.Context, id string) ([]TokenRecord, error) {
	rows, err := p.DB.Query(ctx, `SELECT `+tokCols+` FROM warrant_tokens WHERE parent=$1 ORDER BY created_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenRecord
	for rows.Next() {
		t, err := scanTok(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *Postgres) Revoke(ctx context.Context, id, reason string) error {
	_, err := p.DB.Exec(ctx, `INSERT INTO warrant_revocations(id,reason) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, reason)
	return err
}

func (p *Postgres) FirstRevoked(ctx context.Context, ids []string) (string, error) {
	rows, err := p.DB.Query(ctx, `SELECT id FROM warrant_revocations WHERE id = ANY($1)`, ids)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	hit := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
		hit[s] = true
	}
	for _, id := range ids {
		if hit[id] {
			return id, nil
		}
	}
	return "", rows.Err()
}

func (p *Postgres) Consume(ctx context.Context, id string, scopeIdx int, lineage []string) error {
	tx, err := p.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Lock rows in a stable order to avoid deadlocks between siblings.
	locked := append([]string{}, lineage...)
	sort.Strings(locked)
	limits := map[string]int{}
	var scopeLimits []int32
	for _, a := range locked {
		var mc int
		var sl []int32
		err := tx.QueryRow(ctx, `SELECT max_calls, scope_limits FROM warrant_tokens WHERE id=$1 FOR UPDATE`, a).Scan(&mc, &sl)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		limits[a] = mc
		if a == id {
			scopeLimits = sl
		}
	}
	if scopeIdx < 0 || scopeIdx >= len(scopeLimits) {
		return ErrExhausted{Which: "scope index out of range"}
	}
	get := func(tok string, idx int) (int, error) {
		var n int
		err := tx.QueryRow(ctx, `SELECT calls FROM warrant_counters WHERE token_id=$1 AND scope_idx=$2`, tok, idx).Scan(&n)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return n, err
	}
	n, err := get(id, scopeIdx)
	if err != nil {
		return err
	}
	if n >= int(scopeLimits[scopeIdx]) {
		return ErrExhausted{Which: "scope max_calls"}
	}
	for _, a := range lineage {
		n, err := get(a, totalIdx)
		if err != nil {
			return err
		}
		if n >= limits[a] {
			return ErrExhausted{Which: "token max_calls of " + a}
		}
	}
	inc := `INSERT INTO warrant_counters(token_id,scope_idx,calls) VALUES($1,$2,1)
	  ON CONFLICT (token_id,scope_idx) DO UPDATE SET calls=warrant_counters.calls+1`
	for _, a := range lineage {
		if _, err := tx.Exec(ctx, inc, a, totalIdx); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, inc, id, scopeIdx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) Usage(ctx context.Context, id string) (int, map[int]int, error) {
	rows, err := p.DB.Query(ctx, `SELECT scope_idx, calls FROM warrant_counters WHERE token_id=$1`, id)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	total, ps := 0, map[int]int{}
	for rows.Next() {
		var i, n int
		if err := rows.Scan(&i, &n); err != nil {
			return 0, nil, err
		}
		if i == totalIdx {
			total = n
		} else {
			ps[i] = n
		}
	}
	return total, ps, rows.Err()
}

func (p *Postgres) UseApproval(ctx context.Context, id string, expires time.Time) (bool, error) {
	tag, err := p.DB.Exec(ctx, `INSERT INTO warrant_approvals_used(id,expires) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, expires)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
