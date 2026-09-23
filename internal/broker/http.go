package broker

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// Handler returns the broker's HTTP API. adminToken guards administrative
// endpoints (workload registration, root mint, approvals, revocation).
func (s *Service) Handler(adminToken string) http.Handler {
	mux := http.NewServeMux()
	admin := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !isAdmin(r, adminToken) {
				writeErr(w, http.StatusUnauthorized, errors.New("admin token required"))
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
			"kid": s.Signer.KID, "x": base64.RawURLEncoding.EncodeToString(s.Signer.Pub)}}})
	})
	mux.HandleFunc("POST /v1/workloads", admin(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name, Secret string }
		if !decode(w, r, &req) {
			return
		}
		if err := s.RegisterWorkload(r.Context(), req.Name, req.Secret); err != nil {
			writeErr(w, status(err), err)
			return
		}
		writeJSON(w, 201, map[string]string{"name": req.Name, "spiffe_prefix": s.SpiffeID(req.Name, "")})
	}))
	mux.HandleFunc("POST /v1/identity", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Workload, Secret, Instance string }
		if !decode(w, r, &req) {
			return
		}
		t, c, err := s.IssueSVID(r.Context(), req.Workload, req.Secret, req.Instance)
		if err != nil {
			writeErr(w, status(err), err)
			return
		}
		writeJSON(w, 201, map[string]any{"svid": t, "spiffe_id": c.Subject, "expires": c.Expires})
	})
	mux.HandleFunc("POST /v1/tokens", admin(func(w http.ResponseWriter, r *http.Request) {
		var req MintRequest
		if !decode(w, r, &req) {
			return
		}
		iss, err := s.MintRoot(r.Context(), req)
		if err != nil {
			writeErr(w, status(err), err)
			return
		}
		writeJSON(w, 201, iss)
	}))
	mux.HandleFunc("POST /v1/tokens/delegate", func(w http.ResponseWriter, r *http.Request) {
		var req DelegateRequest
		if !decode(w, r, &req) {
			return
		}
		iss, err := s.Delegate(r.Context(), req)
		if err != nil {
			writeErr(w, status(err), err)
			return
		}
		writeJSON(w, 201, iss)
	})
	mux.HandleFunc("POST /v1/approvals", admin(func(w http.ResponseWriter, r *http.Request) {
		var req ApproveRequest
		if !decode(w, r, &req) {
			return
		}
		a, err := s.Approve(r.Context(), req)
		if err != nil {
			writeErr(w, status(err), err)
			return
		}
		writeJSON(w, 201, a)
	}))
	mux.HandleFunc("POST /v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var req AuthorizeRequest
		if !decode(w, r, &req) {
			return
		}
		d := s.Authorize(r.Context(), req)
		code := 200
		if !d.Allow {
			code = 403
		}
		writeJSON(w, code, d)
	})
	mux.HandleFunc("POST /v1/tokens/{id}/revoke", admin(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Reason string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Reason == "" {
			req.Reason = "revoked"
		}
		if err := s.Revoke(r.Context(), r.PathValue("id"), req.Reason, "admin"); err != nil {
			writeErr(w, status(err), err)
			return
		}
		writeJSON(w, 200, map[string]string{"revoked": r.PathValue("id")})
	}))
	mux.HandleFunc("GET /v1/tokens/{id}/blast-radius", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		// Admins may inspect any token; a holder may inspect its own.
		if !isAdmin(r, adminToken) {
			c, err := token.Verify(s.Signer.Pub, bearer(r), s.Now())
			if err != nil || c.Kind != "capability" || !contains(c.Lineage(), id) {
				writeErr(w, http.StatusUnauthorized, errors.New("admin token or a token in this lineage required"))
				return
			}
		}
		br, err := s.BlastRadius(r.Context(), id)
		if err != nil {
			writeErr(w, status(err), err)
			return
		}
		writeJSON(w, 200, br)
	})
	return mux
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func isAdmin(r *http.Request, adminToken string) bool {
	return adminToken != "" && subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(adminToken)) == 1
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, err)
		return false
	}
	return true
}

func status(err error) int {
	var ex store.ErrExhausted
	switch {
	case errors.Is(err, ErrBadRequest):
		return 400
	case errors.Is(err, ErrBadSecret), errors.Is(err, token.ErrSignature), errors.Is(err, token.ErrExpired),
		errors.Is(err, token.ErrMalformed), errors.Is(err, ErrWrongKind):
		return 401
	case errors.Is(err, store.ErrNotFound):
		return 404
	case errors.Is(err, ErrPolicy), errors.Is(err, ErrDepth), errors.Is(err, ErrEmptyScope), errors.Is(err, ErrRevoked),
		errors.Is(err, ErrBinding), errors.As(err, &ex):
		return 403
	}
	return 500
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
