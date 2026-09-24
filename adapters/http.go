package adapters

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ResourceFunc extracts the resource a request targets, e.g. from its path
// or query string. Tool is normally the route's own name/pattern.
type ResourceFunc func(r *http.Request) string

// HTTPMiddleware returns generic net/http middleware: it reads
// Authorization: Bearer <token>, X-Warrant-SVID and X-Warrant-Approval from
// the incoming request exactly like the PEP does, authorizes (tool,
// resource) against e, and only then calls next. On denial it writes a
// structured 403 JSON body and never calls next. Query parameters are
// passed through as args (so simple `?key=value` policy constraints work
// without a body).
func HTTPMiddleware(e *Enforcer, tool string, resourceOf ResourceFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			creds := Credentials{
				Token:    strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
				SVID:     r.Header.Get("X-Warrant-SVID"),
				Approval: r.Header.Get("X-Warrant-Approval"),
			}
			args := map[string]any{}
			for k, vs := range r.URL.Query() {
				if len(vs) > 0 {
					args[k] = vs[0]
				}
			}
			resource := "*"
			if resourceOf != nil {
				resource = resourceOf(r)
			}
			d, err := e.Authorize(r.Context(), creds, tool, resource, args)
			if err != nil {
				writeDenied(w, err)
				return
			}
			r.Header.Set("X-Warrant-Subject", d.Claims.Subject)
			r.Header.Set("X-Warrant-Token-ID", d.Claims.ID)
			next.ServeHTTP(w, r)
		})
	}
}

func writeDenied(w http.ResponseWriter, err error) {
	var den *Denied
	if d, ok := err.(*Denied); ok {
		den = d
	} else {
		den = &Denied{Reason: err.Error()}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"allow": false, "error": den})
}
