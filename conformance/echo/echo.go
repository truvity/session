// Package echo is the test backend of the conformance suite: the site behind the proxy, which answers every request with what
// it received, as JSON. The local stand serves it in the test process, and the image ghcr.io/truvity/session-echo
// (conformance/echo/session-echo) serves it behind a deployed test site, so the suite reads the same answer from both
// (decision 0029). It is a test fixture: it echoes every header it gets, the identity header and the exchanged token included,
// so it must never stand behind a site that real people use.
package echo

import (
	"encoding/json"
	"net/http"
)

// Seen is what the site received: the method, the path with its query as the request line had it, and every header.
type Seen struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
}

// Handler answers every request, on every path and method, with the Seen of that request.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(Seen{Method: r.Method, Path: r.URL.RequestURI(), Headers: r.Header})
	})
}
