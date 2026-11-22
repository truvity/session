// Package audit holds the stand-in for the security-audit emitter of truvity/audit, which is planned (decision 0008). It writes
// each event as one JSON line to its own writer, apart from the operational log. It carries the fields of core.Event only: no
// header value, cookie, token or body. It never emits usage or billing records; there is no such kind.
package audit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/truvity/session/core"
)

// Lines writes events as JSON lines.
type Lines struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLines returns an emitter that writes to w.
func NewLines(w io.Writer) *Lines { return &Lines{w: w} }

type line struct {
	Time         string `json:"time"`
	Class        string `json:"class"`
	Kind         string `json:"kind"`
	Site         string `json:"site"`
	Subject      string `json:"subject,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	Route        string `json:"route,omitempty"`
	Reason       string `json:"reason,omitempty"`
	PolicyDigest string `json:"policy_digest,omitempty"`
}

// Emit writes one line. A write error is the transport being down: the caller counts it.
func (l *Lines) Emit(_ context.Context, e core.Event) error {
	b, err := json.Marshal(line{Time: e.Time.UTC().Format(time.RFC3339Nano), Class: "security", Kind: string(e.Kind), Site: e.Site,
		Subject: e.Subject, Issuer: e.Issuer, Route: e.Route, Reason: e.Reason, PolicyDigest: e.PolicyDigest})
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.w.Write(append(b, '\n'))
	return err
}

var _ core.Auditor = (*Lines)(nil)
