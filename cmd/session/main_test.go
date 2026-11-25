package main

import (
	"bytes"
	"strings"
	"testing"
)

// Decision 0024: exactly one of --audit-socket and --audit-stdout, whatever --audit-scope says; the scope is a label only (decision 0027).
func TestTheAuditTransportIsAnExplicitSwitch(t *testing.T) {
	tr, stop, err := auditTransport("", true, &bytes.Buffer{})
	if err != nil || tr == nil || stop == nil {
		t.Fatalf("--audit-stdout: %v", err)
	}
	stop()
	if tr, stop, err := auditTransport("/run/session/audit/emit.sock", false, &bytes.Buffer{}); err != nil || tr == nil || stop != nil {
		t.Fatalf("--audit-socket: %v", err)
	}
	if _, _, err := auditTransport("", false, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--audit-socket is required") {
		t.Fatalf("neither started: %v", err)
	}
	if _, _, err := auditTransport("/run/session/audit/emit.sock", true, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("both started: %v", err)
	}
}

func TestTheAuditScopeIsTheLabel(t *testing.T) {
	if s := auditScope(""); s != "local" {
		t.Fatalf("unset: scope %q", s)
	}
	for _, env := range []string{"local", "devel", "stage", "prod", "development", "production", "anything"} {
		if s := auditScope(env); s != env {
			t.Fatalf("%q: scope %q", env, s)
		}
	}
}
