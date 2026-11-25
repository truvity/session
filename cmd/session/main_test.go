package main

import (
	"bytes"
	"strings"
	"testing"
)

// Decision 0023: the records go to stdout for local development only; every named environment needs --audit-socket.
func TestOnlyLocalDevelopmentWritesTheRecordsToStdout(t *testing.T) {
	for _, env := range []string{"", "local"} {
		tr, stop, err := auditTransport("", env, &bytes.Buffer{})
		if err != nil || tr == nil || stop == nil {
			t.Fatalf("%q: %v", env, err)
		}
		stop()
		if s := auditScope(env); s != "local" {
			t.Fatalf("%q: scope %q", env, s)
		}
		if d := driverEnvironment(env); d != "" {
			t.Fatalf("%q: driver environment %q", env, d)
		}
	}
	for _, env := range []string{"devel", "stage", "prod", "development", "staging", "production", "anything"} {
		if _, _, err := auditTransport("", env, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--audit-socket") {
			t.Fatalf("%q started without --audit-socket: %v", env, err)
		}
		if tr, stop, err := auditTransport("/run/session/audit/emit.sock", env, &bytes.Buffer{}); err != nil || tr == nil || stop != nil {
			t.Fatalf("%q with a socket: %v", env, err)
		}
		if auditScope(env) != env || driverEnvironment(env) != env {
			t.Fatalf("%q: scope %q, driver %q", env, auditScope(env), driverEnvironment(env))
		}
	}
}
