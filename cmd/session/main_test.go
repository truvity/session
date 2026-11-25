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

// Decision 0014: the authorizer is a native handler of a Lambda function, and refuses to run anywhere else; it needs the site
// and the store like `session serve`.
func TestTheAuthorizerRunsOnLambdaOnly(t *testing.T) {
	t.Setenv("AWS_LAMBDA_RUNTIME_API", "")
	if err := authorizer([]string{"--config-dir", t.TempDir(), "--dynamodb-table", "sessions"}); err == nil ||
		!strings.Contains(err.Error(), "AWS_LAMBDA_RUNTIME_API") {
		t.Fatalf("outside Lambda: %v", err)
	}
	if err := authorizer([]string{"--dynamodb-table", "sessions"}); err == nil || !strings.Contains(err.Error(), "--config-dir is required") {
		t.Fatalf("no config dir: %v", err)
	}
}
