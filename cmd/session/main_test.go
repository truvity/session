package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/truvity/session/internal/audit"
)

// cfg is an AWS configuration that makes no call when a client is built from it.
var cfg = aws.Config{Region: "eu-west-1", Credentials: aws.AnonymousCredentials{}}

const (
	socketPath = "/run/session/audit/emit.sock"
	queueURL   = "https://sqs.example.com/audit.fifo"
)

// runDir is where a deployment puts the files the NATS flags name; nothing reads them in these tests.
const runDir = "/run/session"

var natsSet = audit.NATSOptions{URL: "nats://127.0.0.1:1", Stream: "audit", Subject: "audit.session"}

// Decisions 0024 and 0032: exactly one of --audit-socket, --audit-nats, --audit-sqs and --audit-stdout, whatever --audit-scope
// says; the scope is a label only (decision 0027).
func TestTheAuditTransportIsAnExplicitSwitch(t *testing.T) {
	for _, c := range []struct {
		name string
		f    auditFlags
		kind string
	}{
		{"--audit-stdout", auditFlags{stdout: true}, "stdout"},
		{"--audit-socket", auditFlags{socket: socketPath}, "socket"},
		{"--audit-sqs", auditFlags{sqs: queueURL}, "sqs"},
		{"--audit-nats", auditFlags{nats: natsSet}, "nats"},
		{"--audit-nats with a token file and a CA", auditFlags{nats: audit.NATSOptions{URL: natsSet.URL, Stream: "audit", Subject: "audit.session",
			TokenFile: filepath.Join(runDir, "nats.token"), TLSCA: filepath.Join(runDir, "ca.pem")}}, "nats"},
		{"--audit-nats with a credentials file", auditFlags{nats: audit.NATSOptions{URL: natsSet.URL, Stream: "audit", Subject: "audit.session",
			Creds: filepath.Join(runDir, "nats.creds")}}, "nats"},
	} {
		kind, err := c.f.choice()
		if err != nil || kind != c.kind {
			t.Fatalf("%s: %q, %v", c.name, kind, err)
		}
	}
	// Each one builds its client; the credentials file is not read here, so the case without one builds.
	for _, f := range []auditFlags{{stdout: true}, {socket: socketPath}, {sqs: queueURL}, {nats: natsSet}} {
		tr, stop, err := auditTransport(f, cfg, &bytes.Buffer{})
		if err != nil || tr == nil || stop == nil {
			t.Fatalf("%+v: %v", f, err)
		}
		stop()
	}
}

func TestTheAuditTransportRefusesZeroOrSeveral(t *testing.T) {
	all := []struct {
		name string
		f    auditFlags
	}{
		{"--audit-socket", auditFlags{socket: socketPath}},
		{"--audit-nats", auditFlags{nats: natsSet}},
		{"--audit-sqs", auditFlags{sqs: queueURL}},
		{"--audit-stdout", auditFlags{stdout: true}},
	}
	merge := func(a, b auditFlags) auditFlags {
		if b.socket != "" {
			a.socket = b.socket
		}
		if b.nats.URL != "" {
			a.nats = b.nats
		}
		if b.sqs != "" {
			a.sqs = b.sqs
		}
		a.stdout = a.stdout || b.stdout
		return a
	}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			f := merge(all[i].f, all[j].f)
			_, err := f.choice()
			want := all[i].name + " and " + all[j].name + " are both given"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s with %s: %v", all[i].name, all[j].name, err)
			}
			if _, _, err := auditTransport(f, cfg, &bytes.Buffer{}); err == nil {
				t.Fatalf("%s with %s: built", all[i].name, all[j].name)
			}
		}
	}
	f := merge(merge(all[0].f, all[1].f), merge(all[2].f, all[3].f))
	if _, err := f.choice(); err == nil || !strings.Contains(err.Error(), "are all given") {
		t.Fatalf("all four: %v", err)
	}
	if _, err := (auditFlags{}).choice(); err == nil || !strings.Contains(err.Error(), "an audit transport is required") ||
		!strings.Contains(err.Error(), "--audit-stdout") {
		t.Fatalf("none: %v", err)
	}
}

func TestTheNATSSwitchNeedsItsSettingsAndOnlyThen(t *testing.T) {
	for _, c := range []struct {
		name string
		f    auditFlags
		want string
	}{
		{"no stream", auditFlags{nats: audit.NATSOptions{URL: natsSet.URL, Subject: "audit.session"}}, "--audit-nats needs --audit-nats-stream and --audit-nats-subject"},
		{"no subject", auditFlags{nats: audit.NATSOptions{URL: natsSet.URL, Stream: "audit"}}, "--audit-nats needs --audit-nats-stream and --audit-nats-subject"},
		{"two credentials", auditFlags{nats: audit.NATSOptions{URL: natsSet.URL, Stream: "audit", Subject: "audit.session", Creds: "a", TokenFile: "b"}},
			"--audit-nats-creds and --audit-nats-token-file are both given"},
		{"a stream without --audit-nats", auditFlags{socket: socketPath, nats: audit.NATSOptions{Stream: "audit"}}, "--audit-nats-stream is given without --audit-nats"},
		{"a subject without --audit-nats", auditFlags{sqs: queueURL, nats: audit.NATSOptions{Subject: "audit.session"}}, "--audit-nats-subject is given without --audit-nats"},
		{"a credentials file without --audit-nats", auditFlags{stdout: true, nats: audit.NATSOptions{Creds: "a"}}, "--audit-nats-creds is given without --audit-nats"},
		{"a token file without --audit-nats", auditFlags{nats: audit.NATSOptions{TokenFile: "a"}}, "--audit-nats-token-file is given without --audit-nats"},
		{"a CA without --audit-nats", auditFlags{nats: audit.NATSOptions{TLSCA: "a"}}, "--audit-nats-tls-ca is given without --audit-nats"},
	} {
		if _, err := c.f.choice(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
}

// atoom's transport/sqs refuses a queue that is not FIFO: a standard queue does not keep the order (decision 0032).
func TestTheSQSSwitchNeedsAFIFOQueue(t *testing.T) {
	if _, _, err := auditTransport(auditFlags{sqs: "https://sqs.example.com/audit"}, cfg, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "FIFO") {
		t.Fatalf("a standard queue: %v", err)
	}
}

// Decision 0032: exactly one of --config-dir and --source-appconfig, and --source-appconfig is APP/ENV/PROFILE.
func TestTheSourceIsOneSwitch(t *testing.T) {
	for _, c := range []struct {
		f          serveFlags
		kind, want string
	}{
		{serveFlags{configDir: "/etc/session"}, "file", ""},
		{serveFlags{sourceAppConfig: "session/devel/site"}, "appconfig", ""},
		{serveFlags{}, "", "--config-dir or --source-appconfig is required"},
		{serveFlags{configDir: "/etc/session", sourceAppConfig: "session/devel/site"}, "", "--config-dir and --source-appconfig are both given"},
		{serveFlags{sourceAppConfig: "session/devel"}, "", "is not APP/ENV/PROFILE"},
		{serveFlags{sourceAppConfig: "session//site"}, "", "is not APP/ENV/PROFILE"},
		{serveFlags{sourceAppConfig: "session/devel/site/extra"}, "", "is not APP/ENV/PROFILE"},
		{serveFlags{sourceAppConfig: "/devel/site"}, "", "is not APP/ENV/PROFILE"},
	} {
		kind, err := c.f.sourceChoice()
		if c.want == "" && (err != nil || kind != c.kind) {
			t.Fatalf("%+v: %q, %v", c.f, kind, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Fatalf("%+v: %v", c.f, err)
		}
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
	if err := authorizer([]string{"--source-appconfig", "session/devel/site", "--dynamodb-table", "sessions"}); err == nil ||
		!strings.Contains(err.Error(), "AWS_LAMBDA_RUNTIME_API") {
		t.Fatalf("outside Lambda, on AppConfig: %v", err)
	}
	if err := authorizer([]string{"--dynamodb-table", "sessions"}); err == nil || !strings.Contains(err.Error(), "--config-dir or --source-appconfig is required") {
		t.Fatalf("no source: %v", err)
	}
	if err := authorizer([]string{"--config-dir", t.TempDir(), "--source-appconfig", "session/devel/site", "--dynamodb-table", "sessions"}); err == nil ||
		!strings.Contains(err.Error(), "both given") {
		t.Fatalf("two sources: %v", err)
	}
}
