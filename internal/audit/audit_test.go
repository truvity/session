package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/audit/emitter"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/audit"
	"github.com/truvity/session/internal/sealer"
	"github.com/truvity/session/internal/sealer/sealertest"
)

const (
	subject = "8f2b6d0c-person-subject"
	issuer  = "https://issuer.example.com/realms/docs"
	digest  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var (
	pseudonymRE = regexp.MustCompile(`^p1\.202611\.[A-Za-z0-9_-]{22}$`)
	clock       = func() time.Time { return time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC) }
)

// syncBuffer is a bytes.Buffer safe for the driver's goroutine and the test's.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Split(strings.TrimSuffix(s.b.String(), "\n"), "\n")
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("down") }

type failingPseudonyms struct{}

func (failingPseudonyms) Pseudonym(context.Context, string, []byte, uint32) ([]byte, error) {
	return nil, errors.New("the seal block is down")
}

func newAuditor(t *testing.T, w interface{ Write([]byte) (int, error) }, p audit.Pseudonymiser) *audit.Auditor {
	t.Helper()
	if p == nil {
		p = sealertest.New(t).(*sealer.Sealer)
	}
	tr, stop := audit.NewLines(w).Mount()
	t.Cleanup(stop)
	a, err := audit.New(audit.Options{Transport: tr, Pseudonyms: p, Release: "0.0.0-dev", Scope: "development", Policy: "policy-bundle", Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func record(t *testing.T, a *audit.Auditor, e core.Event) map[string]any {
	t.Helper()
	if e.Site == "" {
		e.Site = "docs"
	}
	b, err := a.Record(context.Background(), e)
	if err != nil {
		t.Fatalf("%s: %v", e.Kind, err)
	}
	if bytes.Contains(b, []byte(subject)) {
		t.Fatalf("%s: the subject is in the record: %s", e.Kind, b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func at(m map[string]any, path ...string) any {
	var v any = m
	for _, p := range path {
		o, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = o[p]
	}
	return v
}

func TestTheTableAndItsSchemasLoad(t *testing.T) {
	if _, err := audit.Table(); err != nil {
		t.Fatal(err)
	}
	if err := emitter.CheckPolicy(audit.Schemas()); err != nil {
		t.Fatal(err)
	}
	if n := len(audit.Schemas()); n != 7 {
		t.Fatalf("documents: %d", n)
	}
}

func TestEveryKindMapsToAValidRecord(t *testing.T) {
	a := newAuditor(t, &syncBuffer{}, nil)
	cases := []struct {
		e                  core.Event
		action             string
		class, activity    float64
		status             float64
		code               string
		named, policy, api bool
	}{
		{core.Event{Kind: core.EventSignIn, Subject: subject, Issuer: issuer}, "sign-in", 3002, 1, 1, "", true, false, false},
		{core.Event{Kind: core.EventSignInFailed, Issuer: issuer, Reason: "state"}, "sign-in", 3002, 1, 2, "state", false, false, false},
		{core.Event{Kind: core.EventLogout, Subject: subject, Issuer: issuer}, "logout", 3002, 2, 1, "", true, false, false},
		{core.Event{Kind: core.EventBackChannelLogout, Subject: subject, Issuer: issuer}, "back-channel-logout", 3002, 2, 1, "", true, false, false},
		{core.Event{Kind: core.EventBackChannelLogout, Issuer: issuer, Reason: "signature"}, "back-channel-logout", 3002, 2, 2, "signature", false, false, false},
		{core.Event{Kind: core.EventDenied, Route: "/api/", Reason: "csrf"}, "denied", 6003, 99, 2, "csrf", false, false, true},
		{core.Event{Kind: core.EventDenied, Subject: subject, Issuer: issuer, Route: "/api/", Reason: "forbidden", PolicyDigest: digest},
			"denied", 6003, 99, 2, "forbidden", true, true, true},
		{core.Event{Kind: core.EventExchange, Subject: subject, Issuer: issuer, Audience: "https://billing.example.com"}, "token-exchange", 3002, 99, 1, "", true, false, false},
		{core.Event{Kind: core.EventExchange, Subject: subject, Issuer: issuer, Audience: "https://billing.example.com", Reason: "invalid_target"},
			"token-exchange", 3002, 99, 2, "invalid_target", true, false, false},
		{core.Event{Kind: core.EventRefreshFailed, Subject: subject, Issuer: issuer, Reason: "invalid_grant"}, "refresh", 3002, 99, 2, "invalid_grant", true, false, false},
	}
	for _, c := range cases {
		m := record(t, a, c.e)
		if got := at(m, "metadata", "event_code"); got != c.action {
			t.Errorf("%s: event_code %v", c.e.Kind, got)
		}
		if at(m, "class_uid") != c.class || at(m, "activity_id") != c.activity || at(m, "status_id") != c.status {
			t.Errorf("%s: class %v activity %v status %v", c.e.Kind, at(m, "class_uid"), at(m, "activity_id"), at(m, "status_id"))
		}
		if code, _ := at(m, "status_code").(string); code != c.code {
			t.Errorf("%s: status_code %q", c.e.Kind, code)
		}
		if at(m, "metadata", "product", "name") != "session" || at(m, "metadata", "log_name") != "development" ||
			at(m, "actor", "user", "uid") != "session@development" || at(m, "unmapped", "session", "site") != "docs" {
			t.Errorf("%s: product, scope or site: %v", c.e.Kind, m)
		}
		var uid string
		if c.api {
			if at(m, "api", "operation") != "check" || at(m, "src_endpoint", "name") != "unknown" {
				t.Errorf("%s: api %v", c.e.Kind, m)
			}
			if rs, ok := at(m, "resources").([]any); ok && len(rs) == 1 {
				uid, _ = rs[0].(map[string]any)["uid"].(string)
			}
		} else {
			uid, _ = at(m, "user", "uid").(string)
		}
		switch {
		case c.named && !pseudonymRE.MatchString(uid):
			t.Errorf("%s: subject %q is not a pseudonym", c.e.Kind, uid)
		case !c.named && !c.api && uid != "unknown":
			t.Errorf("%s: subject %q, want unknown", c.e.Kind, uid)
		}
		if c.policy != (at(m, "policy") != nil) {
			t.Errorf("%s: policy %v", c.e.Kind, at(m, "policy"))
		}
		if c.policy && (at(m, "policy", "uid") != "policy-bundle" || at(m, "policy", "version") != digest || at(m, "action_id") != float64(2)) {
			t.Errorf("%s: policy %v", c.e.Kind, m)
		}
	}
}

func TestThePseudonymIsStableAndBoundToTheSubject(t *testing.T) {
	a := newAuditor(t, &syncBuffer{}, nil)
	uid := func(sub string) any {
		return at(record(t, a, core.Event{Kind: core.EventLogout, Subject: sub, Issuer: issuer}), "user", "uid")
	}
	if one, two, other := uid(subject), uid(subject), uid(subject+"-2"); one != two || one == other {
		t.Fatalf("pseudonyms %v %v %v", one, two, other)
	}
}

func TestARefusalIsAuditedWithoutItsSubjectWhenThePseudonymCannotBeMade(t *testing.T) {
	a := newAuditor(t, &syncBuffer{}, failingPseudonyms{})
	m := record(t, a, core.Event{Kind: core.EventRefreshFailed, Subject: subject, Issuer: issuer, Reason: "invalid_grant"})
	if at(m, "user", "uid") != "unknown" {
		t.Fatalf("user %v", at(m, "user"))
	}
	if _, err := a.Record(context.Background(), core.Event{Kind: core.EventSignIn, Site: "docs", Subject: subject, Issuer: issuer}); err == nil {
		t.Fatal("a sign-in was recorded without its subject")
	}
}

func TestAReasonThatIsNotAWordIsUnrecognised(t *testing.T) {
	a := newAuditor(t, &syncBuffer{}, nil)
	for _, reason := range []string{"bad code", "1abc", "x@y.example", strings.Repeat("a", 65), "é"} {
		m := record(t, a, core.Event{Kind: core.EventExchange, Subject: subject, Issuer: issuer, Audience: "https://billing.example.com", Reason: reason})
		if at(m, "status_code") != "unrecognised" {
			t.Errorf("%q: %v", reason, at(m, "status_code"))
		}
	}
}

func TestAnUnknownKindIsRefused(t *testing.T) {
	a := newAuditor(t, &syncBuffer{}, nil)
	if err := a.Emit(context.Background(), core.Event{Kind: "usage", Site: "docs"}); err == nil {
		t.Fatal("an unknown kind was emitted")
	}
}

func TestLinesWritesOneRecordALine(t *testing.T) {
	var w syncBuffer
	a := newAuditor(t, &w, nil)
	ctx := context.Background()
	for _, e := range []core.Event{
		{Kind: core.EventSignIn, Site: "docs", Subject: subject, Issuer: issuer},
		{Kind: core.EventDenied, Site: "docs", Route: core.PathLogout, Reason: "csrf"},
	} {
		if err := a.Emit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	lines := w.lines()
	if len(lines) != 2 {
		t.Fatalf("lines: %q", lines)
	}
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil || strings.Contains(l, subject) {
			t.Fatalf("line %q: %v", l, err)
		}
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(lines[1]), &m)
	if at(m, "api", "operation") != "logout" {
		t.Fatalf("operation %v", at(m, "api"))
	}
}

func TestATransportThatIsDownFailsTheSignInAndCountsTheRest(t *testing.T) {
	a := newAuditor(t, failingWriter{}, nil)
	ctx := context.Background()
	if err := a.Emit(ctx, core.Event{Kind: core.EventSignIn, Site: "docs", Subject: subject, Issuer: issuer}); err == nil {
		t.Fatal("a sign-in's event went nowhere and nobody was told")
	}
	if a.Lost() != 0 {
		t.Fatalf("a sign-in's event counted as lost: %d", a.Lost())
	}
	if err := a.Emit(ctx, core.Event{Kind: core.EventLogout, Site: "docs", Subject: subject, Issuer: issuer}); err == nil {
		t.Fatal("a lost event was not reported")
	}
	if a.Lost() != 1 {
		t.Fatalf("lost %d", a.Lost())
	}
}

func TestTheReleaseIsASemanticVersion(t *testing.T) {
	tr, stop := audit.NewLines(&syncBuffer{}).Mount()
	defer stop()
	if _, err := audit.New(audit.Options{Transport: tr, Pseudonyms: failingPseudonyms{}, Release: "dev", Scope: "development"}); err == nil {
		t.Fatal("the release dev was taken")
	}
}

func TestTheSchemasAreClosed(t *testing.T) {
	table, err := audit.Table()
	if err != nil {
		t.Fatal(err)
	}
	tr, stop := audit.NewLines(&syncBuffer{}).Mount()
	defer stop()
	e, err := emitter.New(emitter.Config{Product: "session", Release: "0.0.0-dev", Scope: "development", Component: "session", Table: table, Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	logoff := emitter.Action{Name: "logout", ClassUID: 3002, ActivityID: 2}
	for name, ev := range map[string]emitter.Event{
		"no site":       {Action: logoff, Status: emitter.StatusSuccess},
		"another field": {Action: logoff, Status: emitter.StatusSuccess, ProductObject: map[string]any{"site": "docs", "cookie": "x"}},
		"an outcome":    {Action: logoff, Status: emitter.StatusFailure, StatusCode: "x", ProductObject: map[string]any{"site": "docs"}},
		"no audience": {Action: emitter.Action{Name: "token-exchange", ClassUID: 3002, ActivityID: 99, ActivityName: "Token Exchange"},
			Status: emitter.StatusSuccess, ProductObject: map[string]any{"site": "docs"}},
	} {
		if _, _, err := e.Record(context.Background(), ev); err == nil {
			t.Errorf("%s: the record validated", name)
		}
	}
}
