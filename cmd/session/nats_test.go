package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	transportv1 "github.com/truvity/atoom/transport/gen/atoom/transport/v1alpha1"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/audit"
	"github.com/truvity/session/internal/sealer"
	"github.com/truvity/session/internal/sealer/sealertest"
)

// Decision 0032: --audit-nats against a real NATS server with JetStream (`just test-nats`, a container that asks for a token): the
// stream is the deployment's, made here as a deployment would, and session only publishes to it. A sign-in's record lands once, and
// a retry of its message (the same uid) is dropped by JetStream's duplicate window.
func TestTheSignInRecordLandsOnceOnNATS(t *testing.T) {
	url, token := os.Getenv("SESSION_TEST_NATS"), os.Getenv("SESSION_TEST_NATS_TOKEN")
	if url == "" {
		t.Skip("SESSION_TEST_NATS is not set: run `just test-nats`, which starts a NATS server with JetStream in a container")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	run := hex.EncodeToString(b)
	stream, subject := "session-audit-"+run, "audit.session."+run

	nc, err := natsgo.Connect(url, natsgo.Token(token))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: stream, Subjects: []string{subject}, Storage: jetstream.MemoryStorage,
		Duplicates: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(context.Background(), stream) }()

	tokenFile := filepath.Join(t.TempDir(), "nats.token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil { //nolint:gosec // a file in the test's own directory
		t.Fatal(err)
	}
	tr, stop, err := auditTransport(auditFlags{nats: audit.NATSOptions{URL: url, Stream: stream, Subject: subject, TokenFile: tokenFile}}, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	a, err := audit.New(audit.Options{Transport: tr, Pseudonyms: sealertest.New(t).(*sealer.Sealer), Release: "0.0.0-dev", Scope: "local"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Emit(ctx, core.Event{Kind: core.EventSignIn, Site: "docs", Subject: "8f2b6d0c-person-subject",
		Issuer: "https://issuer.example.com/realms/docs"}); err != nil {
		t.Fatalf("the sign-in's blocking emit: %v", err)
	}

	raw, err := st.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := raw.Header.Get("Atoom-Emitter"); got != audit.Emitter {
		t.Fatalf("emitter %q", got)
	}
	var m transportv1.Message
	if err := proto.Unmarshal(raw.Data, &m); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(m.GetPayload(), &rec); err != nil {
		t.Fatal(err)
	}
	if md, _ := rec["metadata"].(map[string]any); md["event_code"] != "sign-in" || md["uid"] != m.GetId() {
		t.Fatalf("the record: %s", m.GetPayload())
	}

	// A retry of the same message, as the emitter makes one after an answer it did not get, is one message in the stream.
	if _, err := tr.Emit(ctx, connect.NewRequest(&transportv1.EmitRequest{Message: &m, Blocking: true})); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	info, err := st.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("%d messages in the stream, want 1", info.State.Msgs)
	}
}
