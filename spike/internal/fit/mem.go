package fit

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/truvity/session/spike/internal/sess"
)

// Mem is an in-memory session store for tests that run without DynamoDB Local (the Lambda emulator test).
// The session id "sess-ok" is a live session of alice, and the id "boom" makes the store fail.
type Mem struct {
	mu sync.Mutex
	m  map[string]*sess.Record
}

func NewMem() *Mem {
	return &Mem{m: map[string]*sess.Record{"sess-ok": {Sub: "alice", Iss: "iss", Email: "alice@example.test", Groups: []string{"staff"}}}}
}

func (s *Mem) Get(_ context.Context, id string, _ bool) (*sess.Loaded, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "boom" {
		return nil, errors.New("store down")
	}
	r, ok := s.m[id]
	if !ok {
		return nil, sess.ErrNotFound
	}
	return &sess.Loaded{Rec: r, Created: time.Now().Unix(), LastSeen: time.Now().Unix()}, nil
}

func (s *Mem) Touch(context.Context, string, *sess.Loaded) (bool, error) { return false, nil }

var _ sess.CheckStore = (*Mem)(nil)
