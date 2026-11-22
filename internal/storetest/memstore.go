// Package storetest is a test double of atoom's store port: the item contract (store/docs/store-port.md) over a map, served as
// the generated ConnectRPC handler and reached through the generated client on the in-memory transport, as a real driver is.
//
// It exists because atoom's memory driver (store/memory) is Rust only, so a Go test cannot link it in process. It is for tests
// only: it keeps nothing, has no change log, and is not a driver. The same tests run against atoom's store/dynamodb driver on
// DynamoDB Local (core's dynamodb_test.go), which holds this double to the real contract.
package storetest

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/truvity/atoom/common/call"
	"github.com/truvity/atoom/common/refusal"
	storev1 "github.com/truvity/atoom/store/gen/atoom/store/v1alpha1"
	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"

	"github.com/truvity/session/internal/atoomx"
)

// Store is the double.
type Store struct {
	storev1alpha1connect.UnimplementedItemServiceHandler

	mu    sync.Mutex
	items map[string]*storev1.DriverItem
	now   func() time.Time

	// Gets counts the Get calls, LinearGets those with linearizable set; Transacts counts the Transact calls.
	Gets, LinearGets, Transacts atomic.Int64
	// Down, when set, makes every call fail with unavailable, reason engine.
	Down atomic.Bool
	// Delay, when set, holds every call this long, or until the caller's deadline.
	Delay atomic.Int64
}

// New returns an empty store. now may be nil.
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{items: map[string]*storev1.DriverItem{}, now: now}
}

// Client mounts the double on the in-memory transport and returns the generated client and a stop function.
func (s *Store) Client() (storev1alpha1connect.ItemServiceClient, func()) {
	path, h := storev1alpha1connect.NewItemServiceHandler(s)
	hc, stop := atoomx.Mount(path, h)
	return storev1alpha1connect.NewItemServiceClient(hc, "http://store", call.ClientOptions()...), stop
}

// Len is the number of live items.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, it := range s.items {
		if s.live(it) {
			n++
		}
	}
	return n
}

// Keys returns the live keys, sorted.
func (s *Store) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k, it := range s.items {
		if s.live(it) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Item returns a copy of the live item under key, or nil.
func (s *Store) Item(key string) *storev1.DriverItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[key]
	if !ok || !s.live(it) {
		return nil
	}
	return proto.Clone(it).(*storev1.DriverItem)
}

// SetItem writes an item directly, bypassing the contract (to test a tampered store).
func (s *Store) SetItem(it *storev1.DriverItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[string(it.GetKey())] = proto.Clone(it).(*storev1.DriverItem)
}

func (s *Store) live(it *storev1.DriverItem) bool {
	return it.GetExpiresAt() == nil || s.now().Before(it.GetExpiresAt().AsTime())
}

func (s *Store) gate(ctx context.Context) error {
	if d := time.Duration(s.Delay.Load()); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return connect.NewError(connect.CodeDeadlineExceeded, ctx.Err())
		}
	}
	if s.Down.Load() {
		return refusal.New(connect.CodeUnavailable, "engine", "")
	}
	return nil
}

func validKey(k []byte) bool {
	if len(k) == 0 || len(k) > 512 {
		return false
	}
	for _, c := range k {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// Capabilities names the double.
func (s *Store) Capabilities(context.Context, *connect.Request[storev1.CapabilitiesRequest]) (*connect.Response[storev1.CapabilitiesResponse], error) {
	return connect.NewResponse(&storev1.CapabilitiesResponse{Store: "storetest"}), nil
}

// Get reads one item; absent or expired is not_found, reason absent.
func (s *Store) Get(ctx context.Context, req *connect.Request[storev1.ItemGetRequest]) (*connect.Response[storev1.ItemGetResponse], error) {
	s.Gets.Add(1)
	if req.Msg.GetLinearizable() {
		s.LinearGets.Add(1)
	}
	if err := s.gate(ctx); err != nil {
		return nil, err
	}
	if !validKey(req.Msg.GetKey()) {
		return nil, refusal.New(connect.CodeInvalidArgument, "address", "key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[string(req.Msg.GetKey())]
	if !ok || !s.live(it) {
		return nil, refusal.New(connect.CodeNotFound, "absent", "key")
	}
	return connect.NewResponse(&storev1.ItemGetResponse{Item: proto.Clone(it).(*storev1.DriverItem)}), nil
}

// Query lists the items under a prefix, or with an index entry, in key order, paged.
func (s *Store) Query(ctx context.Context, req *connect.Request[storev1.QueryRequest]) (*connect.Response[storev1.QueryResponse], error) {
	if err := s.gate(ctx); err != nil {
		return nil, err
	}
	m := req.Msg
	size := int(m.GetPageSize())
	switch {
	case size == 0:
		size = 100
	case size < 0:
		return nil, refusal.New(connect.CodeInvalidArgument, "batch", "page_size")
	case size > 500:
		size = 500
	}
	if len(m.GetIndexValue()) > 0 && m.GetIndex() == "" {
		return nil, refusal.New(connect.CodeInvalidArgument, "index", "index")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	for k, it := range s.items {
		if !s.live(it) || !bytes.HasPrefix([]byte(k), m.GetPrefix()) || (len(m.GetPageToken()) > 0 && k <= string(m.GetPageToken())) {
			continue
		}
		if m.GetIndex() != "" && !hasEntry(it, m.GetIndex(), m.GetIndexValue()) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res := &storev1.QueryResponse{LogEpoch: 1}
	for i, k := range keys {
		if i == size {
			res.NextPageToken = []byte(keys[i-1])
			break
		}
		res.Items = append(res.Items, proto.Clone(s.items[k]).(*storev1.DriverItem))
	}
	return connect.NewResponse(res), nil
}

func hasEntry(it *storev1.DriverItem, name string, value []byte) bool {
	for _, e := range it.GetIndexes() {
		if e.GetName() == name && bytes.Equal(e.GetValue(), value) {
			return true
		}
	}
	return false
}

// Transact applies the conditions, then the deletes, then the puts, all or none.
func (s *Store) Transact(ctx context.Context, req *connect.Request[storev1.TransactRequest]) (*connect.Response[storev1.TransactResponse], error) {
	s.Transacts.Add(1)
	if err := s.gate(ctx); err != nil {
		return nil, err
	}
	m := req.Msg
	if len(m.GetConditions())+len(m.GetPuts())+len(m.GetDeletes()) > 256 {
		return nil, refusal.New(connect.CodeInvalidArgument, "batch", "")
	}
	touched := map[string]bool{}
	for i, p := range m.GetPuts() {
		if !validKey(p.GetKey()) {
			return nil, refusal.New(connect.CodeInvalidArgument, "address", fmt.Sprintf("puts[%d].key", i))
		}
		if touched[string(p.GetKey())] {
			return nil, refusal.New(connect.CodeInvalidArgument, "batch", fmt.Sprintf("puts[%d].key", i))
		}
		touched[string(p.GetKey())] = true
		if p.GetLog() {
			return nil, refusal.New(connect.CodeUnimplemented, "log", fmt.Sprintf("puts[%d].log", i))
		}
	}
	for i, d := range m.GetDeletes() {
		if !validKey(d.GetKey()) {
			return nil, refusal.New(connect.CodeInvalidArgument, "address", fmt.Sprintf("deletes[%d].key", i))
		}
		if touched[string(d.GetKey())] {
			return nil, refusal.New(connect.CodeInvalidArgument, "batch", fmt.Sprintf("deletes[%d].key", i))
		}
		touched[string(d.GetKey())] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range m.GetConditions() {
		it, ok := s.items[string(c.GetKey())]
		present := ok && s.live(it)
		switch e := c.GetExpect().(type) {
		case *storev1.Condition_Absent:
			if present {
				return nil, refusal.New(connect.CodeAborted, "version", fmt.Sprintf("conditions[%d]", i))
			}
		case *storev1.Condition_Version:
			if !present || it.GetVersion() != e.Version {
				return nil, refusal.New(connect.CodeAborted, "version", fmt.Sprintf("conditions[%d]", i))
			}
		default:
			return nil, refusal.New(connect.CodeInvalidArgument, "batch", fmt.Sprintf("conditions[%d]", i))
		}
	}
	for _, d := range m.GetDeletes() {
		delete(s.items, string(d.GetKey()))
	}
	res := &storev1.TransactResponse{}
	for _, p := range m.GetPuts() {
		var v uint64 = 1
		if old, ok := s.items[string(p.GetKey())]; ok && s.live(old) {
			v = old.GetVersion() + 1
		}
		it := &storev1.DriverItem{Key: p.GetKey(), Version: v, Value: p.GetValue(), ExpiresAt: p.GetExpiresAt(), Indexes: p.GetIndexes()}
		s.items[string(p.GetKey())] = proto.Clone(it).(*storev1.DriverItem)
		res.Items = append(res.Items, it)
	}
	return connect.NewResponse(res), nil
}
