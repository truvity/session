package core

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	storev1 "github.com/truvity/atoom/store/gen/atoom/store/v1alpha1"
)

// Errors of the store operations. Any other error is a store failure, and the check answers it with 503.
var (
	ErrNotFound  = errors.New("session: not found")
	ErrLoggedOut = errors.New("session: a logout arrived during the sign-in")
)

// Claims are the person's claims, cached at sign-in for the policy decision and whoami.
type Claims struct {
	Name     string   `json:"name,omitempty"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
}

// Record is the sealed part of a session item (design section 5.1).
type Record struct {
	Subject      string `json:"sub"`
	Issuer       string `json:"iss"`
	SID          string `json:"sid,omitempty"`
	Claims       Claims `json:"claims"`
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AccessExpiry int64  `json:"access_exp,omitempty"` // unix seconds
}

// Session is a session as the store holds it.
type Session struct {
	Record
	Created  time.Time // millisecond precision, for the tombstone comparison (decision 0010)
	LastSeen time.Time // second precision
	Expires  time.Time // the absolute end
	key      []byte
	version  uint64
}

// IdleExpires is when the session ends if it is not used.
func (s *Session) IdleExpires(idle time.Duration) time.Time { return s.LastSeen.Add(idle) }

// The readable header of a session item: a format byte, the creation in milliseconds and the last use in seconds.
const (
	headerFormat = 1
	headerLen    = 17
)

func (c *Core) mac(ctx context.Context, purpose string, parts ...string) (string, error) {
	var b []byte
	for i, p := range parts {
		if i > 0 {
			b = append(b, 0)
		}
		b = append(b, p...)
	}
	m, err := c.seal.Mac(ctx, purpose, b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(m), nil
}

func (c *Core) sessionKey(ctx context.Context, id string) ([]byte, error) {
	m, err := c.mac(ctx, PurposeSessionKey, id)
	return []byte("s/" + m), err
}

func (c *Core) lookupKey(ctx context.Context, prefix string, parts ...string) ([]byte, error) {
	m, err := c.mac(ctx, PurposeLookupKey, parts...)
	return []byte(prefix + m), err
}

func notFound(err error) bool { return connect.CodeOf(err) == connect.CodeNotFound }
func aborted(err error) bool  { return connect.CodeOf(err) == connect.CodeAborted }

func (c *Core) packSession(ctx context.Context, key []byte, created, lastSeen time.Time, r *Record) ([]byte, error) {
	plain, err := json.Marshal(r) //nolint:gosec // G117: the record holds the tokens by design, and is sealed before it is stored
	if err != nil {
		return nil, err
	}
	sealed, err := c.seal.Seal(ctx, PurposeSessionRecord, key, plain)
	if err != nil {
		return nil, err
	}
	v := make([]byte, headerLen, headerLen+len(sealed))
	v[0] = headerFormat
	binary.BigEndian.PutUint64(v[1:], uint64(created.UnixMilli()))
	binary.BigEndian.PutUint64(v[9:], uint64(lastSeen.Unix())) //nolint:gosec // G115: a time after 1970 is positive
	return append(v, sealed...), nil
}

func (c *Core) unpackSession(ctx context.Context, it *storev1.DriverItem) (*Session, error) {
	v := it.GetValue()
	if len(v) < headerLen || v[0] != headerFormat {
		return nil, errors.New("session: an item of an unknown format")
	}
	s := &Session{
		Created:  time.UnixMilli(int64(binary.BigEndian.Uint64(v[1:]))), //nolint:gosec // G115: written from a positive int64
		LastSeen: time.Unix(int64(binary.BigEndian.Uint64(v[9:])), 0),   //nolint:gosec // G115: as above
		Expires:  it.GetExpiresAt().AsTime(),
		key:      it.GetKey(),
		version:  it.GetVersion(),
	}
	plain, err := c.seal.Open(ctx, PurposeSessionRecord, it.GetKey(), v[headerLen:])
	if err != nil {
		return nil, fmt.Errorf("session: a record that does not open: %w", err)
	}
	if err := json.Unmarshal(plain, &s.Record); err != nil {
		return nil, err
	}
	return s, nil
}

// Load reads a session by its cookie id: one linearizable Get, and nothing else (decision 0006). A session past its idle or
// absolute end is ErrNotFound, whatever the store's TTL sweeper has done.
func (c *Core) Load(ctx context.Context, id string) (*Session, error) {
	if !validID(id) {
		return nil, ErrNotFound
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	key, err := c.sessionKey(ctx, id)
	if err != nil {
		return nil, err
	}
	res, err := c.items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: key, Linearizable: true}))
	if notFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s, err := c.unpackSession(ctx, res.Msg.GetItem())
	if err != nil {
		return nil, err
	}
	now := c.now()
	if !now.Before(s.Expires) || !now.Before(s.IdleExpires(c.rules.Idle)) {
		return nil, ErrNotFound
	}
	return s, nil
}

// touch refreshes the idle time when it is due, at most once per TouchEvery: a put at the version that was read (the store port
// has no partial update, so the value is written again). A lost race is not an error.
func (c *Core) touch(ctx context.Context, s *Session) {
	now := c.now()
	if now.Sub(s.LastSeen) < c.rules.TouchEvery {
		return
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	v, err := c.packSession(ctx, s.key, s.Created, now, &s.Record)
	if err == nil {
		_, err = c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
			Conditions: []*storev1.Condition{{Key: s.key, Expect: &storev1.Condition_Version{Version: s.version}}},
			Puts:       []*storev1.Put{{Key: s.key, Value: v, ExpiresAt: timestamppb.New(s.Expires)}},
		}))
	}
	if err != nil && !aborted(err) {
		c.metrics.touchFailed.Add(1)
	}
}

// pointer is the value of a pointer item: the store keys of the sessions of one sid or subject.
type pointer struct {
	Members []string `json:"m"`
}

func (c *Core) pointerKeys(ctx context.Context, r *Record) ([][]byte, error) {
	sub, err := c.lookupKey(ctx, "p/sub/", r.Issuer, r.Subject)
	if err != nil {
		return nil, err
	}
	keys := [][]byte{sub}
	if r.SID != "" {
		sid, err := c.lookupKey(ctx, "p/sid/", r.Issuer, r.SID)
		if err != nil {
			return nil, err
		}
		keys = append(keys, sid)
	}
	return keys, nil
}

// createTries bounds the retries of a session creation that lost a race on a pointer item.
const createTries = 20

// Create stores a new session under a new id and returns the id (a new id at every sign-in: no fixation). The session item and
// the pointer items of its sid and subject are written in one transaction (decision 0010). Then it reads the tombstones once:
// if a back-channel logout for the sid or the subject arrived after started, the time the sign-in began, it deletes the new
// session and returns ErrLoggedOut.
func (c *Core) Create(ctx context.Context, r *Record, started time.Time) (string, error) {
	if r.Subject == "" || r.Issuer == "" {
		return "", errors.New("session: a record without subject or issuer")
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	id := NewID()
	key, err := c.sessionKey(ctx, id)
	if err != nil {
		return "", err
	}
	now := c.now()
	expires := now.Add(c.rules.Max)
	value, err := c.packSession(ctx, key, now, now, r)
	if err != nil {
		return "", err
	}
	pks, err := c.pointerKeys(ctx, r)
	if err != nil {
		return "", err
	}
	for try := 1; ; try++ {
		req := &storev1.TransactRequest{
			Conditions: []*storev1.Condition{{Key: key, Expect: &storev1.Condition_Absent{Absent: true}}},
			Puts:       []*storev1.Put{{Key: key, Value: value, ExpiresAt: timestamppb.New(expires)}},
		}
		for _, pk := range pks {
			var p pointer
			res, err := c.items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: pk, Linearizable: true}))
			switch {
			case err == nil:
				if err := json.Unmarshal(res.Msg.GetItem().GetValue(), &p); err != nil {
					return "", fmt.Errorf("session: a pointer item that does not parse: %w", err)
				}
				req.Conditions = append(req.Conditions, &storev1.Condition{Key: pk, Expect: &storev1.Condition_Version{Version: res.Msg.GetItem().GetVersion()}})
			case notFound(err):
				req.Conditions = append(req.Conditions, &storev1.Condition{Key: pk, Expect: &storev1.Condition_Absent{Absent: true}})
			default:
				return "", err
			}
			p.Members = append(p.Members, string(key))
			pv, _ := json.Marshal(p)
			// A pointer lives as long as the newest session it lists can.
			req.Puts = append(req.Puts, &storev1.Put{Key: pk, Value: pv, ExpiresAt: timestamppb.New(expires)})
		}
		_, err := c.items.Transact(ctx, connect.NewRequest(req))
		if err == nil {
			break
		}
		if !aborted(err) || try >= createTries {
			return "", err
		}
	}
	// The race of a logout that arrives before the sign-in has finished (decision 0010): one tombstone read, at creation only.
	at, err := c.tombstoneAt(ctx, r)
	if err != nil {
		_ = c.deleteKey(ctx, key)
		return "", err
	}
	if !at.IsZero() && !at.Before(started) {
		_ = c.deleteKey(ctx, key)
		return "", ErrLoggedOut
	}
	return id, nil
}

func (c *Core) deleteKey(ctx context.Context, key []byte) error {
	_, err := c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{Deletes: []*storev1.Delete{{Key: key}}}))
	return err
}

// Delete ends a session by its cookie id (the person's own logout). Its pointer entries stay until they expire: a stale member
// costs one failed delete at a back-channel logout.
func (c *Core) Delete(ctx context.Context, id string) error {
	if !validID(id) {
		return nil
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	key, err := c.sessionKey(ctx, id)
	if err != nil {
		return err
	}
	return c.deleteKey(ctx, key)
}

func (c *Core) tombstoneKeys(ctx context.Context, iss, sid, sub string) ([][]byte, error) {
	var keys [][]byte
	if sid != "" {
		k, err := c.lookupKey(ctx, "t/sid/", iss, sid)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if sub != "" {
		k, err := c.lookupKey(ctx, "t/sub/", iss, sub)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// tombstoneAt returns the newest logout time of the record's sid and subject, or the zero time.
func (c *Core) tombstoneAt(ctx context.Context, r *Record) (time.Time, error) {
	keys, err := c.tombstoneKeys(ctx, r.Issuer, r.SID, r.Subject)
	if err != nil {
		return time.Time{}, err
	}
	var newest time.Time
	for _, k := range keys {
		res, err := c.items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: k, Linearizable: true}))
		if notFound(err) {
			continue
		}
		if err != nil {
			return time.Time{}, err
		}
		v := res.Msg.GetItem().GetValue()
		if len(v) != 8 {
			return time.Time{}, errors.New("session: a tombstone of an unknown format")
		}
		if t := time.UnixMilli(int64(binary.BigEndian.Uint64(v))); t.After(newest) { //nolint:gosec // G115: written from a positive int64
			newest = t
		}
	}
	return newest, nil
}

// LogoutBy ends the sessions of a sid, or of a subject when sid is empty (a back-channel logout, decision 0010). It writes the
// tombstone, reads the pointer item with a linearizable Get, and deletes the sessions it lists and the pointer in one
// transaction. It returns how many listed sessions it deleted (stale members included).
func (c *Core) LogoutBy(ctx context.Context, iss, sid, sub string) (int, error) {
	if iss == "" || (sid == "" && sub == "") {
		return 0, errors.New("session: a logout needs the issuer and a sid or a subject")
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	now := c.now()
	kind, val := "sid", sid
	if sid == "" {
		kind, val = "sub", sub
	}
	tk, err := c.lookupKey(ctx, "t/"+kind+"/", iss, val)
	if err != nil {
		return 0, err
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(now.UnixMilli()))
	if _, err := c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Puts: []*storev1.Put{{Key: tk, Value: b, ExpiresAt: timestamppb.New(now.Add(c.rules.Max))}}})); err != nil {
		return 0, err
	}
	pk, err := c.lookupKey(ctx, "p/"+kind+"/", iss, val)
	if err != nil {
		return 0, err
	}
	res, err := c.items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: pk, Linearizable: true}))
	if notFound(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var p pointer
	if err := json.Unmarshal(res.Msg.GetItem().GetValue(), &p); err != nil {
		return 0, fmt.Errorf("session: a pointer item that does not parse: %w", err)
	}
	members := slices.Compact(slices.Sorted(slices.Values(p.Members)))
	dels := []*storev1.Delete{{Key: pk}}
	for _, m := range members {
		dels = append(dels, &storev1.Delete{Key: []byte(m)})
	}
	// The store takes at most 256 operations in one transaction: delete in chunks, the pointer in the first.
	for start := 0; start < len(dels); start += 256 {
		end := min(start+256, len(dels))
		if _, err := c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{Deletes: dels[start:end]})); err != nil {
			return 0, err
		}
	}
	return len(members), nil
}

// ClaimOnce records a name once until the given time and says whether this call was the first (the jti of a logout token).
func (c *Core) ClaimOnce(ctx context.Context, name string, until time.Time) (bool, error) {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	k, err := c.lookupKey(ctx, "o/", name)
	if err != nil {
		return false, err
	}
	_, err = c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Conditions: []*storev1.Condition{{Key: k, Expect: &storev1.Condition_Absent{Absent: true}}},
		Puts:       []*storev1.Put{{Key: k, Value: []byte{1}, ExpiresAt: timestamppb.New(until)}}}))
	if aborted(err) {
		return false, nil
	}
	return err == nil, err
}

// SignIn is a sign-in transaction: what the callback needs, kept by state, sealed, used once.
type SignIn struct {
	Verifier    string    `json:"v"`
	Nonce       string    `json:"n"`
	ReturnTo    string    `json:"r"`
	BindingHash string    `json:"b"` // a hash of the binding cookie's value
	Started     time.Time `json:"t"`
}

// PutSignIn stores a sign-in transaction under its state for SignInLifetime.
func (c *Core) PutSignIn(ctx context.Context, state string, tx *SignIn) error {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	k, err := c.lookupKey(ctx, "x/", state)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	sealed, err := c.seal.Seal(ctx, PurposeSignInRecord, k, plain)
	if err != nil {
		return err
	}
	_, err = c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Conditions: []*storev1.Condition{{Key: k, Expect: &storev1.Condition_Absent{Absent: true}}},
		Puts:       []*storev1.Put{{Key: k, Value: sealed, ExpiresAt: timestamppb.New(c.now().Add(SignInLifetime))}}}))
	return err
}

// TakeSignIn reads and deletes a sign-in transaction: the delete is conditional on the version read, so of two callbacks with
// one state only one gets it. An unknown, expired or used state is ErrNotFound.
func (c *Core) TakeSignIn(ctx context.Context, state string) (*SignIn, error) {
	if !validID(state) {
		return nil, ErrNotFound
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	k, err := c.lookupKey(ctx, "x/", state)
	if err != nil {
		return nil, err
	}
	res, err := c.items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: k, Linearizable: true}))
	if notFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	it := res.Msg.GetItem()
	_, err = c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Conditions: []*storev1.Condition{{Key: k, Expect: &storev1.Condition_Version{Version: it.GetVersion()}}},
		Deletes:    []*storev1.Delete{{Key: k}}}))
	if aborted(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	plain, err := c.seal.Open(ctx, PurposeSignInRecord, k, it.GetValue())
	if err != nil {
		return nil, fmt.Errorf("session: a sign-in record that does not open: %w", err)
	}
	var tx SignIn
	if err := json.Unmarshal(plain, &tx); err != nil {
		return nil, err
	}
	if c.now().Sub(tx.Started) > SignInLifetime {
		return nil, ErrNotFound
	}
	return &tx, nil
}
