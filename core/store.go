package core

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/truvity/atoom/common/gen/atoom/common/v1alpha1"
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
	return c.loadKey(ctx, key)
}

// loadKey reads a session by its store key, as Load does.
func (c *Core) loadKey(ctx context.Context, key []byte) (*Session, error) {
	ctx, cancel := c.bound(ctx)
	defer cancel()
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
	// A session of an issuer the site no longer names is no session (decision 0034).
	if len(c.rules.Issuers) > 0 && c.rules.issuerID(s.Issuer) == "" {
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
	put, err := c.sessionPut(ctx, s.key, s.Created, now, s.Expires, &s.Record)
	if err == nil {
		_, err = c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
			Conditions: []*storev1.Condition{{Key: s.key, Expect: &storev1.Condition_Version{Version: s.version}}},
			Puts:       []*storev1.Put{put},
		}))
	}
	if err != nil && !aborted(err) {
		c.metrics.touchFailed.Add(1)
	}
}

// The index entries of a session item (decision 0031): the store finds a sid's or a subject's sessions by them, with a
// linearizable Query, at a back-channel logout. Their values are keyed hashes of the issuer and the sid or subject, never the
// values in clear.
const (
	indexSID = "sid"
	indexSub = "sub"
)

// sessionIndexes are the index entries of a record. Every put of the session item must carry them all: a put that leaves one
// out deletes it (fit spike, section 2.3.1), so the idle refresh and the write of refreshed tokens make them here too.
func (c *Core) sessionIndexes(ctx context.Context, r *Record) ([]*commonv1.IndexEntry, error) {
	sub, err := c.mac(ctx, PurposeLookupKey, r.Issuer, r.Subject)
	if err != nil {
		return nil, err
	}
	entries := []*commonv1.IndexEntry{{Name: indexSub, Value: []byte(sub)}}
	if r.SID != "" {
		sid, err := c.mac(ctx, PurposeLookupKey, r.Issuer, r.SID)
		if err != nil {
			return nil, err
		}
		entries = append(entries, &commonv1.IndexEntry{Name: indexSID, Value: []byte(sid)})
	}
	return entries, nil
}

// sessionPut is the put of a session item: the sealed record and its index entries.
func (c *Core) sessionPut(ctx context.Context, key []byte, created, lastSeen, expires time.Time, r *Record) (*storev1.Put, error) {
	v, err := c.packSession(ctx, key, created, lastSeen, r)
	if err != nil {
		return nil, err
	}
	ix, err := c.sessionIndexes(ctx, r)
	if err != nil {
		return nil, err
	}
	return &storev1.Put{Key: key, Value: v, ExpiresAt: timestamppb.New(expires), Indexes: ix}, nil
}

// Create stores a new session under a new id and returns the id (a new id at every sign-in: no fixation). The session item is
// one put with its index entries for its sid and subject (decision 0031), on the condition that the key is absent. Then it
// reads the tombstones once: if a back-channel logout for the sid or the subject arrived after started, the time the sign-in
// began, it deletes the new session and returns ErrLoggedOut.
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
	put, err := c.sessionPut(ctx, key, now, now, now.Add(c.rules.Max), r)
	if err != nil {
		return "", err
	}
	if _, err := c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Conditions: []*storev1.Condition{{Key: key, Expect: &storev1.Condition_Absent{Absent: true}}},
		Puts:       []*storev1.Put{put},
	})); err != nil {
		return "", err
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

// maxTransact is the most operations session puts in one Transact: DynamoDB's limit of 100 writes in one transaction, which
// is lower than the store contract's 256 (atoom store/dynamodb, rules.go).
const maxTransact = 100

// sessionDeletes lists the deletes that end a session: its item and, on a site with exchange routes, every item under it (the
// cached tokens and the exchange locks), found with a linearizable Query by the prefix of its key (decision 0016).
func (c *Core) sessionDeletes(ctx context.Context, key []byte) ([]*storev1.Delete, error) {
	dels := []*storev1.Delete{{Key: key}}
	if exchange, _ := c.rules.needs(); !exchange {
		return dels, nil
	}
	prefix := append(append([]byte(nil), key...), '/')
	var token []byte
	for {
		res, err := c.items.Query(ctx, connect.NewRequest(&storev1.QueryRequest{Prefix: prefix, PageSize: 100, PageToken: token, Linearizable: true}))
		if err != nil {
			return nil, err
		}
		for _, it := range res.Msg.GetItems() {
			dels = append(dels, &storev1.Delete{Key: it.GetKey()})
		}
		token = res.Msg.GetNextPageToken()
		if len(token) == 0 {
			return dels, nil
		}
	}
}

// deleteAll deletes in chunks of maxTransact, in order.
func (c *Core) deleteAll(ctx context.Context, dels []*storev1.Delete) error {
	for start := 0; start < len(dels); start += maxTransact {
		end := min(start+maxTransact, len(dels))
		if _, err := c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{Deletes: dels[start:end]})); err != nil {
			return err
		}
	}
	return nil
}

// deleteSession deletes a session by its store key, with the items under it.
func (c *Core) deleteSession(ctx context.Context, key []byte) error {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	dels, err := c.sessionDeletes(ctx, key)
	if err != nil {
		return err
	}
	return c.deleteAll(ctx, dels)
}

// Delete ends a session by its cookie id (the person's own logout), with its cached tokens. Its index entries go with it.
func (c *Core) Delete(ctx context.Context, id string) error {
	if !validID(id) {
		return nil
	}
	key, err := c.sessionKey(ctx, id)
	if err != nil {
		return err
	}
	return c.deleteSession(ctx, key)
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

// LogoutBy ends the sessions of a sid, or of a subject when sid is empty (a back-channel logout, decisions 0010 and 0031). It
// writes the tombstone, finds the sessions by their index entry with a linearizable Query, and deletes them with the items
// under their keys. It returns how many sessions it deleted.
func (c *Core) LogoutBy(ctx context.Context, iss, sid, sub string) (int, error) {
	if iss == "" || (sid == "" && sub == "") {
		return 0, errors.New("session: a logout needs the issuer and a sid or a subject")
	}
	ctx, cancel := c.bound(ctx)
	defer cancel()
	now := c.now()
	kind, index, val := "sid", indexSID, sid
	if sid == "" {
		kind, index, val = "sub", indexSub, sub
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
	v, err := c.mac(ctx, PurposeLookupKey, iss, val)
	if err != nil {
		return 0, err
	}
	var keys [][]byte
	var token []byte
	for {
		res, err := c.items.Query(ctx, connect.NewRequest(&storev1.QueryRequest{Prefix: []byte("s/"), Index: index, IndexValue: []byte(v),
			PageSize: 100, PageToken: token, Linearizable: true}))
		if err != nil {
			return 0, err
		}
		for _, it := range res.Msg.GetItems() {
			keys = append(keys, it.GetKey())
		}
		token = res.Msg.GetNextPageToken()
		if len(token) == 0 {
			break
		}
	}
	var dels []*storev1.Delete
	for _, k := range keys {
		kd, err := c.sessionDeletes(ctx, k)
		if err != nil {
			return 0, err
		}
		dels = append(dels, kd...)
	}
	// Delete in chunks that DynamoDB takes in one transaction.
	if err := c.deleteAll(ctx, dels); err != nil {
		return 0, err
	}
	return len(keys), nil
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
	// Issuer is the id of the issuer the sign-in was started at: the callback redeems the code there only (decision 0034).
	Issuer      string    `json:"i"`
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
