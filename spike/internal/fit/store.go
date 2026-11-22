package fit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/truvity/atoom/common/gen/atoom/common/v1alpha1"
	"github.com/truvity/atoom/common/refusal"
	storev1 "github.com/truvity/atoom/store/gen/atoom/store/v1alpha1"
	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"

	"github.com/truvity/session/spike/internal/sess"
)

// Store keeps sessions in an atoom store driver, called through the generated ItemService client.
// It satisfies sess.CheckStore. The value of an item is a 16-byte readable header (created in milliseconds,
// last seen in seconds) and the sealed record. The absolute lifetime is the item's expires_at.
type Store struct {
	Items    storev1alpha1connect.ItemServiceClient
	HMACKey  []byte
	DataKey  []byte
	IdleTTL  time.Duration
	MaxTTL   time.Duration
	TouchGap time.Duration
	Now      func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// KeyOf is the store key of a session id (a keyed hash of it).
func (s *Store) KeyOf(id string) string { return s.keyOf(id) }

func (s *Store) keyOf(id string) string {
	m := hmac.New(sha256.New, s.HMACKey)
	m.Write([]byte(id))
	return "S#" + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Store) seal(id string, r *sess.Record) ([]byte, error) {
	plain, _ := json.Marshal(r)
	block, _ := aes.NewCipher(s.DataKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte(id)), nil
}

func (s *Store) open(id string, blob []byte) (*sess.Record, error) {
	block, _ := aes.NewCipher(s.DataKey)
	gcm, _ := cipher.NewGCM(block)
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("short blob")
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], []byte(id))
	if err != nil {
		return nil, err
	}
	var r sess.Record
	return &r, json.Unmarshal(plain, &r)
}

func pack(createdMs, lastSeen int64, blob []byte) []byte {
	v := make([]byte, 16, 16+len(blob))
	binary.BigEndian.PutUint64(v, uint64(createdMs))
	binary.BigEndian.PutUint64(v[8:], uint64(lastSeen))
	return append(v, blob...)
}

// ---- index entries (the variant atoom makes possible) ----

const (
	IdxSid = "sid"
	IdxSub = "sub"
)

func indexes(r *sess.Record) []*commonv1.IndexEntry {
	out := []*commonv1.IndexEntry{{Name: IdxSub, Value: []byte(r.Iss + "|" + r.Sub)}}
	if r.Sid != "" {
		out = append(out, &commonv1.IndexEntry{Name: IdxSid, Value: []byte(r.Iss + "|" + r.Sid)})
	}
	return out
}

func notFound(err error) bool { return connect.CodeOf(err) == connect.CodeNotFound }

// Create writes the session as one item whose index entries are the logout lookup (no pointer items).
func (s *Store) Create(ctx context.Context, id string, r *sess.Record) error {
	now := s.now()
	r.Created = now.Unix()
	blob, err := s.seal(id, r)
	if err != nil {
		return err
	}
	k := []byte(s.keyOf(id))
	_, err = s.Items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Conditions: []*storev1.Condition{{Key: k, Expect: &storev1.Condition_Absent{Absent: true}}},
		Puts: []*storev1.Put{{Key: k, Value: pack(now.UnixMilli(), now.Unix(), blob),
			ExpiresAt: timestamppb.New(now.Add(s.MaxTTL)), Indexes: indexes(r)}},
	}))
	return err
}

// Get is the one strongly consistent read of a check. The driver already treats an item past expires_at as absent;
// the idle check is session's own, from the header.
func (s *Store) Get(ctx context.Context, id string, _ bool) (*sess.Loaded, error) {
	res, err := s.Items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: []byte(s.keyOf(id)), Linearizable: true}))
	if err != nil {
		if notFound(err) {
			return nil, sess.ErrNotFound
		}
		return nil, err
	}
	return s.finish(id, res.Msg.GetItem())
}

func (s *Store) finish(id string, it *storev1.DriverItem) (*sess.Loaded, error) {
	v := it.GetValue()
	if len(v) < 16 {
		return nil, errors.New("short value")
	}
	l := &sess.Loaded{Created: int64(binary.BigEndian.Uint64(v)), LastSeen: int64(binary.BigEndian.Uint64(v[8:])),
		Expires: it.GetExpiresAt().AsTime().Unix(), Version: it.GetVersion()}
	if l.LastSeen+int64(s.IdleTTL/time.Second) <= s.now().Unix() {
		return nil, sess.ErrNotFound
	}
	rec, err := s.open(id, v[16:])
	if err != nil {
		return nil, err
	}
	l.Rec = rec
	return l, nil
}

// Touch refreshes the idle time at most once per TouchGap: a put at the version that was read (the store port has
// no partial update, so the whole value is written again, with the index entries the item declares).
func (s *Store) Touch(ctx context.Context, id string, l *sess.Loaded) (bool, error) {
	now := s.now()
	if now.Unix()-l.LastSeen < int64(s.TouchGap/time.Second) {
		return false, nil
	}
	blob, err := s.seal(id, l.Rec)
	if err != nil {
		return false, err
	}
	k := []byte(s.keyOf(id))
	_, err = s.Items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Conditions: []*storev1.Condition{{Key: k, Expect: &storev1.Condition_Version{Version: l.Version}}},
		Puts: []*storev1.Put{{Key: k, Value: pack(l.Created*1000, now.Unix(), blob),
			ExpiresAt: timestamppb.New(time.Unix(l.Expires, 0)), Indexes: indexes(l.Rec)}},
	}))
	if connect.CodeOf(err) == connect.CodeAborted {
		return false, nil // somebody else touched it, or it is gone
	}
	return err == nil, err
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.Items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Deletes: []*storev1.Delete{{Key: []byte(s.keyOf(id))}}}))
	return err
}

// LogoutByIndex finds the sessions of a sid (or of a subject when sid is empty) by a linearizable query on the index
// entries and deletes them in one transaction. Returns how many it deleted.
func (s *Store) LogoutByIndex(ctx context.Context, iss, sid, sub string) (int, error) {
	name, val := IdxSid, iss+"|"+sid
	if sid == "" {
		name, val = IdxSub, iss+"|"+sub
	}
	var del []*storev1.Delete
	var token []byte
	for {
		res, err := s.Items.Query(ctx, connect.NewRequest(&storev1.QueryRequest{Prefix: []byte("S#"), Index: name,
			IndexValue: []byte(val), PageSize: 100, PageToken: token, Linearizable: true}))
		if err != nil {
			return 0, err
		}
		for _, it := range res.Msg.GetItems() {
			del = append(del, &storev1.Delete{Key: it.GetKey()})
		}
		if token = res.Msg.GetNextPageToken(); len(token) == 0 {
			break
		}
	}
	if len(del) == 0 {
		return 0, nil
	}
	_, err := s.Items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{Deletes: del}))
	return len(del), err
}

// ---- pointer items (record 0010 as written), for comparison ----

func ptrKey(kind, iss, v string) []byte { return []byte("P#" + kind + "#" + iss + "|" + v) }

type ptr struct {
	Members []string `json:"m"`
}

// CreateWithPointers writes the session and adds its key to the pointer items of its sid and subject, in one
// Transact: each pointer is read, then written under a condition on the version that was read. A lost race is
// `aborted`, and the whole step is read and tried again.
func (s *Store) CreateWithPointers(ctx context.Context, id string, r *sess.Record) (tries int, err error) {
	now := s.now()
	r.Created = now.Unix()
	blob, err := s.seal(id, r)
	if err != nil {
		return 0, err
	}
	k := []byte(s.keyOf(id))
	exp := timestamppb.New(now.Add(s.MaxTTL))
	pks := [][]byte{ptrKey("sub", r.Iss, r.Sub)}
	if r.Sid != "" {
		pks = append(pks, ptrKey("sid", r.Iss, r.Sid))
	}
	for tries = 1; tries <= 20; tries++ {
		req := &storev1.TransactRequest{Conditions: []*storev1.Condition{{Key: k, Expect: &storev1.Condition_Absent{Absent: true}}},
			Puts: []*storev1.Put{{Key: k, Value: pack(now.UnixMilli(), now.Unix(), blob), ExpiresAt: exp}}}
		for _, pk := range pks {
			var cur ptr
			res, gerr := s.Items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: pk, Linearizable: true}))
			switch {
			case gerr == nil:
				_ = json.Unmarshal(res.Msg.GetItem().GetValue(), &cur)
				req.Conditions = append(req.Conditions, &storev1.Condition{Key: pk, Expect: &storev1.Condition_Version{Version: res.Msg.GetItem().GetVersion()}})
			case notFound(gerr):
				req.Conditions = append(req.Conditions, &storev1.Condition{Key: pk, Expect: &storev1.Condition_Absent{Absent: true}})
			default:
				return tries, gerr
			}
			cur.Members = append(cur.Members, string(k))
			v, _ := json.Marshal(cur)
			req.Puts = append(req.Puts, &storev1.Put{Key: pk, Value: v, ExpiresAt: exp})
		}
		_, err = s.Items.Transact(ctx, connect.NewRequest(req))
		if connect.CodeOf(err) != connect.CodeAborted {
			return tries, err
		}
	}
	return tries, err
}

// LogoutByPointer reads the pointer (linearizable) and deletes the sessions it lists and the pointer.
func (s *Store) LogoutByPointer(ctx context.Context, iss, sid, sub string) (int, error) {
	pk := ptrKey("sid", iss, sid)
	if sid == "" {
		pk = ptrKey("sub", iss, sub)
	}
	res, err := s.Items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: pk, Linearizable: true}))
	if notFound(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var cur ptr
	_ = json.Unmarshal(res.Msg.GetItem().GetValue(), &cur)
	req := &storev1.TransactRequest{Deletes: []*storev1.Delete{{Key: pk}}}
	for _, m := range slices.Compact(slices.Sorted(slices.Values(cur.Members))) {
		req.Deletes = append(req.Deletes, &storev1.Delete{Key: []byte(m)})
	}
	_, err = s.Items.Transact(ctx, connect.NewRequest(req))
	return len(req.Deletes) - 1, err
}

// ---- tombstones, jti, lock ----

// PutTombstone records a logout time in milliseconds under key "X#<kind>#<iss>|<v>" for the maximum lifetime.
func (s *Store) PutTombstone(ctx context.Context, kind, iss, v string) error {
	now := s.now()
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(now.UnixMilli()))
	_, err := s.Items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{Puts: []*storev1.Put{{
		Key: []byte("X#" + kind + "#" + iss + "|" + v), Value: b, ExpiresAt: timestamppb.New(now.Add(s.MaxTTL))}}}))
	return err
}

// TombstoneAt returns the logout time in milliseconds, or 0.
func (s *Store) TombstoneAt(ctx context.Context, kind, iss, v string) (int64, error) {
	res, err := s.Items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: []byte("X#" + kind + "#" + iss + "|" + v), Linearizable: true}))
	if notFound(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(res.Msg.GetItem().GetValue())), nil
}

// ClaimJTI records a logout token id once: a replay returns false.
func (s *Store) ClaimJTI(ctx context.Context, jti string, exp time.Time) (bool, error) {
	return s.putIfAbsent(ctx, "J#"+jti, []byte{1}, exp.Add(time.Minute))
}

// Lock takes a short lock for one session and audience. The expiry of the item is the lock's end: an item past its
// expires_at is absent to a condition, so no explicit "or expired" clause is needed.
func (s *Store) Lock(ctx context.Context, name string, d time.Duration) (bool, error) {
	return s.putIfAbsent(ctx, "L#"+name, []byte{1}, s.now().Add(d))
}

func (s *Store) putIfAbsent(ctx context.Context, key string, v []byte, exp time.Time) (bool, error) {
	k := []byte(key)
	_, err := s.Items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Conditions: []*storev1.Condition{{Key: k, Expect: &storev1.Condition_Absent{Absent: true}}},
		Puts:       []*storev1.Put{{Key: k, Value: v, ExpiresAt: timestamppb.New(exp)}}}))
	if connect.CodeOf(err) == connect.CodeAborted {
		return false, nil
	}
	return err == nil, err
}

// Reason returns the refusal reason of an error from a port, "" when it has none.
func Reason(err error) string {
	r, _ := refusal.Reason(err)
	return r
}

var _ sess.CheckStore = (*Store)(nil)
