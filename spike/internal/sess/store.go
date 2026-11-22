// Package sess is throwaway spike code: a session store on DynamoDB, the
// check core, the sign-in handlers and the adapters. Not production quality.
package sess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var ErrNotFound = errors.New("session not found")

// Record is the plaintext of a session. It is stored encrypted.
type Record struct {
	Sub          string   `json:"sub"`
	Iss          string   `json:"iss"`
	Sid          string   `json:"sid"`
	Email        string   `json:"email"`
	Name         string   `json:"name"`
	Groups       []string `json:"groups"`
	IDToken      string   `json:"id_token"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	AccessExp    int64    `json:"access_exp"`
	Created      int64    `json:"created"`
}

// Tx is the sign-in transaction kept between /login and /callback.
type Tx struct {
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
	ReturnTo string `json:"return_to"`
	BindHash string `json:"bind_hash"`
}

type Store struct {
	DB       *dynamodb.Client
	Table    string
	HMACKey  []byte // keyed hash of the cookie id -> store key
	DataKey  []byte // AES-256 key for record encryption
	Consist  bool   // strongly consistent reads
	IdleTTL  time.Duration
	MaxTTL   time.Duration
	Now      func() time.Time
	TouchGap time.Duration // idle refresh at most this often
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) keyOf(id string) string {
	m := hmac.New(sha256.New, s.HMACKey)
	m.Write([]byte(id))
	return "S#" + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func NewID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) seal(id string, r *Record) ([]byte, error) {
	plain, _ := json.Marshal(r)
	block, _ := aes.NewCipher(s.DataKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte(id)), nil
}

func (s *Store) open(id string, blob []byte) (*Record, error) {
	block, _ := aes.NewCipher(s.DataKey)
	gcm, _ := cipher.NewGCM(block)
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("short blob")
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], []byte(id))
	if err != nil {
		return nil, err
	}
	var r Record
	return &r, json.Unmarshal(plain, &r)
}

func n(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}
func str(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

// EnsureTable creates the table with the two secondary indexes and TTL.
func EnsureTable(ctx context.Context, db *dynamodb.Client, table string) error {
	if _, err := db.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &table}); err == nil {
		return nil
	}
	gsi := func(name, attr string) types.GlobalSecondaryIndex {
		return types.GlobalSecondaryIndex{
			IndexName:  aws.String(name),
			KeySchema:  []types.KeySchemaElement{{AttributeName: aws.String(attr), KeyType: types.KeyTypeHash}},
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeKeysOnly},
		}
	}
	_, err := db.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   &table,
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("sidk"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("subk"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema:              []types.KeySchemaElement{{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash}},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{gsi("by_sid", "sidk"), gsi("by_sub", "subk")},
	})
	if err != nil {
		return err
	}
	_, err = db.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName:               &table,
		TimeToLiveSpecification: &types.TimeToLiveSpecification{AttributeName: aws.String("ttl"), Enabled: aws.Bool(true)},
	})
	return err
}

// ---- sign-in transactions ----

func (s *Store) PutTx(ctx context.Context, state string, tx Tx) error {
	b, _ := json.Marshal(tx)
	_, err := s.DB.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.Table, Item: map[string]types.AttributeValue{
		"pk": str("T#" + state), "blob": &types.AttributeValueMemberB{Value: b}, "ttl": n(s.now().Add(10 * time.Minute).Unix()),
	}, ConditionExpression: aws.String("attribute_not_exists(pk)")})
	return err
}

// TakeTx loads and deletes in one call: a transaction is used once.
func (s *Store) TakeTx(ctx context.Context, state string) (*Tx, error) {
	out, err := s.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str("T#" + state)},
		ReturnValues: types.ReturnValueAllOld})
	if err != nil {
		return nil, err
	}
	b, ok := out.Attributes["blob"].(*types.AttributeValueMemberB)
	if !ok {
		return nil, ErrNotFound
	}
	var tx Tx
	if err := json.Unmarshal(b.Value, &tx); err != nil {
		return nil, err
	}
	if t, ok := out.Attributes["ttl"].(*types.AttributeValueMemberN); ok {
		if v, _ := strconv.ParseInt(t.Value, 10, 64); v < s.now().Unix() {
			return nil, ErrNotFound
		}
	}
	return &tx, nil
}

// ---- sessions ----

func (s *Store) Create(ctx context.Context, id string, r *Record) error {
	now := s.now().Unix()
	r.Created = now
	nowMs := s.now().UnixMilli()
	blob, err := s.seal(id, r)
	if err != nil {
		return err
	}
	item := map[string]types.AttributeValue{
		"pk": str(s.keyOf(id)), "blob": &types.AttributeValueMemberB{Value: blob},
		"created": n(nowMs), "last_seen": n(now),
		"expires": n(now + int64(s.MaxTTL/time.Second)),
		"ttl":     n(now + int64(s.MaxTTL/time.Second) + 3600),
	}
	if r.Sid != "" {
		item["sidk"] = str(r.Iss + "|" + r.Sid)
	}
	item["subk"] = str(r.Iss + "|" + r.Sub)
	_, err = s.DB.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.Table, Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)")})
	return err
}

type Loaded struct {
	Rec      *Record
	Created  int64
	LastSeen int64
	Expires  int64
	// Set by stores whose items carry a version (the fit spike's atoom-backed store).
	Version uint64
}

// Get loads a session and applies the explicit expiry checks (TTL deletion is lazy)
// and the tombstone check (design Q2 option B). One BatchGetItem round trip reads
// the session and both tombstones, strongly consistent when s.Consist is set.
func (s *Store) Get(ctx context.Context, id string, withTombstones bool) (*Loaded, error) {
	key := s.keyOf(id)
	var item map[string]types.AttributeValue
	if !withTombstones {
		out, err := s.DB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str(key)}, ConsistentRead: &s.Consist})
		if err != nil {
			return nil, err
		}
		item = out.Item
	} else {
		// The tombstone keys come from the session record, so this is two sequential
		// round trips: GetItem, then BatchGetItem of the tombstones.
		return s.getWithTombstones(ctx, id, key)
	}
	return s.finish(id, item)
}

func (s *Store) finish(id string, item map[string]types.AttributeValue) (*Loaded, error) {
	if item == nil {
		return nil, ErrNotFound
	}
	l := &Loaded{}
	l.Created = num(item["created"])
	l.LastSeen = num(item["last_seen"])
	l.Expires = num(item["expires"])
	now := s.now().Unix()
	if l.Expires <= now || l.LastSeen+int64(s.IdleTTL/time.Second) <= now {
		return nil, ErrNotFound
	}
	b, ok := item["blob"].(*types.AttributeValueMemberB)
	if !ok {
		return nil, ErrNotFound
	}
	rec, err := s.open(id, b.Value)
	if err != nil {
		return nil, err
	}
	l.Rec = rec
	return l, nil
}

func num(v types.AttributeValue) int64 {
	if x, ok := v.(*types.AttributeValueMemberN); ok {
		i, _ := strconv.ParseInt(x.Value, 10, 64)
		return i
	}
	return 0
}

// Touch refreshes the idle time, at most once per TouchGap: a conditional update.
func (s *Store) Touch(ctx context.Context, id string, l *Loaded) (bool, error) {
	now := s.now().Unix()
	if now-l.LastSeen < int64(s.TouchGap/time.Second) {
		return false, nil
	}
	_, err := s.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str(s.keyOf(id))},
		UpdateExpression:          aws.String("SET last_seen = :now"),
		ConditionExpression:       aws.String("attribute_exists(pk) AND last_seen < :gap"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": n(now), ":gap": n(now - int64(s.TouchGap/time.Second) + 1)},
	})
	var ccf *types.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return false, nil // somebody else touched it, or it is gone
	}
	return err == nil, err
}

// Update replaces the record (for example after a token refresh), keeping the item.
func (s *Store) Update(ctx context.Context, id string, r *Record) error {
	blob, err := s.seal(id, r)
	if err != nil {
		return err
	}
	_, err = s.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str(s.keyOf(id))},
		UpdateExpression:          aws.String("SET blob = :b"),
		ConditionExpression:       aws.String("attribute_exists(pk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":b": &types.AttributeValueMemberB{Value: blob}},
	})
	return err
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str(s.keyOf(id))}})
	return err
}

// ---- back-channel logout: lookup by index, tombstones ----

func tombSid(iss, sid string) string { return "X#sid#" + iss + "|" + sid }
func tombSub(iss, sub string) string { return "X#sub#" + iss + "|" + sub }

// TombstoneTTL: how long a tombstone is kept. The race it closes is index lag, so a short
// time would do; the spike keeps it equal to the maximum session lifetime for the test.
func (s *Store) PutTombstones(ctx context.Context, iss, sid, sub string) error {
	now := s.now().Unix()
	put := func(pk string) error {
		_, err := s.DB.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.Table, Item: map[string]types.AttributeValue{
			"pk": str(pk), "logout_at": n(s.now().UnixMilli()), "ttl": n(now + int64(s.MaxTTL/time.Second)),
		}})
		return err
	}
	if sid != "" {
		if err := put(tombSid(iss, sid)); err != nil {
			return err
		}
	}
	if sub != "" && sid == "" {
		return put(tombSub(iss, sub))
	}
	return nil
}

// DeleteByIndex finds sessions through the secondary index (eventually consistent in
// real DynamoDB, synchronous in DynamoDB Local) and deletes them.
func (s *Store) DeleteByIndex(ctx context.Context, iss, sid, sub string) (int, error) {
	index, attr, val := "by_sid", "sidk", iss+"|"+sid
	if sid == "" {
		index, attr, val = "by_sub", "subk", iss+"|"+sub
	}
	out, err := s.DB.Query(ctx, &dynamodb.QueryInput{TableName: &s.Table, IndexName: &index,
		KeyConditionExpression:    aws.String("#a = :v"),
		ExpressionAttributeNames:  map[string]string{"#a": attr},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": str(val)}})
	if err != nil {
		return 0, err
	}
	for _, it := range out.Items {
		if _, err := s.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": it["pk"]}}); err != nil {
			return 0, err
		}
	}
	return len(out.Items), nil
}

// getWithTombstones reads the session, then both tombstones in a single BatchGetItem
// (strongly consistent). A session whose creation is not newer than a tombstone is refused.
func (s *Store) getWithTombstones(ctx context.Context, id, key string) (*Loaded, error) {
	out, err := s.DB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str(key)}, ConsistentRead: &s.Consist})
	if err != nil {
		return nil, err
	}
	l, err := s.finish(id, out.Item)
	if err != nil {
		return nil, err
	}
	keys := []map[string]types.AttributeValue{{"pk": str(tombSub(l.Rec.Iss, l.Rec.Sub))}}
	if l.Rec.Sid != "" {
		keys = append(keys, map[string]types.AttributeValue{"pk": str(tombSid(l.Rec.Iss, l.Rec.Sid))})
	}
	b, err := s.DB.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: map[string]types.KeysAndAttributes{
		s.Table: {Keys: keys, ConsistentRead: &s.Consist}}})
	if err != nil {
		return nil, err
	}
	for _, t := range b.Responses[s.Table] {
		if num(t["logout_at"]) >= l.Created {
			_ = s.Delete(ctx, id)
			return nil, ErrNotFound
		}
	}
	return l, nil
}

// ClaimJTI records a logout token id once: a replay fails.
func (s *Store) ClaimJTI(ctx context.Context, jti string, exp time.Time) (bool, error) {
	_, err := s.DB.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.Table, Item: map[string]types.AttributeValue{
		"pk": str("J#" + jti), "ttl": n(exp.Unix() + 60)}, ConditionExpression: aws.String("attribute_not_exists(pk)")})
	var ccf *types.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return false, nil
	}
	return err == nil, err
}

// Lock takes a short lock for one session and audience (exchange single flight).
func (s *Store) Lock(ctx context.Context, name string, d time.Duration) (bool, error) {
	now := s.now().Unix()
	_, err := s.DB.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.Table, Item: map[string]types.AttributeValue{
		"pk": str("L#" + name), "until": n(now + int64(d/time.Second)), "ttl": n(now + 3600)},
		ConditionExpression:       aws.String("attribute_not_exists(pk) OR #u < :now"),
		ExpressionAttributeNames:  map[string]string{"#u": "until"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": n(now)}})
	var ccf *types.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return false, nil
	}
	return err == nil, err
}

var _ = fmt.Sprintf
