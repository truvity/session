package sess

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Option C of design Q2, spike variant: no secondary index. A pointer item per sid and per
// subject holds the set of session store keys, and is written in the same transaction as the
// session. The logout reads the pointer with a strongly consistent GetItem, so it cannot miss a
// session that was committed before it. Only one race is left: a logout that arrives BEFORE the
// sign-in finished. That is closed by a tombstone read once, at session creation, not on each check.

func ptrSid(iss, sid string) string { return "P#sid#" + iss + "|" + sid }
func ptrSub(iss, sub string) string { return "P#sub#" + iss + "|" + sub }

// CreateWithPointers writes the session and its pointers in one transaction.
func (s *Store) CreateWithPointers(ctx context.Context, id string, r *Record) error {
	now := s.now().Unix()
	r.Created = now
	blob, err := s.seal(id, r)
	if err != nil {
		return err
	}
	key := s.keyOf(id)
	ttl := n(now + int64(s.MaxTTL/1e9) + 3600)
	item := map[string]types.AttributeValue{
		"pk": str(key), "blob": &types.AttributeValueMemberB{Value: blob}, "created": n(s.now().UnixMilli()), "last_seen": n(now),
		"expires": n(now + int64(s.MaxTTL/1e9)), "ttl": ttl,
	}
	add := func(pk string) types.TransactWriteItem {
		return types.TransactWriteItem{Update: &types.Update{TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str(pk)},
			UpdateExpression:          aws.String("ADD members :k SET #t = :ttl"),
			ExpressionAttributeNames:  map[string]string{"#t": "ttl"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":k": &types.AttributeValueMemberSS{Value: []string{key}}, ":ttl": ttl}}}
	}
	items := []types.TransactWriteItem{
		{Put: &types.Put{TableName: &s.Table, Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)")}},
		add(ptrSub(r.Iss, r.Sub)),
	}
	if r.Sid != "" {
		items = append(items, add(ptrSid(r.Iss, r.Sid)))
	}
	_, err = s.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	return err
}

// DeleteByPointer finds sessions with a strongly consistent GetItem and deletes them and the pointer.
func (s *Store) DeleteByPointer(ctx context.Context, iss, sid, sub string) (int, error) {
	pk := ptrSid(iss, sid)
	if sid == "" {
		pk = ptrSub(iss, sub)
	}
	out, err := s.DB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str(pk)}, ConsistentRead: aws.Bool(true)})
	if err != nil {
		return 0, err
	}
	ss, ok := out.Item["members"].(*types.AttributeValueMemberSS)
	if !ok {
		return 0, nil
	}
	for _, k := range ss.Value {
		if _, err := s.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str(k)}}); err != nil {
			return 0, err
		}
	}
	_, err = s.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.Table, Key: map[string]types.AttributeValue{"pk": str(pk)}})
	return len(ss.Value), err
}

// SignedOutSince reports whether a tombstone for this sid or subject is newer than sinceMs.
// Called once at session creation (the callback), never on each check.
func (s *Store) SignedOutSince(ctx context.Context, iss, sid, sub string, sinceMs int64) (bool, error) {
	keys := []map[string]types.AttributeValue{{"pk": str(tombSub(iss, sub))}}
	if sid != "" {
		keys = append(keys, map[string]types.AttributeValue{"pk": str(tombSid(iss, sid))})
	}
	b, err := s.DB.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: map[string]types.KeysAndAttributes{
		s.Table: {Keys: keys, ConsistentRead: aws.Bool(true)}}})
	if err != nil {
		return false, err
	}
	for _, t := range b.Responses[s.Table] {
		if num(t["logout_at"]) >= sinceMs {
			return true, nil
		}
	}
	return false, nil
}

var _ = errors.New
