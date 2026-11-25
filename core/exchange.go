package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	storev1 "github.com/truvity/atoom/store/gen/atoom/store/v1alpha1"
)

// The route mode exchange (design section 7, decisions 0005 and 0016). For a route that names an API audience, the check puts
// a token of that audience in the allow answer. The token is cached in the store under the session, sealed, until it ends
// minus a skew; a cache miss takes a short lock in the store for the session and the audience, so parallel checks make one
// exchange; the holder refreshes the sign-in token first when it is old.

// The errors of an exchange that the check answers apart from an outage.
var (
	// errSessionEnded: the sign-in token is old and could not be refreshed, so the session was ended (decision 0005).
	errSessionEnded = errors.New("session: the sign-in token could not be refreshed")
	// errExchangeRefused: the issuer refused the exchange for this audience. The session stays.
	errExchangeRefused = errors.New("session: the issuer refused the exchange")
)

// pollEvery is how often a check that waits for another check's exchange looks at the cache again.
const pollEvery = 50 * time.Millisecond

// The kinds of the items under a session's key: a cached token and an exchange lock, one of each for each audience.
const (
	childExchanged = "e"
	childLock      = "l"
)

// exchanged is the sealed value of a cached token.
type exchanged struct {
	Token string `json:"t"`
	Ends  int64  `json:"e"` // unix milliseconds: when the token ends, minus the skew
}

// childKey is the store key of an item under the session: the session's key, the kind and a keyed hash of the audience and
// the scope (the cache key of decision 0005). The scope is empty in this version: sluis refuses a scope in an exchange.
func (c *Core) childKey(ctx context.Context, s *Session, kind, audience string) ([]byte, error) {
	m, err := c.mac(ctx, PurposeLookupKey, "audience", audience, "")
	if err != nil {
		return nil, err
	}
	return []byte(string(s.key) + "/" + kind + "/" + m), nil
}

// cached reads a cached token. A missing or ended entry is not an error.
func (c *Core) cached(ctx context.Context, key []byte) (string, bool, error) {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	res, err := c.items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: key, Linearizable: true}))
	if notFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	plain, err := c.seal.Open(ctx, PurposeExchanged, key, res.Msg.GetItem().GetValue())
	if err != nil {
		return "", false, fmt.Errorf("session: a cached token that does not open: %w", err)
	}
	var e exchanged
	if err := json.Unmarshal(plain, &e); err != nil {
		return "", false, err
	}
	if !c.now().Before(time.UnixMilli(e.Ends)) {
		return "", false, nil
	}
	return e.Token, true, nil
}

// lock takes the exchange lock of a session and an audience: a put on the condition that the key is absent, which ends on
// its own after the exchange timeout, so a check that dies holding it does not block the next one for long.
func (c *Core) lock(ctx context.Context, key []byte) (bool, uint64, error) {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	res, err := c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Conditions: []*storev1.Condition{{Key: key, Expect: &storev1.Condition_Absent{Absent: true}}},
		Puts:       []*storev1.Put{{Key: key, Value: []byte{1}, ExpiresAt: timestamppb.New(c.now().Add(c.rules.ExchangeTimeout))}},
	}))
	if aborted(err) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	var v uint64
	if items := res.Msg.GetItems(); len(items) == 1 {
		v = items[0].GetVersion()
	}
	return true, v, nil
}

// unlock releases a lock that this check holds; a lock that has ended or was taken again is left alone.
func (c *Core) unlock(key []byte, version uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), c.rules.StoreTimeout)
	defer cancel()
	_, _ = c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Conditions: []*storev1.Condition{{Key: key, Expect: &storev1.Condition_Version{Version: version}}},
		Deletes:    []*storev1.Delete{{Key: key}},
	}))
}

// tokenFor returns a token of the audience for the session: from the cache, or by an exchange under the lock. It returns
// errSessionEnded, errExchangeRefused, or another error for an outage (the check answers 503).
func (c *Core) tokenFor(ctx context.Context, s *Session, audience string) (string, error) {
	entry, err := c.childKey(ctx, s, childExchanged, audience)
	if err != nil {
		return "", err
	}
	if tok, ok, err := c.cached(ctx, entry); err != nil || ok {
		return tok, err
	}
	lockKey, err := c.childKey(ctx, s, childLock, audience)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, c.rules.ExchangeTimeout)
	defer cancel()
	for {
		held, version, err := c.lock(ctx, lockKey)
		if err != nil {
			return "", err
		}
		if held {
			defer c.unlock(lockKey, version)
			return c.exchange(ctx, s, audience, entry)
		}
		// Another check is exchanging for this session and audience: wait for its token.
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("session: waiting for the exchange of another check: %w", ctx.Err())
		case <-time.After(pollEvery):
		}
		if tok, ok, err := c.cached(ctx, entry); err != nil || ok {
			return tok, err
		}
	}
}

// exchange runs under the lock: it looks at the cache once more (another check may have just finished), refreshes the
// sign-in token when it is old, asks the issuer, and caches the answer.
func (c *Core) exchange(ctx context.Context, s *Session, audience string, entry []byte) (string, error) {
	if tok, ok, err := c.cached(ctx, entry); err != nil || ok {
		return tok, err
	}
	if err := c.freshen(ctx, s); err != nil {
		return "", err
	}
	t, err := c.issuer.Exchange(ctx, s.AccessToken, audience)
	var refused *RefusedError
	if errors.As(err, &refused) {
		c.Emit(ctx, Event{Kind: EventExchange, Subject: s.Subject, Issuer: s.Issuer, Audience: audience, Reason: refused.Code})
		return "", errExchangeRefused
	}
	if err != nil {
		return "", fmt.Errorf("session: the token exchange: %w", err)
	}
	if t.AccessToken == "" {
		return "", errors.New("session: the issuer answered an exchange without a token")
	}
	c.Emit(ctx, Event{Kind: EventExchange, Subject: s.Subject, Issuer: s.Issuer, Audience: audience})
	// A token that lives no longer than the skew is used for this request only.
	if t.ExpiresIn > c.rules.ExchangeSkew {
		ends := c.now().Add(t.ExpiresIn - c.rules.ExchangeSkew)
		if err := c.putExchanged(ctx, entry, t.AccessToken, ends); err != nil {
			c.metrics.cacheWriteFailed.Add(1)
		}
	}
	return t.AccessToken, nil
}

func (c *Core) putExchanged(ctx context.Context, key []byte, token string, ends time.Time) error {
	ctx, cancel := c.bound(ctx)
	defer cancel()
	plain, err := json.Marshal(exchanged{Token: token, Ends: ends.UnixMilli()})
	if err != nil {
		return err
	}
	sealed, err := c.seal.Seal(ctx, PurposeExchanged, key, plain)
	if err != nil {
		return err
	}
	_, err = c.items.Transact(ctx, connect.NewRequest(&storev1.TransactRequest{
		Puts: []*storev1.Put{{Key: key, Value: sealed, ExpiresAt: timestamppb.New(ends)}}}))
	return err
}

// freshen refreshes the sign-in access token when it ends within the skew (decision 0005: under the same lock). A refresh the
// issuer refuses with invalid_grant (the refresh token is no longer good), or a session without a refresh token, ends the
// session (errSessionEnded). Any other refusal (such as invalid_client, a fault of the installation, not of the person) and
// an issuer that does not answer are outages: the session stays and the check answers 503 (decision 0016).
func (c *Core) freshen(ctx context.Context, s *Session) error {
	if s.AccessExpiry == 0 || c.now().Add(c.rules.ExchangeSkew).Before(time.Unix(s.AccessExpiry, 0)) {
		return nil
	}
	end := func(reason string) error {
		c.Emit(ctx, Event{Kind: EventRefreshFailed, Subject: s.Subject, Issuer: s.Issuer, Reason: reason})
		if err := c.deleteSession(ctx, s.key); err != nil {
			return err
		}
		return errSessionEnded
	}
	if s.RefreshToken == "" {
		return end("no_refresh_token")
	}
	r, err := c.issuer.Refresh(ctx, s.RefreshToken)
	var refused *RefusedError
	if errors.As(err, &refused) && refused.Code == "invalid_grant" {
		return end(refused.Code)
	}
	if errors.As(err, &refused) {
		c.Emit(ctx, Event{Kind: EventRefreshFailed, Subject: s.Subject, Issuer: s.Issuer, Reason: refused.Code})
	}
	if err != nil {
		return fmt.Errorf("session: the refresh: %w", err)
	}
	if r.AccessToken == "" {
		return errors.New("session: the issuer answered a refresh without a token")
	}
	apply := func(rec *Record) {
		rec.AccessToken = r.AccessToken
		rec.AccessExpiry = 0
		if r.ExpiresIn > 0 {
			rec.AccessExpiry = c.now().Add(r.ExpiresIn).Unix()
		}
		if r.RefreshToken != "" {
			rec.RefreshToken = r.RefreshToken
		}
		if r.IDToken != "" {
			rec.IDToken = r.IDToken
		}
	}
	apply(&s.Record)
	return c.saveTokens(ctx, s, apply)
}

// saveTries bounds the writes of refreshed tokens that lose a race with an idle refresh.
const saveTries = 3

// saveTokens writes a session whose tokens changed, at the version that was read. A lost race (an idle refresh of another
// check) reads the session again and applies the tokens to it, so a rotated refresh token is never lost. A session that is
// gone (a logout in the meantime) is errSessionEnded.
func (c *Core) saveTokens(ctx context.Context, s *Session, apply func(*Record)) error {
	for try := 1; ; try++ {
		bctx, cancel := c.bound(ctx)
		now := c.now()
		put, err := c.sessionPut(bctx, s.key, s.Created, now, s.Expires, &s.Record)
		if err == nil {
			var res *connect.Response[storev1.TransactResponse]
			res, err = c.items.Transact(bctx, connect.NewRequest(&storev1.TransactRequest{
				Conditions: []*storev1.Condition{{Key: s.key, Expect: &storev1.Condition_Version{Version: s.version}}},
				Puts:       []*storev1.Put{put},
			}))
			if err == nil {
				if items := res.Msg.GetItems(); len(items) == 1 {
					s.version = items[0].GetVersion()
				}
				s.LastSeen = time.Unix(now.Unix(), 0)
			}
		}
		cancel()
		if err == nil || !aborted(err) || try >= saveTries {
			return err
		}
		fresh, err := c.loadKey(ctx, s.key)
		if errors.Is(err, ErrNotFound) {
			return errSessionEnded
		}
		if err != nil {
			return err
		}
		apply(&fresh.Record)
		*s = *fresh
	}
}
