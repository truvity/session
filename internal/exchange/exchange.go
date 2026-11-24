// Package exchange is the exchange client (design section 7, decisions 0005 and 0016): the client of the issuer's token
// endpoint that the check uses for the route mode exchange. It makes the token exchange of RFC 8693 and the refresh of the
// sign-in token, both with the client's private_key_jwt assertion, and implements core.Issuer.
//
// The exchange request is the one the sluis v2 exchange actor serves (actors/exchange, checkRequest): grant_type token-exchange,
// the session's access token as subject_token of type access_token, requested_token_type access_token, and audience. No
// scope, no resource and no actor token: sluis refuses each of them.
//
// It never logs a token, and never passes the issuer's error description on: a refusal is its OAuth error code only.
package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/truvity/session/core"
)

// The registered names of RFC 8693.
//
//nolint:gosec // G101: names of the RFC, not credentials
const (
	GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccess    = "urn:ietf:params:oauth:token-type:access_token"
)

// Asserter makes the client's private_key_jwt assertion (internal/signin.Signer).
type Asserter interface {
	ClientAssertion(ctx context.Context, clientID, audience string, now time.Time) (string, error)
}

// Options configure the client.
type Options struct {
	// Issuer is the issuer's identifier: the audience of the client assertion (FAPI 2.0, decision 0015), and where the token
	// endpoint is discovered when TokenURL is empty.
	Issuer   string
	ClientID string
	Asserter Asserter
	// TokenURL is the issuer's token endpoint; empty reads it from the issuer's discovery document.
	TokenURL string
	// HTTP is the client for the token endpoint; nil is a client with a 10 s timeout. The check bounds every call with its
	// own exchange timeout as well.
	HTTP *http.Client
}

// Client is the exchange client of one site.
type Client struct {
	o Options
}

// New returns the client, reading the issuer's discovery document when no token endpoint is given.
func New(ctx context.Context, o Options) (*Client, error) {
	if o.Issuer == "" || o.ClientID == "" || o.Asserter == nil {
		return nil, errors.New("exchange: the issuer, the client id and the asserter are required")
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if o.TokenURL == "" {
		p, err := oidc.NewProvider(oidc.ClientContext(ctx, o.HTTP), o.Issuer)
		if err != nil {
			return nil, fmt.Errorf("exchange: discovery of the issuer: %w", err)
		}
		o.TokenURL = p.Endpoint().TokenURL
	}
	if o.TokenURL == "" {
		return nil, errors.New("exchange: the issuer has no token endpoint")
	}
	return &Client{o: o}, nil
}

// answer is a token endpoint's answer, success or error (RFC 6749 sections 5.1 and 5.2, RFC 8693 section 2.2).
type answer struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	RefreshToken    string `json:"refresh_token"`
	IDToken         string `json:"id_token"`
	Error           string `json:"error"`
}

// post sends a form with the client's assertion. An OAuth error answer (a 4xx with an error code) is a *core.RefusedError;
// anything else that is not a 200 with JSON is an outage.
func (c *Client) post(ctx context.Context, form url.Values) (*answer, error) {
	a, err := c.o.Asserter.ClientAssertion(ctx, c.o.ClientID, c.o.Issuer, time.Now())
	if err != nil {
		return nil, fmt.Errorf("exchange: the client assertion: %w", err)
	}
	form.Set("client_id", c.o.ClientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", a)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.o.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.o.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out answer
	jsonErr := json.Unmarshal(body, &out)
	switch {
	case res.StatusCode >= 400 && res.StatusCode < 500 && jsonErr == nil && validCode(out.Error):
		return nil, &core.RefusedError{Code: out.Error}
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("exchange: the token endpoint answered status %d", res.StatusCode)
	case jsonErr != nil:
		return nil, errors.New("exchange: the token endpoint answered something that is not JSON")
	case out.AccessToken == "":
		return nil, errors.New("exchange: the token endpoint answered without an access token")
	case !strings.EqualFold(out.TokenType, "Bearer"):
		return nil, fmt.Errorf("exchange: a token of type %q, not Bearer", out.TokenType)
	}
	return &out, nil
}

// validCode accepts an OAuth error code: 1 to 64 characters of the RFC 6749 set without the quote and the backslash (the
// code goes into an audit event).
func validCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// Exchange makes the token exchange of RFC 8693 for one audience.
func (c *Client) Exchange(ctx context.Context, subjectToken, audience string) (core.Token, error) {
	out, err := c.post(ctx, url.Values{
		"grant_type":           {GrantTokenExchange},
		"subject_token":        {subjectToken},
		"subject_token_type":   {TokenTypeAccess},
		"requested_token_type": {TokenTypeAccess},
		"audience":             {audience},
	})
	if err != nil {
		return core.Token{}, err
	}
	if out.IssuedTokenType != "" && out.IssuedTokenType != TokenTypeAccess {
		return core.Token{}, fmt.Errorf("exchange: an issued token of type %q, not an access token", out.IssuedTokenType)
	}
	return core.Token{AccessToken: out.AccessToken, ExpiresIn: seconds(out.ExpiresIn)}, nil
}

// Refresh trades the refresh token for new sign-in tokens (RFC 6749 section 6).
func (c *Client) Refresh(ctx context.Context, refreshToken string) (core.Refreshed, error) {
	out, err := c.post(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	if err != nil {
		return core.Refreshed{}, err
	}
	return core.Refreshed{Token: core.Token{AccessToken: out.AccessToken, ExpiresIn: seconds(out.ExpiresIn)},
		RefreshToken: out.RefreshToken, IDToken: out.IDToken}, nil
}

func seconds(n int64) time.Duration {
	if n <= 0 || n > int64(24*time.Hour/time.Second) {
		return 0
	}
	return time.Duration(n) * time.Second
}
