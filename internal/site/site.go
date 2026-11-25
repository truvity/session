// Package site reads a site file: one YAML document per site (design section 10), decoded strictly. An unknown key, a
// duplicate key, a second document or a value the check cannot serve is refused with every problem named.
package site

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	atpolicy "github.com/truvity/atoom/policy"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/policy"
)

// File is the site file as written.
type File struct {
	Site string `yaml:"site"`
	Host string `yaml:"host"`
	// Issuers are the site's issuers, one or more (decision 0034). With one, the sign-in goes to it at once; with several, the
	// person picks one on the sign-in page.
	Issuers []Issuer `yaml:"issuers"`
	SignIn  SignIn   `yaml:"signin"`
	Session Session  `yaml:"session"`
	Policy  *Policy  `yaml:"policy"`
	// ErrorPage names a document of the source port: the HTML page a navigation gets when the issuer refuses the exchange of
	// its route. Empty is the built-in page.
	ErrorPage string  `yaml:"error_page"`
	Routes    []Route `yaml:"routes"`

	// The keys of one issuer before decision 0034, decoded only to name the move when a file still has them.
	OldIssuer any `yaml:"issuer"`
	OldClient any `yaml:"client"`
	OldScopes any `yaml:"scopes"`
}

// Issuer is one issuer of the site and the site's client at it.
type Issuer struct {
	// ID names the issuer in the site: ?issuer=<id> of the sign-in paths, and the remembered choice. 1 to 32 lower-case letters,
	// digits and '-'.
	ID string `yaml:"id"`
	// Label is what the sign-in page shows: "Sign in with <label>".
	Label string `yaml:"label"`
	// Issuer is the issuer identifier, an https URL; its discovery document is <issuer>/.well-known/openid-configuration.
	Issuer string   `yaml:"issuer"`
	Client Client   `yaml:"client"`
	Scopes []string `yaml:"scopes"`
}

// SignIn holds the settings of the sign-in page.
type SignIn struct {
	// RememberChoice, when set, keeps the issuer a person signed in with in a cookie for that long, and the next sign-in that
	// names no issuer goes to it without the page. Unset (the default) remembers nothing.
	RememberChoice string `yaml:"remember_choice"`
}

// Client is the site's client at the issuer. Its key is the key port's purpose client-assertion; which key driver holds it is a
// start-up setting, not part of the site file (design section 10).
type Client struct {
	ID   string `yaml:"id"`
	Auth string `yaml:"auth"`
}

// Session holds the lifetimes.
type Session struct {
	Idle string `yaml:"idle"`
	Max  string `yaml:"max"`
}

// Policy names the policy bundle, a document of the source port, and the one key that verifies it. Without it the route table
// decides alone.
type Policy struct {
	Bundle    string    `yaml:"bundle"`
	VerifyKey VerifyKey `yaml:"verify_key"`
}

// VerifyKey is the publisher's key the site pins (atoom record 0019): the kid its signature names, and the P-384 public key as
// PEM (PUBLIC KEY). A key is pinned here and never by a document.
type VerifyKey struct {
	KID       string `yaml:"kid"`
	PublicKey string `yaml:"public_key"`
}

// Publisher is the pinned key for the policy loader.
func (p *Policy) Publisher() (atpolicy.Publisher, error) {
	return policy.PublisherFromPEM(p.VerifyKey.KID, p.VerifyKey.PublicKey)
}

// Route is one row of the route table.
type Route struct {
	Name            string `yaml:"name"`
	Match           Match  `yaml:"match"`
	Mode            string `yaml:"mode"`
	Unauthenticated string `yaml:"unauthenticated"`
	// Audience is the API audience of mode exchange, and the aud of the identity header of mode identity-header.
	Audience string `yaml:"audience"`
}

// Match is a route's path match: one of prefix and exact.
type Match struct {
	Prefix string `yaml:"prefix"`
	Exact  string `yaml:"exact"`
}

// Parse decodes and checks a site file.
func Parse(b []byte) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("site file: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("site file: one YAML document only")
	}
	if _, err := f.Rules(); err != nil {
		return nil, err
	}
	return &f, nil
}

func duration(name, s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s %q: a positive duration such as 30m or 8h", name, s)
	}
	return d, nil
}

// Remember is the lifetime of the remembered choice of issuer; 0 remembers nothing.
func (f *File) Remember() time.Duration {
	d, err := duration("signin.remember_choice", f.SignIn.RememberChoice, 0)
	if err != nil {
		return 0
	}
	return d
}

// checkIssuers checks the issuers: one or more, each id and issuer identifier once, each with its label, client and scopes.
func (f *File) checkIssuers() []error {
	var errs []error
	if f.OldIssuer != nil || f.OldClient != nil || f.OldScopes != nil {
		errs = append(errs, errors.New("issuer, client and scopes: moved into an entry of issuers (decision 0034)"))
	}
	if len(f.Issuers) == 0 {
		errs = append(errs, errors.New("issuers: at least one issuer"))
	}
	ids, urls := map[string]bool{}, map[string]bool{}
	for i, is := range f.Issuers {
		at := fmt.Sprintf("issuers[%d]", i)
		if !core.ValidSiteName(is.ID) {
			errs = append(errs, fmt.Errorf("%s.id %q: 1 to 32 lower-case letters, digits and '-'", at, is.ID))
		}
		if ids[is.ID] {
			errs = append(errs, fmt.Errorf("%s.id %q: used twice", at, is.ID))
		}
		ids[is.ID] = true
		if strings.TrimSpace(is.Label) == "" || len(is.Label) > 64 {
			errs = append(errs, fmt.Errorf("%s.label: the name the sign-in page shows, at most 64 characters", at))
		}
		if u, err := url.Parse(is.Issuer); err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			// An issuer on plain HTTP is accepted only on the loopback, for tests against a local Keycloak.
			if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
				errs = append(errs, fmt.Errorf("%s.issuer %q: an https URL", at, is.Issuer))
			}
		}
		if urls[is.Issuer] {
			errs = append(errs, fmt.Errorf("%s.issuer %q: used twice", at, is.Issuer))
		}
		urls[is.Issuer] = true
		if is.Client.ID == "" {
			errs = append(errs, fmt.Errorf("%s.client.id: required", at))
		}
		if is.Client.Auth != "private_key_jwt" {
			errs = append(errs, fmt.Errorf("%s.client.auth %q: private_key_jwt (S3)", at, is.Client.Auth))
		}
		if !slices.Contains(is.Scopes, "openid") {
			errs = append(errs, fmt.Errorf("%s.scopes: must include openid", at))
		}
	}
	return errs
}

// Rules turns the file into the core's rules, and checks what the core does not: the issuers, their clients and scopes.
func (f *File) Rules() (core.Rules, error) {
	var errs []error
	idle, err := duration("session.idle", f.Session.Idle, core.DefaultIdle)
	errs = append(errs, err)
	maxLife, err := duration("session.max", f.Session.Max, core.DefaultMax)
	errs = append(errs, err)
	_, err = duration("signin.remember_choice", f.SignIn.RememberChoice, 0)
	errs = append(errs, err)
	errs = append(errs, f.checkIssuers()...)
	if f.Policy != nil && f.Policy.Bundle == "" {
		errs = append(errs, errors.New("policy.bundle: the name of the bundle document"))
	}
	if f.Policy != nil {
		if _, err := f.Policy.Publisher(); err != nil {
			errs = append(errs, fmt.Errorf("policy.verify_key: a kid and a P-384 public key (PEM): %w", err))
		}
	}
	if f.ErrorPage != "" && (f.ErrorPage == "site" || (f.Policy != nil && f.ErrorPage == f.Policy.Bundle)) {
		errs = append(errs, fmt.Errorf("error_page %q: a document of its own", f.ErrorPage))
	}
	r := core.Rules{Site: f.Site, Host: f.Host, Idle: idle, Max: maxLife}
	for _, is := range f.Issuers {
		r.Issuers = append(r.Issuers, core.SiteIssuer{ID: is.ID, Identifier: is.Issuer})
	}
	for _, rt := range f.Routes {
		r.Routes = append(r.Routes, core.Route{Name: rt.Name, Prefix: rt.Match.Prefix, Exact: rt.Match.Exact,
			Mode: core.Mode(rt.Mode), Unauthenticated: core.Unauthenticated(rt.Unauthenticated), Audience: rt.Audience})
	}
	full := r.WithDefaults()
	if err := full.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return core.Rules{}, fmt.Errorf("site file: %w", err)
	}
	return r, nil
}
