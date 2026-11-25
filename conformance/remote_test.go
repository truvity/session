package conformance_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/chromedp"
	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/audit"
	"github.com/truvity/session/internal/site"
)

// remoteConfig is what the remote runner is told, from the environment that `just test-remote` sets (decision 0029).
type remoteConfig struct {
	host     string // SESSION_REMOTE_HOST: the site's host, as the browser uses it (with a port when it is not 443)
	issuerID string // SESSION_REMOTE_ISSUER: the id of the site file's issuer to sign in through; the only one when empty
	issuer   string // that issuer's identifier, from the site file
	several  bool   // the site file has several issuers: the runner skips the sign-in page with ?issuer=
	siteFile string // SESSION_REMOTE_SITE_FILE: the site file the site runs; remote/site.yaml when empty
	idp      string // SESSION_REMOTE_IDP: the alias of the brokered identity provider, sent as kc_idp_hint
	hint     string // SESSION_REMOTE_HINT: the test identity, sent as login_hint and chosen at mimic's chooser
	email    string // SESSION_REMOTE_EMAIL: the e-mail address whoami must name; any when empty
	ca       string // SESSION_REMOTE_CA: a PEM file of the CA that signs the site's or the issuer's certificate
	resolve  string // SESSION_REMOTE_RESOLVE: an address the host is sent to instead of its DNS answer
	proxy    string // SESSION_REMOTE_PROXY: envoy (the default) or nginx, the host whose answers to bad paths are expected
	mimic    string // SESSION_REMOTE_MIMIC: mimic's public URL, where the session is handed over
	token    string // SESSION_REMOTE_MIMIC_TOKEN, or the file SESSION_REMOTE_MIMIC_TOKEN_FILE: a token for mimic's POST /session
	username string // SESSION_REMOTE_USERNAME and SESSION_REMOTE_PASSWORD: a person of the realm itself, at Keycloak's form
	password string
	audit    string // SESSION_REMOTE_AUDIT: a command that prints the site's audit records since SESSION_REMOTE_SINCE
}

func remoteFromEnv(t *testing.T) remoteConfig {
	t.Helper()
	c := remoteConfig{
		host: os.Getenv("SESSION_REMOTE_HOST"), issuerID: os.Getenv("SESSION_REMOTE_ISSUER"),
		siteFile: os.Getenv("SESSION_REMOTE_SITE_FILE"), idp: os.Getenv("SESSION_REMOTE_IDP"),
		hint: os.Getenv("SESSION_REMOTE_HINT"), email: os.Getenv("SESSION_REMOTE_EMAIL"), ca: os.Getenv("SESSION_REMOTE_CA"),
		resolve: os.Getenv("SESSION_REMOTE_RESOLVE"), proxy: os.Getenv("SESSION_REMOTE_PROXY"),
		mimic: strings.TrimSuffix(os.Getenv("SESSION_REMOTE_MIMIC"), "/"), token: os.Getenv("SESSION_REMOTE_MIMIC_TOKEN"),
		username: os.Getenv("SESSION_REMOTE_USERNAME"), password: os.Getenv("SESSION_REMOTE_PASSWORD"),
		audit: os.Getenv("SESSION_REMOTE_AUDIT"),
	}
	if f := os.Getenv("SESSION_REMOTE_MIMIC_TOKEN_FILE"); f != "" && c.token == "" {
		b, err := os.ReadFile(f) //nolint:gosec // G304: the file the person running the suite names
		if err != nil {
			t.Fatal(err)
		}
		c.token = strings.TrimSpace(string(b))
	}
	if c.siteFile == "" {
		c.siteFile = filepath.Join("remote", "site.yaml")
	}
	if c.proxy == "" {
		c.proxy = "envoy"
	}
	return c
}

// TestRemote runs the remote-capable scenarios against a deployed site (decision 0029). It runs only when SESSION_REMOTE_HOST
// is set: `just test-remote HOST=...`.
func TestRemote(t *testing.T) {
	c := remoteFromEnv(t)
	if c.host == "" {
		t.Skip("no deployed site: run `just test-remote HOST=...` (SESSION_REMOTE_HOST is not set)")
	}
	file, err := os.ReadFile(c.siteFile)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := site.Parse(file)
	if err != nil {
		t.Fatalf("%s: %v", c.siteFile, err)
	}
	rules, err := sf.Rules()
	if err != nil {
		t.Fatal(err)
	}
	rules = rules.WithDefaults()
	// The issuer to sign in through (decision 0034): ISSUER names it by its id; a site file of one issuer needs no ISSUER.
	var ids []string
	for _, is := range sf.Issuers {
		ids = append(ids, is.ID)
		if is.ID == c.issuerID || (c.issuerID == "" && len(sf.Issuers) == 1) {
			c.issuerID, c.issuer = is.ID, strings.TrimSuffix(is.Issuer, "/")
		}
	}
	if c.issuer == "" {
		t.Fatalf("SESSION_REMOTE_ISSUER %q: the id of one of the site file's issuers %v", c.issuerID, ids)
	}
	c.several = len(sf.Issuers) > 1
	var paths []badPath
	switch c.proxy {
	case "envoy":
		paths = envoyPaths
	case "nginx":
		paths = nginxPaths
	default:
		t.Fatalf("SESSION_REMOTE_PROXY %q: envoy or nginx", c.proxy)
	}

	client, spki := remoteClient(t, c)
	args := []string{}
	if c.resolve != "" {
		hostname, _, err := net.SplitHostPort(c.host)
		if err != nil {
			hostname = c.host
		}
		args = append(args, "--host-resolver-rules=MAP "+hostname+" "+c.resolve)
	}
	if len(spki) > 0 {
		args = append(args, "--ignore-certificate-errors-spki-list="+strings.Join(spki, ","))
	}
	browser := startBrowser(t, args...)
	origin := "https://" + c.host
	b := newTab(browser, t, origin)
	var auths atomic.Int64
	interceptSignIn(t, b, c, &auths)
	if c.mimic != "" && c.token != "" {
		handOverToMimic(t, b, c)
	}

	var seenAuths int64
	x := &target{
		origin: origin, issuer: c.issuer, cookieName: "__Host-" + rules.Site, email: c.email, idp: c.issuerID,
		ctx:  oidc.ClientContext(context.Background(), client),
		idle: rules.Idle, max: rules.Max, paths: paths,
		signIn: func(t *testing.T, b *tab) { remoteSignIn(t, b, c) },
		leftToSignIn: func(_ *testing.T, _ *tab) bool {
			n := auths.Load()
			left := n > seenAuths
			seenAuths = n
			return left
		},
		raw: func(method, path string) (answer, error) { return remoteRaw(client, origin, method, path, c.host) },
	}
	since := time.Now().UTC()
	runScenarios(t, x, b, runRemote)

	if c.audit == "" {
		t.Log("audit: not checked; a deployed site's records go to its spool, not to the runner (set SESSION_REMOTE_AUDIT)")
		return
	}
	// The command prints the site's records since the start of the run, one JSON record a line.
	cmd := exec.Command("bash", "-c", c.audit) //nolint:gosec // G204: the command the person running the suite gives
	cmd.Env = append(os.Environ(), "SESSION_REMOTE_SINCE="+since.Format(time.RFC3339))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("SESSION_REMOTE_AUDIT: %v", err)
	}
	checkRecords(t, string(out), []string{c.hint, c.email, c.username},
		[]string{audit.ActionSignIn, audit.ActionDenied, audit.ActionTokenExchange, audit.ActionLogout})
}

// remoteClient is the HTTP client of the runner (the bad paths, the issuer's discovery and keys): the system's roots and the CA
// given, the host sent to SESSION_REMOTE_RESOLVE when set, and no redirects. spki are the base64 SHA-256 hashes of the CA's keys,
// which the browser is told to accept.
func remoteClient(t *testing.T, c remoteConfig) (*http.Client, []string) {
	t.Helper()
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	var spki []string
	if c.ca != "" {
		b, err := os.ReadFile(c.ca)
		if err != nil {
			t.Fatal(err)
		}
		for rest := b; ; {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				t.Fatalf("SESSION_REMOTE_CA: %v", err)
			}
			roots.AddCert(cert)
			h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			spki = append(spki, base64.StdEncoding.EncodeToString(h[:]))
		}
		if len(spki) == 0 {
			t.Fatalf("SESSION_REMOTE_CA: no certificate in %s", c.ca)
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if c.resolve != "" {
				if h, port, err := net.SplitHostPort(addr); err == nil && (h == c.host || net.JoinHostPort(h, port) == c.host ||
					strings.HasPrefix(c.host, h+":")) {
					addr = net.JoinHostPort(c.resolve, port)
				}
			}
			return dialer.DialContext(ctx, network, addr)
		}}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, spki
}

// remoteRaw is raw over TLS to the deployed site: the path exactly as given, with the site's Host.
func remoteRaw(client *http.Client, origin, method, path, host string) (answer, error) {
	req, err := http.NewRequest(method, origin+path, nil)
	if err != nil {
		return answer{}, err
	}
	req.Host = host
	res, err := client.Do(req)
	if err != nil {
		return answer{}, err
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return answer{status: res.StatusCode, header: res.Header, body: string(body)}, nil
}

// interceptSignIn pauses every request of the tab to the issuer's authorization endpoint, counts it, and adds kc_idp_hint and
// login_hint when the runner has them, so Keycloak sends the browser straight to the brokered provider and names the test
// identity there. session's own sign-in request is left as session built it otherwise: the hints are the runner's, not the
// site's. On a site of several issuers it also adds ?issuer=<ISSUER> to the site's sign-in page, which then sends the browser on
// to that issuer's sign-in at once, as a person's click on its link would (decision 0034).
func interceptSignIn(t *testing.T, b *tab, c remoteConfig, auths *atomic.Int64) {
	t.Helper()
	endpoint := c.issuer + "/protocol/openid-connect/auth"
	page := "https://" + c.host + core.PathSignIn
	// The listener runs in the tab's reading loop and must not send a command: the pauses go to a goroutine that answers them.
	paused := make(chan *fetch.EventRequestPaused, 64)
	err := chromedp.Listen(b.ctx, func(ev any) {
		if e, ok := ev.(*fetch.EventRequestPaused); ok {
			paused <- e
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			select {
			case <-b.ctx.Done():
				return
			case e := <-paused:
				p := fetch.ContinueRequestParams{RequestID: e.RequestID}
				if u, err := url.Parse(e.Request.URL); err == nil && c.several && strings.HasPrefix(e.Request.URL, page) {
					q := u.Query()
					if q.Get("issuer") == "" {
						q.Set("issuer", c.issuerID)
					}
					u.RawQuery = q.Encode()
					p.URL = u.String()
				}
				if u, err := url.Parse(e.Request.URL); err == nil && strings.HasPrefix(e.Request.URL, endpoint) {
					auths.Add(1)
					q := u.Query()
					if c.idp != "" && q.Get("kc_idp_hint") == "" {
						q.Set("kc_idp_hint", c.idp)
					}
					if c.hint != "" && q.Get("login_hint") == "" {
						q.Set("login_hint", c.hint)
					}
					u.RawQuery = q.Encode()
					p.URL = u.String()
				}
				_, _ = chromedp.Call(b.ctx, fetch.ContinueRequest, p)
			}
		}
	}()
	patterns := []*fetch.RequestPattern{{URLPattern: endpoint + "*", RequestStage: fetch.RequestStageRequest}}
	if c.several {
		patterns = append(patterns, &fetch.RequestPattern{URLPattern: page + "*", RequestStage: fetch.RequestStageRequest})
	}
	if _, err := chromedp.Call(b.ctx, fetch.Enable, fetch.EnableParams{Patterns: patterns}); err != nil {
		t.Fatal(err)
	}
}

// handOverToMimic gives the browser a session at mimic, as a CI job does: the token posted to mimic's POST /session from a page
// of mimic's origin, so mimic's cookie lands in the tab's profile.
func handOverToMimic(t *testing.T, b *tab, c remoteConfig) {
	t.Helper()
	b.open(t, c.mimic+"/healthz")
	r := b.fetch(t, "POST", "/session", map[string]string{"Authorization": "Bearer " + c.token})
	if r.Status != http.StatusNoContent {
		t.Fatalf("mimic's POST /session: %d %s", r.Status, r.Body)
	}
}

// remoteSignIn follows the sign-in until the browser is back at the site: through Keycloak, which a kc_idp_hint sends on to
// the brokered provider, and mimic, which signs in the identity of the login_hint at once or shows its chooser. At Keycloak's
// own form it picks the provider, or signs in the realm's person when the runner has one.
func remoteSignIn(t *testing.T, b *tab, c remoteConfig) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	acted := ""
	for {
		loc := b.location(t)
		if strings.HasPrefix(loc, b.origin+"/") && !strings.HasPrefix(loc, b.origin+core.PathCallback) &&
			run(t, b, chromedp.Evaluate[string](`document.readyState`)) == "complete" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sign-in did not come back to the site; the tab is at %s", loc)
		}
		switch {
		case acted == loc:
		case strings.HasPrefix(loc, c.issuer+"/") && run(t, b, chromedp.Evaluate[bool](`!!document.getElementById("kc-form-login")`)):
			switch {
			case c.idp != "" && run(t, b, chromedp.Evaluate[bool](fmt.Sprintf(`!!document.getElementById(%q)`, "social-"+c.idp))):
				run(t, b, chromedp.Click(chromedp.ID("social-"+c.idp)))
			case c.username != "":
				// A login_hint fills the user name in; it is typed again.
				run(t, b, chromedp.Evaluate[chromedp.Void](`document.getElementById("username").value = ""`))
				run(t, b, chromedp.Steps(
					chromedp.SendKeys(chromedp.ID("username"), c.username),
					chromedp.SendKeys(chromedp.ID("password"), c.password),
					chromedp.Click(chromedp.ID("kc-login")),
				))
			default:
				t.Fatalf("Keycloak's form shows and the runner has neither IDP nor USERNAME: %s", loc)
			}
			acted = loc
		case run(t, b, chromedp.Evaluate[bool](`!!document.querySelector('form[action$="/authorize/choose"]')`)):
			if c.hint == "" {
				t.Fatalf("mimic's chooser shows: set HINT to the test identity (%s)", loc)
			}
			sel := fmt.Sprintf(`form[action$="/authorize/choose"]:has(input[name="login_hint"][value=%q]) button`, c.hint)
			if !run(t, b, chromedp.Evaluate[bool](fmt.Sprintf(`!!document.querySelector(%q)`, sel))) {
				t.Fatalf("mimic's chooser has no identity %q", c.hint)
			}
			run(t, b, chromedp.Click(chromedp.CSS(sel)))
			acted = loc
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestRemoteSiteFile says that the remote site file is valid, that its routes are the suite's, and that its lifetimes are
// short enough to wait out and long enough for the touch interval.
func TestRemoteSiteFile(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("remote", "site.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sf, err := site.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	r, err := sf.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Routes, routes) {
		t.Fatalf("the remote site file's routes are not the suite's:\n%+v\n%+v", r.Routes, routes)
	}
	r = r.WithDefaults()
	if r.Idle <= r.TouchEvery || r.Max > 5*time.Minute || r.Idle > r.Max {
		t.Fatalf("lifetimes: idle %s, max %s, touch every %s", r.Idle, r.Max, r.TouchEvery)
	}
}
