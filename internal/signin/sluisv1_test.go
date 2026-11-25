package signin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/truvity/session/core"
)

// The sign-in handler against a real sluis v1 (decision 0033): the issuer with no PAR and with private_key_jwt. It runs when
// SESSION_TEST_SLUIS_V1_IMAGE names a sluis image (`just test-sluis-v1`, in a container on the host network) or
// SESSION_TEST_SLUIS_V1_BIN a sluis binary (a local run against a checkout of sluis); otherwise it is skipped. The test writes
// sluis's configuration and policy itself, because the policy carries the public key of the client assertion, which the test
// makes: one confidential client, session-docs, with token_endpoint_auth_method private_key_jwt, pkce required, the site's
// exact callback, signed-out page and back-channel logout address. No person signs in: what runs is everything session asks of
// sluis before and after the person's page.
func TestTheSignInAgainstSluisV1(t *testing.T) {
	image, bin := os.Getenv("SESSION_TEST_SLUIS_V1_IMAGE"), os.Getenv("SESSION_TEST_SLUIS_V1_BIN")
	if image == "" && bin == "" {
		t.Skip("set SESSION_TEST_SLUIS_V1_IMAGE or SESSION_TEST_SLUIS_V1_BIN (just test-sluis-v1)")
	}
	ctx := context.Background()
	keys := newTestSigners(t)
	issuerURL := startSluisV1(t, image, bin, keys)

	// The setting must match the discovery: required is refused at an issuer with no PAR.
	if _, _, err := newSignInAt(t, issuerURL, false, keys); err == nil || !strings.Contains(err.Error(), "client.par: unavailable") {
		t.Fatalf("client.par required at sluis v1: %v, want refused", err)
	}
	c, h, err := newSignInAt(t, issuerURL, true, keys)
	if err != nil {
		t.Fatalf("client.par unavailable at sluis v1: %v", err)
	}

	// The authorization request on the URL is one sluis takes: it sends the browser on to its sign-in, not back with an error.
	w := httptest.NewRecorder()
	h.Login(w, httptest.NewRequest(http.MethodGet, "https://docs.example.test"+core.PathLogin+"?return_to=/", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	authorize := w.Header().Get("Location")
	if !strings.HasPrefix(authorize, issuerURL+"/authorize?") {
		t.Fatalf("login went to %q", authorize)
	}
	noFollow := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := noFollow.Get(authorize) //nolint:noctx // a test against a local issuer
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	next := res.Header.Get("Location")
	if res.StatusCode >= 400 || strings.Contains(next, "error=") || strings.HasPrefix(next, "https://docs.example.test") {
		t.Fatalf("sluis answered the authorization request %d, to %q: want its sign-in", res.StatusCode, next)
	}
	q, _ := url.Parse(authorize)
	if _, err := c.TakeSignIn(ctx, q.Query().Get("state")); err != nil {
		t.Errorf("the transaction of the state: %v", err)
	}

	// The client assertion session signs is one sluis accepts, once (RFC 7009 answers 200 for a token it does not know).
	assertion, err := keys.client.ClientAssertion(ctx, "session-docs", issuerURL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	revoke := func() int {
		form := url.Values{"token": {"not-a-token"}, "token_type_hint": {"refresh_token"}, "client_id": {"session-docs"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}}
		res, err := noFollow.PostForm(issuerURL+"/revoke", form) //nolint:noctx // a test against a local issuer
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	if got := revoke(); got != http.StatusOK {
		t.Errorf("revoke with session's assertion: %d, want 200", got)
	}
	if got := revoke(); got < 400 {
		t.Errorf("the same assertion again: %d, want a refusal", got)
	}

	// The person's logout goes to sluis's end-session with the site's client and signed-out page.
	_, to := (&logoutSite{core: c, handler: h}).logout(t, "")
	if !strings.HasPrefix(to, issuerURL+"/end_session?") || !strings.Contains(to, "client_id=session-docs") {
		t.Errorf("logout went to %q, want sluis's end-session", to)
	}
}

// startSluisV1 writes the configuration and the policy, starts sluis on a free loopback port, and returns its issuer URL once
// its discovery answers.
func startSluisV1(t *testing.T, image, bin string, keys testSigners) string {
	t.Helper()
	jwk, err := keys.client.JWK(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	port, probes := freePort(t), freePort(t)
	issuerURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the container's user reads the files
		t.Fatal(err)
	}
	policyAt := filepath.Join(dir, "policy.yaml")
	if image != "" {
		policyAt = "/config/policy.yaml"
	}
	policy := `apiVersion: sluis.truvity.github.io/policy/v2
groups:
  all:docs:reader:
    members: [ada@example.test]
clients:
  session-docs:
    kind: confidential
    token_endpoint_auth_method: private_key_jwt
    jwks: { keys: [` + string(raw) + `] }
    pkce: required
    redirects: [https://docs.example.test/_session/callback]
    signed_out: [https://docs.example.test/]
    backchannel_logout_uri: https://docs.example.test/_session/backchannel-logout
    requires: [all:docs:reader]
`
	config := fmt.Sprintf(`apiVersion: sluis.truvity.github.io/sluis/v3
demo: true
store: memory
allowInsecure: true
issuerURL: %[1]s
publicURL: %[1]s/console
listen: {address: "127.0.0.1:%[2]d"}
probes: {address: "127.0.0.1:%[3]d"}
policy: {file: %[4]s}
`, issuerURL, port, probes, policyAt)
	for name, text := range map[string]string{"policy.yaml": policy, "sluis.yaml": config} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil { //nolint:gosec // G306: as above
			t.Fatal(err)
		}
	}
	var cmd *exec.Cmd
	if image != "" {
		name := fmt.Sprintf("session-test-sluis-%d", port)
		cmd = exec.Command("docker", "run", "--rm", "--name", name, "--network", "host", "-v", dir+":/config:ro", //nolint:gosec,noctx // the image is the recipe's pin
			image, "issuer", "--config", "/config/sluis.yaml")
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() }) //nolint:noctx,gosec // cleanup of the container this test named
	} else {
		cmd = exec.Command(bin, "issuer", "--config", filepath.Join(dir, "sluis.yaml")) //nolint:gosec,noctx // the binary the runner names
	}
	logs := &strings.Builder{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for range 120 {
		res, err := http.Get(issuerURL + "/.well-known/openid-configuration") //nolint:noctx // a test against a local issuer
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return issuerURL
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("sluis never answered its discovery:\n%s", logs.String())
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // a free port for the test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}
