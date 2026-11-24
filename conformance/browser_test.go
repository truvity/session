package conformance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"

	"github.com/truvity/session/internal/kctest"
)

// startBrowser runs the headless browser (Chromium's headless shell, pinned by digest in the Justfile) in a container on the
// host network, and returns a chromedp context attached to it. The browser maps the site's name to the loopback and accepts
// the TLS front's test certificate. The container is removed at the end of the test.
func startBrowser(t *testing.T) context.Context {
	t.Helper()
	image := os.Getenv("SESSION_TEST_BROWSER_IMAGE")
	if image == "" {
		t.Skip("no browser: run `just test-conformance` (SESSION_TEST_BROWSER_IMAGE is not set)")
	}
	port := freePort(t)
	name := fmt.Sprintf("session-conformance-browser-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--network", "host", //nolint:gosec // G204: the suite's own image
		"--entrypoint", "/headless-shell/headless-shell", image,
		"--no-sandbox", "--use-gl=angle", "--use-angle=swiftshader",
		"--remote-debugging-address=127.0.0.1", fmt.Sprintf("--remote-debugging-port=%d", port),
		"--host-resolver-rules=MAP "+siteName+" 127.0.0.1", "--ignore-certificate-errors", "about:blank").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "30", name).CombinedOutput() //nolint:gosec // G204: as above
			t.Logf("browser logs:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run() //nolint:gosec // G204: as above
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := http.Get(base + "/json/version")
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the browser did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}
	alloc, cancelAlloc := remote.NewAllocator(context.Background(), base)
	t.Cleanup(cancelAlloc)
	ctx, cancel := chromedp.NewContext(alloc)
	t.Cleanup(cancel)
	if err := chromedp.Do(ctx); err != nil {
		t.Fatalf("attach to the browser: %v", err)
	}
	return ctx
}

// tab is one browser profile of its own (a new browser context: no cookies of another host's run) with one tab, at one site.
type tab struct {
	t      *testing.T
	ctx    context.Context
	origin string
}

func newTab(browser context.Context, t *testing.T, origin string) *tab {
	t.Helper()
	ctx, cancel := chromedp.NewContext(browser, chromedp.WithNewBrowserContext())
	t.Cleanup(cancel)
	if err := chromedp.Do(ctx); err != nil {
		t.Fatalf("new tab: %v", err)
	}
	return &tab{t: t, ctx: ctx, origin: origin}
}

func (b *tab) timeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(b.ctx, 30*time.Second)
}

// open navigates the tab, follows the redirects as a browser does, and returns the status of the page it lands on.
func (b *tab) open(t *testing.T, u string) int64 {
	t.Helper()
	ctx, cancel := b.timeout()
	defer cancel()
	res, err := chromedp.Run(ctx, chromedp.NavigateResponse(u))
	if err != nil {
		t.Fatalf("open %s: %v", u, err)
	}
	return res.Status
}

func run[T any](t *testing.T, b *tab, a chromedp.Action[T]) T {
	t.Helper()
	ctx, cancel := b.timeout()
	defer cancel()
	v, err := chromedp.Run(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (b *tab) location(t *testing.T) string {
	t.Helper()
	return run(t, b, chromedp.Location())
}

// text is the page's text: the site's JSON, which the browser shows as text.
func (b *tab) text(t *testing.T) string {
	t.Helper()
	return run(t, b, chromedp.Evaluate[string](`document.body ? document.body.innerText : ""`))
}

// fetched is the answer to a fetch from the page.
type fetched struct {
	Status int    `json:"status"`
	Type   string `json:"type"`
	Body   string `json:"body"`
}

// fetch sends a request with the page's fetch(), as the site's own scripts and the browser helper do: same origin, the
// browser's cookies, Origin and Sec-Fetch-* set by the browser, not by the test.
func (b *tab) fetch(t *testing.T, method, path string, h map[string]string) fetched {
	t.Helper()
	if h == nil {
		h = map[string]string{}
	}
	m, _ := json.Marshal(method)
	p, _ := json.Marshal(path)
	hs, _ := json.Marshal(h)
	js := fmt.Sprintf(`(async () => {
		const r = await fetch(%s, {method: %s, headers: %s});
		return {status: r.status, type: r.headers.get("content-type") || "", body: await r.text()};
	})()`, p, m, hs)
	return run(t, b, chromedp.Evaluate[fetched](js, chromedp.EvalAwaitPromise))
}

// cookie returns the browser's cookie of that name for the site, or nil.
func (b *tab) cookie(t *testing.T, name string) *network.Cookie {
	t.Helper()
	ctx, cancel := b.timeout()
	defer cancel()
	res, err := chromedp.Call(ctx, network.GetCookies, network.GetCookiesParams{URLs: []string{b.origin + "/"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// waitFor polls the page until cond holds, for at most 20 seconds.
func (b *tab) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %s; the tab is at %s", what, b.location(t))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// atLoginForm says whether the tab shows Keycloak's login form of the realm.
func (b *tab) atLoginForm(t *testing.T, issuer string) bool {
	t.Helper()
	if !strings.HasPrefix(b.location(t), issuer+"/") {
		return false
	}
	return run(t, b, chromedp.Evaluate[bool](`!!document.getElementById("kc-form-login")`))
}

// signIn plays the person at Keycloak's login form, which the tab shows, and waits until the browser is back at the site.
func (b *tab) signIn(t *testing.T, issuer string, p kctest.Person) {
	t.Helper()
	b.waitFor(t, "Keycloak's login form", func() bool { return b.atLoginForm(t, issuer) })
	run(t, b, chromedp.Steps(
		chromedp.SendKeys(chromedp.ID("username"), p.Username),
		chromedp.SendKeys(chromedp.ID("password"), p.Password),
		chromedp.Click(chromedp.ID("kc-login")),
	))
	b.waitFor(t, "the return to the site", func() bool {
		return strings.HasPrefix(b.location(t), b.origin+"/") &&
			run(t, b, chromedp.Evaluate[string](`document.readyState`)) == "complete"
	})
}
