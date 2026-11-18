// e2e is a scripted "browser": it signs in through Envoy and Keycloak, then runs the proxy checks.
// Usage: e2e signin <siteBase> <cookiefile>
//
//	e2e checks <label> <base> <cookiefile>
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type jar map[string]string

func (j jar) header() string {
	var p []string
	for k, v := range j {
		p = append(p, k+"="+v)
	}
	return strings.Join(p, "; ")
}
func (j jar) absorb(h http.Header) {
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(j, c.Name)
		} else {
			j[c.Name] = c.Value
		}
	}
}

var client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func get(u string, j jar, h map[string]string) (*http.Response, string) {
	req, _ := http.NewRequest("GET", u, nil)
	return send(req, j, h)
}
func send(req *http.Request, j jar, h map[string]string) (*http.Response, string) {
	if j != nil && len(j) > 0 {
		req.Header.Set("Cookie", j.header())
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if j != nil {
		j.absorb(resp.Header)
	}
	return resp, string(b)
}

var nav = map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "text/html,application/xhtml+xml"}

func must(ok bool, msg string, a ...any) {
	if !ok {
		fmt.Printf("FAIL "+msg+"\n", a...)
		os.Exit(1)
	}
}

func signin(base, cookiefile string) {
	site, kc := jar{}, jar{}
	r, _ := get(base+"/app/page?x=1", site, nav)
	loc := r.Header.Get("Location")
	fmt.Printf("1 unauthenticated navigation: %d Location=%s\n", r.StatusCode, loc)
	must(r.StatusCode == 302 && strings.HasPrefix(loc, "/_session/login"), "expected redirect to login")
	r, _ = get(base+loc, site, nav)
	auth := r.Header.Get("Location")
	u, _ := url.Parse(auth)
	fmt.Printf("2 /_session/login: %d -> %s%s ?%s\n", r.StatusCode, u.Host, u.Path, strings.Join(keys(u.Query()), ","))
	fmt.Printf("  binding cookie set: %v (HttpOnly Secure __Host-: %s)\n", site["__Host-spike-tx"] != "", r.Header.Get("Set-Cookie")[:40])
	must(u.Query().Get("request_uri") != "" && u.Query().Get("code_challenge") == "", "PAR: authorize URL must carry request_uri only")
	r, body := get(auth, kc, nav)
	for i := 0; i < 5 && r.StatusCode == 302; i++ {
		next, _ := url.Parse(auth)
		l, _ := next.Parse(r.Header.Get("Location"))
		auth = l.String()
		r, body = get(auth, kc, nav)
	}
	m := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(body)
	must(m != nil, "no login form (status %d)", r.StatusCode)
	action := html.UnescapeString(m[1])
	req, _ := http.NewRequest("POST", action, strings.NewReader(url.Values{"username": {"alice"}, "password": {"alice"}, "credentialId": {""}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, body = send(req, kc, nil)
	cb := r.Header.Get("Location")
	must(r.StatusCode == 302 && strings.Contains(cb, "/_session/callback"), "login post: %d %s", r.StatusCode, body)
	cu, _ := url.Parse(cb)
	fmt.Printf("3 issuer redirect back: %d, params=%s iss=%s\n", r.StatusCode, strings.Join(keys(cu.Query()), ","), cu.Query().Get("iss"))
	r, body = get(cb, site, nav)
	fmt.Printf("4 callback: %d Location=%s\n", r.StatusCode, r.Header.Get("Location"))
	must(r.StatusCode == 302, "callback failed: %s", body)
	for _, sc := range r.Header.Values("Set-Cookie") {
		fmt.Printf("  Set-Cookie: %s\n", redact(sc))
	}
	must(site["__Host-spike"] != "", "no session cookie")
	os.WriteFile(cookiefile, []byte(site["__Host-spike"]), 0o600)
	r, body = get(base+"/app/page?x=1", site, nav)
	var echo struct{ Headers map[string][]string }
	json.Unmarshal([]byte(body), &echo)
	fmt.Printf("5 with session: %d, upstream saw x-session-user=%v\n", r.StatusCode, echo.Headers["X-Session-User"])
}

func redact(s string) string {
	if i := strings.Index(s, "="); i >= 0 {
		if j := strings.Index(s, ";"); j > i {
			return s[:i+1] + "<value>" + s[j:]
		}
	}
	return s
}
func keys(v url.Values) []string {
	var k []string
	for x := range v {
		k = append(k, x)
	}
	return k
}

// raw sends an HTTP/1.1 request line exactly as given, for path-confusion tests.
func raw(base, target string, hdr map[string]string) (int, http.Header, string) {
	u, _ := url.Parse(base)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		panic(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", target, u.Host)
	for k, v := range hdr {
		fmt.Fprintf(c, "%s: %s\r\n", k, v)
	}
	fmt.Fprint(c, "\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, nil, err.Error()
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func upstream(body string) map[string][]string {
	var e struct {
		Path    string
		Headers map[string][]string
	}
	json.Unmarshal([]byte(body), &e)
	if e.Headers == nil {
		return nil
	}
	e.Headers["_path"] = []string{e.Path}
	return e.Headers
}

func show(h map[string][]string, names ...string) string {
	if h == nil {
		return "(did not reach the upstream)"
	}
	var out []string
	for _, n := range names {
		v, ok := h[n]
		if !ok {
			out = append(out, n+"=<absent>")
		} else {
			t := fmt.Sprintf("%q", v)
			if len(t) > 40 {
				t = t[:37] + "...\""
			}
			out = append(out, n+"="+t)
		}
	}
	return strings.Join(out, " ")
}

func checks(label, base, cookiefile string) {
	b, _ := os.ReadFile(cookiefile)
	sess := strings.TrimSpace(string(b))
	ck := "__Host-spike=" + sess
	fmt.Printf("=== %s (%s)\n", label, base)

	r, body := get(base+"/app/x?q=1", nil, nav)
	fmt.Printf("a navigation, no cookie: %d Location=%q\n", r.StatusCode, r.Header.Get("Location"))
	r, body = get(base+"/app/x", nil, map[string]string{"Accept": "application/json", "Sec-Fetch-Mode": "cors"})
	fmt.Printf("b fetch, no cookie: %d Content-Type=%q body=%s\n", r.StatusCode, r.Header.Get("Content-Type"), strings.TrimSpace(body))
	req, _ := http.NewRequest("POST", base+"/app/x", strings.NewReader("a=b"))
	r, body = send(req, nil, nil)
	fmt.Printf("c POST, no cookie: %d body=%s\n", r.StatusCode, strings.TrimSpace(body))
	r, body = get(base+"/app/x", nil, map[string]string{"Cookie": "__Host-spike=forged-value", "Accept": "text/html", "Sec-Fetch-Mode": "navigate"})
	fmt.Printf("c2 forged cookie id: %d Location=%q\n", r.StatusCode, r.Header.Get("Location"))

	r, body = get(base+"/app/x", nil, map[string]string{"Cookie": ck + "; theme=dark; lang=en"})
	h := upstream(body)
	fmt.Printf("d valid session: %d upstream: %s\n", r.StatusCode, show(h, "X-Session-User", "X-Session-Email", "X-Session-Groups", "Cookie", "Authorization"))

	r, body = get(base+"/app/x", nil, map[string]string{"Cookie": ck})
	h = upstream(body)
	fmt.Printf("d2 only the session cookie: %d upstream: %s\n", r.StatusCode, show(h, "Cookie"))

	r, body = get(base+"/app/x", nil, map[string]string{"Cookie": ck, "X-Session-User": "evil", "X-Session-Groups": "admin", "Authorization": "Bearer evil"})
	h = upstream(body)
	fmt.Printf("e spoofed identity + Authorization with a valid session: %d upstream: %s\n", r.StatusCode, show(h, "X-Session-User", "X-Session-Groups", "Authorization"))

	r, body = get(base+"/assets/logo.png", nil, map[string]string{"X-Session-User": "evil", "Authorization": "Bearer evil", "Cookie": "a=1"})
	h = upstream(body)
	fmt.Printf("f public route, spoofed headers: %d upstream: %s\n", r.StatusCode, show(h, "X-Session-User", "Authorization", "Cookie"))

	r, body = get(base+"/api/token/x", nil, map[string]string{"Cookie": ck})
	h = upstream(body)
	fmt.Printf("g token route: %d upstream: %s\n", r.StatusCode, show(h, "Authorization"))

	r, body = get(base+"/refresh-demo/x", nil, map[string]string{"Cookie": ck})
	var scs []string
	for _, sc := range r.Header.Values("Set-Cookie") {
		scs = append(scs, redact(sc))
	}
	fmt.Printf("h Set-Cookie on an allowed request: %d Set-Cookie=%q\n", r.StatusCode, scs)

	code, hd, body2 := raw(base, "/assets/../private/x", nil)
	h = upstream(body2)
	fmt.Printf("i dot-segment /assets/../private/x without cookie: %d Location=%q upstream: %s\n", code, hd.Get("Location"), show(h, "_path"))
	code, hd, body2 = raw(base, "/assets/%2e%2e/private/x", nil)
	h = upstream(body2)
	fmt.Printf("i2 encoded dot-segment /assets/%%2e%%2e/private/x: %d Location=%q upstream: %s\n", code, hd.Get("Location"), show(h, "_path"))
	code, hd, body2 = raw(base, "//assets//..//private", nil)
	h = upstream(body2)
	fmt.Printf("i3 merged slashes //assets//..//private: %d Location=%q upstream: %s\n", code, hd.Get("Location"), show(h, "_path"))
}

func main() {
	switch os.Args[1] {
	case "signin":
		signin(os.Args[2], os.Args[3])
	case "checks":
		checks(os.Args[2], os.Args[3], os.Args[4])
	}
}
