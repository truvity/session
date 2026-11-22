package signin

import "testing"

func TestSafeReturnTo(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "/",
		"/app?x=1#f":             "/app?x=1#f",
		"/":                      "/",
		"app":                    "/",
		"//evil.example.test/":   "/",
		`/\evil.example.test`:    "/",
		"https://evil.example/x": "/",
		"/_session/logout":       "/",
		"/a\r\nSet-Cookie: x=y":  "/",
		"javascript:alert(1)":    "/",
	} {
		if got := safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}
