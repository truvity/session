package echo_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/truvity/session/conformance/echo"
)

func TestHandler(t *testing.T) {
	srv := httptest.NewServer(echo.Handler())
	defer srv.Close()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/legacy/x?q=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Session-Identity", "a.b.c")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var got echo.Seen
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" ||
		json.NewDecoder(res.Body).Decode(&got) != nil {
		t.Fatalf("answer: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if got.Method != http.MethodPost || got.Path != "/legacy/x?q=1" || len(got.Headers["X-Session-Identity"]) != 1 ||
		got.Headers["X-Session-Identity"][0] != "a.b.c" {
		t.Fatalf("seen: %+v", got)
	}
}
