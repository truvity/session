// fitapp is the web app of the Lambda Web Adapter test: the check core behind a plain HTTP server, with the
// authorizer shapes of the first spike. It runs as /var/task/bootstrap in the Runtime Interface Emulator image.
// Each request is logged as one JSON line, so that the log says how the adapter classified an event:
//   - an event that is not an HTTP event arrives as POST on the pass-through path (/events) with the raw event as body;
//   - an event that the adapter takes for an HTTP event arrives as the HTTP request it describes, with the
//     x-amzn-request-context header that the adapter adds.
//
// Throwaway spike code.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/truvity/session/spike/internal/fit"
	"github.com/truvity/session/spike/internal/sess"
)

// clean drops the characters that could split a log line.
func clean(v string) string {
	v = strings.ReplaceAll(v, "\n", "")
	return strings.ReplaceAll(v, "\r", "")
}

// logLine logs how a request arrived. It never logs a header value, a cookie or a body: only what says how the
// adapter classified the event (the path, whether the adapter's own context header is there, the sizes).
func logLine(r *http.Request, body []byte, seenAs, note string) {
	line, _ := json.Marshal(map[string]any{
		"seen_as": seenAs, "method": clean(r.Method), "path": clean(r.URL.Path), "query_bytes": len(r.URL.RawQuery),
		"has_cookie_header": r.Header.Get("Cookie") != "", "has_x_amzn_request_context": r.Header.Get("X-Amzn-Request-Context") != "",
		"x_amzn_request_context_is_null": r.Header.Get("X-Amzn-Request-Context") == "null",
		"has_x_amzn_lambda_context":      r.Header.Get("X-Amzn-Lambda-Context") != "", "body_bytes": len(body), "event": clean(note),
	})
	log.Printf("REQ %s", line)
}

func main() {
	store := fit.NewMem()
	core := &sess.Core{Checker: store, CookieName: "__Host-spike"}
	auth := &sess.LambdaAuthorizer{Core: core}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	// pass-through: the event as the body. The authorizer answer is the JSON body, with the status of the answer.
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var probe struct {
			Type    string `json:"type"`
			Version string `json:"version"`
		}
		_ = json.Unmarshal(body, &probe)
		logLine(r, body, "pass-through", "type="+probe.Type+" version="+probe.Version)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case probe.Type == "REQUEST" && probe.Version == "2.0":
			var ev events.APIGatewayV2CustomAuthorizerV2Request
			_ = json.Unmarshal(body, &ev)
			out, err := auth.HandleV2(r.Context(), ev)
			answer(w, out, err)
		case probe.Type == "REQUEST":
			var ev events.APIGatewayCustomAuthorizerRequestTypeRequest
			_ = json.Unmarshal(body, &ev)
			out, err := auth.HandleREST(r.Context(), ev)
			answer(w, out, err)
		default:
			_, _ = w.Write([]byte(`{"ok":true,"note":"not an authorizer event"}`))
		}
	})
	// everything else is an event that the adapter took for an HTTP event
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		logLine(r, body, "http", "")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"seen_as":"http","note":"this app answered as an HTTP server"}`))
	})
	addr := ":" + envOr("AWS_LWA_PORT", "8000")
	log.Printf("fitapp up on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// answer writes the authorizer's answer as the body. The error "Unauthorized" of the first spike cannot be a body:
// a function error is not something a web app can return, so this app answers 401 with a marker body, which is
// what the test then observes.
func answer(w http.ResponseWriter, out any, err error) {
	if err != nil {
		if strings.Contains(err.Error(), "unavailable") {
			w.WriteHeader(http.StatusServiceUnavailable) // fail closed: the adapter turns it into a function error when asked to
			_, _ = w.Write([]byte(`{"errorMessage":"store unavailable"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorMessage":"` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`))
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
