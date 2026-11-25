package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/aws/aws-sdk-go-v2/aws"

	sourcev1 "github.com/truvity/atoom/source/gen/atoom/source/v1alpha1"
)

// appConfigData is a small fake of the AppConfig data plane (the two operations atoom's source/appconfig calls, in their REST-JSON
// protocol), so that --source-appconfig is tested through the real AWS SDK client. atoom's own fake is internal to its module
// (source/appconfig/internal/appconfigfake) and cannot be imported here; this one keeps only what the driver needs: one-use
// tokens, the bytes of the first answer of a session, and ResourceNotFoundException for a profile that is not deployed.
type appConfigData struct {
	mu       sync.Mutex
	deployed map[string][]byte // application/environment/profile -> bytes
	tokens   map[string]string // token -> application/environment/profile
	starts   map[string]int    // profile -> sessions started
	n        int
}

func (f *appConfigData) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/configurationsessions":
		var in struct{ ApplicationIdentifier, EnvironmentIdentifier, ConfigurationProfileIdentifier string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "not JSON", http.StatusBadRequest)
			return
		}
		key := in.ApplicationIdentifier + "/" + in.EnvironmentIdentifier + "/" + in.ConfigurationProfileIdentifier
		f.starts[in.ConfigurationProfileIdentifier]++
		if _, ok := f.deployed[key]; !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"__type": "ResourceNotFoundException", "Message": "no such profile"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"InitialConfigurationToken": f.token(key)})
	case r.Method == http.MethodGet && r.URL.Path == "/configuration":
		key, ok := f.tokens[r.URL.Query().Get("configuration_token")]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"__type": "BadRequestException", "Message": "the token is not valid"})
			return
		}
		w.Header().Set("Next-Poll-Configuration-Token", f.token(key))
		w.Header().Set("Next-Poll-Interval-In-Seconds", "60")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(f.deployed[key])
	default:
		http.NotFound(w, r)
	}
}

func (f *appConfigData) token(key string) string {
	f.n++
	t := "token-" + strconv.Itoa(f.n)
	f.tokens[t] = key
	return t
}

// Decision 0032: --source-appconfig APP/ENV/PROFILE reads the site file from the profile PROFILE, and every other document the site
// file names from the profile of its own name, through atoom's Go source/appconfig in the process.
func TestTheSourceOnAppConfig(t *testing.T) {
	fake := &appConfigData{tokens: map[string]string{}, starts: map[string]int{}, deployed: map[string][]byte{
		"session/devel/docs-site":     []byte("the site file"),
		"session/devel/policy-bundle": []byte("the policy bundle"),
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := aws.Config{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL), HTTPClient: srv.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "placeholder", SecretAccessKey: "placeholder"}, nil
		})}
	src, err := openSource(serveFlags{sourceAppConfig: "session/devel/docs-site"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Stop()
	ctx := context.Background()
	for name, want := range map[string]string{"site": "the site file", "policy-bundle": "the policy bundle"} {
		for range 2 {
			doc, err := src.Source.Read(ctx, connect.NewRequest(&sourcev1.ReadRequest{Name: name}))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if got := string(doc.Msg.GetData()); got != want {
				t.Fatalf("%s: %q", name, got)
			}
		}
	}
	// One session for each profile: a second read within the poll interval does not call AppConfig.
	if fake.starts["docs-site"] != 1 || fake.starts["policy-bundle"] != 1 || fake.starts["site"] != 0 {
		t.Fatalf("sessions started: %v", fake.starts)
	}
	if _, err := src.Source.Read(ctx, connect.NewRequest(&sourcev1.ReadRequest{Name: "error-page"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a profile that is not deployed: %v", err)
	}
}
