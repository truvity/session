// Command session is the session service: the sign-in paths and the check, for Envoy over gRPC (--check-grpc) and HTTP
// (--check-http) and for nginx's auth_request (--check-nginx), with the exchange client and the identity header for the route modes exchange and identity-header.
//
//	session serve --config-dir DIR --dynamodb-table NAME [--key-dir DIR] [--key PURPOSE=DRIVER[:KEY] ...] --audit-socket PATH|--audit-stdout [flags]
//	session check --site FILE      validate a site file
//	session version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	awskmsapi "github.com/aws/aws-sdk-go-v2/service/kms"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"

	"github.com/truvity/atoom/key/awskms"
	sourcev1 "github.com/truvity/atoom/source/gen/atoom/source/v1alpha1"
	"github.com/truvity/atoom/transport/gen/atoom/transport/v1alpha1/transportv1alpha1connect"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/atoomx"
	"github.com/truvity/session/internal/audit"
	"github.com/truvity/session/internal/envoy"
	"github.com/truvity/session/internal/exchange"
	"github.com/truvity/session/internal/nginx"
	"github.com/truvity/session/internal/policy"
	"github.com/truvity/session/internal/sealer"
	"github.com/truvity/session/internal/signin"
	"github.com/truvity/session/internal/site"
)

// version is session's release, a semantic version: the audit records name it (metadata.product.version).
var version = "0.0.0-dev"

func main() {
	slog.SetDefault(slog.New(quietRefusals{slog.NewJSONHandler(os.Stderr, nil)}))
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	case "version", "--version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "session:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: session serve|check|version (session <command> -h for its flags)")
	os.Exit(2)
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := fs.String("site", "", "the site file to validate")
	_ = fs.Parse(args)
	b, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	if _, err := site.Parse(b); err != nil {
		return err
	}
	fmt.Println("site file ok")
	return nil
}

type serveFlags struct {
	configDir, keyDir, environment   string
	table, endpoint                  string
	listen, admin                    string
	checkGRPC, checkHTTP, checkNginx string
	storeTimeout, exchangeTimeout    time.Duration
	keys                             listFlag
	kmsAliasPrefix, kmsEndpoint      string
	auditSocket                      string
	auditStdout                      bool
}

// listFlag is a flag that may be given more than once.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var f serveFlags
	fs.StringVar(&f.configDir, "config-dir", "", "the directory of the source port's file driver: site.jws (the site file, YAML) and the policy bundle")
	fs.StringVar(&f.keyDir, "key-dir", "", "the state directory of the software key driver (mode 0700); required when a key purpose is on it")
	fs.Var(&f.keys, "key", "the key driver of a key purpose (client-assertion, identity-header, wrapping): PURPOSE=software, PURPOSE=awskms "+
		"(the KMS key under the alias alias/<kms-alias-prefix>/PURPOSE) or PURPOSE=awskms:KEY (a KMS key ID, key ARN or alias name); "+
		"repeatable; a purpose not named is on software")
	fs.StringVar(&f.kmsAliasPrefix, "kms-alias-prefix", "", "the alias prefix of the KMS keys of --key PURPOSE=awskms; empty is session/<site>")
	fs.StringVar(&f.kmsEndpoint, "kms-endpoint", "", "an AWS KMS endpoint other than AWS's")
	fs.StringVar(&f.auditSocket, "audit-socket", "", "the emit socket of atoom's transport port (a transport driver such as transport-spool: DIR/emit.sock), "+
		"to the audit writer; session refuses to start without it unless --audit-stdout is given, and refuses both")
	fs.BoolVar(&f.auditStdout, "audit-stdout", false, "write each security-audit record as one JSON line to stdout, for local development: "+
		"no writer receives them; refused with --audit-socket")
	fs.StringVar(&f.environment, "environment", "", "a label of the installation: the scope of the security-audit log (unset is local), "+
		"and the environment the software key driver is told (atoom 0.6.0 takes unset, development, staging or production); "+
		"nothing in session decides by its value")
	fs.StringVar(&f.table, "dynamodb-table", "", "the DynamoDB table of the store driver")
	fs.StringVar(&f.endpoint, "dynamodb-endpoint", "", "a DynamoDB endpoint other than AWS's (DynamoDB Local)")
	fs.StringVar(&f.listen, "listen", ":8080", "the address of the sign-in paths")
	fs.StringVar(&f.checkGRPC, "check-grpc", ":9001", "the address of Envoy's gRPC external authorisation; empty turns it off")
	fs.StringVar(&f.checkHTTP, "check-http", "", "the address of Envoy's HTTP external authorisation (path prefix /check); empty turns it off")
	fs.StringVar(&f.checkNginx, "check-nginx", "", "the address of nginx's auth_request check (paths /auth and /error-page); empty turns it off")
	fs.StringVar(&f.admin, "admin", "127.0.0.1:9090", "the address of /metrics and /healthz")
	fs.DurationVar(&f.storeTimeout, "store-timeout", core.DefaultStoreTimeout, "the timeout of every store call; shorter than the proxy's timeout for the check")
	fs.DurationVar(&f.exchangeTimeout, "exchange-timeout", core.DefaultExchangeTimeout,
		"the bound of a check's token exchange (lock, refresh, issuer call); store timeout plus this is shorter than the proxy's timeout for the check")
	_ = fs.Parse(args)
	for name, v := range map[string]string{"config-dir": f.configDir, "dynamodb-table": f.table} {
		if v == "" {
			return fmt.Errorf("--%s is required", name)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	app, err := build(ctx, f)
	if err != nil {
		return err
	}
	defer app.close()
	return app.run(ctx, f)
}

type app struct {
	core    *core.Core
	signin  *signin.Handler
	closers []func()
	// runners run beside the servers until the context ends: the policy loader's refresh.
	runners []func(context.Context) error
}

func (a *app) close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
}

func build(ctx context.Context, f serveFlags) (*app, error) {
	a := &app{}
	ok := false
	defer func() {
		if !ok {
			a.close()
		}
	}()
	src, err := atoomx.FileSource(f.configDir)
	if err != nil {
		return nil, fmt.Errorf("config dir: %w", err)
	}
	a.closers = append(a.closers, src.Stop)
	doc, err := src.Source.Read(ctx, connect.NewRequest(&sourcev1.ReadRequest{Name: "site"}))
	if err != nil {
		return nil, fmt.Errorf("site file: %w", err)
	}
	sf, err := site.Parse(doc.Msg.GetData())
	if err != nil {
		return nil, err
	}
	rules, err := sf.Rules()
	if err != nil {
		return nil, err
	}
	rules.StoreTimeout = f.storeTimeout
	rules.ExchangeTimeout = f.exchangeTimeout
	if sf.ErrorPage != "" {
		page, err := src.Source.Read(ctx, connect.NewRequest(&sourcev1.ReadRequest{Name: sf.ErrorPage}))
		if err != nil {
			return nil, fmt.Errorf("error page: %w", err)
		}
		rules.ErrorPage = page.Msg.GetData()
	}
	var pol core.Policy
	if sf.Policy != nil {
		pub, err := sf.Policy.Publisher()
		if err != nil {
			return nil, err
		}
		eng, err := policy.Start(ctx, policy.Options{Source: src.Source, Name: sf.Policy.Bundle, Publisher: pub})
		if err != nil {
			return nil, err
		}
		slog.Info("policy bundle", "digest", eng.Digest())
		a.runners = append(a.runners, eng.Run)
		pol = eng
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	db := awsdynamodb.NewFromConfig(cfg, func(o *awsdynamodb.Options) {
		if f.endpoint != "" {
			o.BaseEndpoint = aws.String(f.endpoint)
		}
	})
	st, err := atoomx.DynamoDB(db, f.table)
	if err != nil {
		return nil, err
	}
	a.closers = append(a.closers, st.Stop)
	keyPurposes := append(signin.Purposes(), sealer.KeyPurposes()...)
	choices, err := atoomx.ParseKeyChoices(f.keys, keyPurposes)
	if err != nil {
		return nil, err
	}
	prefix := f.kmsAliasPrefix
	if prefix == "" {
		prefix = "session/" + sf.Site
	}
	keys, err := atoomx.OpenKeys(atoomx.KeyOptions{Purposes: keyPurposes, Choices: choices, StateDir: f.keyDir, Environment: f.environment,
		AliasPrefix: prefix, KMS: func() (awskms.API, error) {
			return awskmsapi.NewFromConfig(cfg, func(o *awskmsapi.Options) {
				if f.kmsEndpoint != "" {
					o.BaseEndpoint = aws.String(f.kmsEndpoint)
				}
			}), nil
		}})
	if err != nil {
		return nil, err
	}
	a.closers = append(a.closers, keys.Stop)
	for _, p := range keyPurposes {
		slog.Info("key", "purpose", p.Name, "driver", keys.Driver(p.Name))
	}
	// One key client in front of the drivers (atoom's key/route): each purpose's calls go to the driver that holds it.
	routed, err := keys.Route()
	if err != nil {
		return nil, err
	}
	// The seal block keeps its wraps in session's store, under seal/, and signs for the token block, which makes the client
	// assertion and the identity header (decision 0022). Its start ensures every key.
	sb, err := sealer.Open(ctx, sealer.Options{Keys: routed, Items: st.Items, Installation: "session/" + sf.Site, Tokens: signin.TokenPurposes()})
	if err != nil {
		return nil, err
	}
	a.closers = append(a.closers, sb.Stop)
	signer, identity, err := signin.Signers(sb.Tokens)
	if err != nil {
		return nil, err
	}
	issuer, err := exchange.New(ctx, exchange.Options{Issuer: sf.Issuer, ClientID: sf.Client.ID, Asserter: signer})
	if err != nil {
		return nil, err
	}
	auditor, err := openAudit(a, f, sf, sb.Sealer)
	if err != nil {
		return nil, err
	}
	c, err := core.New(core.Options{Rules: rules, Items: st.Items, Seal: sb.Sealer, Policy: pol, Issuer: issuer, Identity: identity,
		Audit: auditor})
	if err != nil {
		return nil, err
	}
	a.core = c
	h, err := signin.New(ctx, signin.Options{Core: c, Issuer: sf.Issuer, ClientID: sf.Client.ID, Scopes: sf.Scopes, Signer: signer,
		Identity: &identity})
	if err != nil {
		return nil, err
	}
	a.signin = h
	ok = true
	return a, nil
}

// auditScope is the scope of the audit log: the label --environment, or local when it is unset. It is a name only.
func auditScope(environment string) string {
	if environment == "" {
		return "local"
	}
	return environment
}

// auditTransport is the client of the transport port (decision 0024): the emit socket of a transport driver (--audit-socket), or,
// with --audit-stdout for local development, the driver Lines in this process, which writes each record as one JSON line to w.
// Exactly one of them must be given, whatever --environment says. stop is nil for the socket.
func auditTransport(socketPath string, stdout bool, w io.Writer) (transportv1alpha1connect.TransportServiceClient, func(), error) {
	switch {
	case socketPath != "" && stdout:
		return nil, nil, errors.New("--audit-socket and --audit-stdout are both given: name one place for the security-audit records")
	case socketPath != "":
		return audit.Socket(socketPath), nil, nil
	case stdout:
		client, stop := audit.NewLines(w).Mount()
		return client, stop, nil
	default:
		return nil, nil, errors.New("--audit-socket is required: the emit socket of the transport driver whose consumer is the audit writer; " +
			"--audit-stdout writes the records to stdout instead, for local development")
	}
}

// openAudit is the emitter of truvity/audit over the transport port (decisions 0023 and 0024), with the seal block's pseudonyms.
func openAudit(a *app, f serveFlags, sf *site.File, seal *sealer.Sealer) (*audit.Auditor, error) {
	tr, stop, err := auditTransport(f.auditSocket, f.auditStdout, os.Stdout)
	if err != nil {
		return nil, err
	}
	if stop != nil {
		a.closers = append(a.closers, stop)
		slog.Info("audit", "transport", "lines", "to", "stdout")
	} else {
		slog.Info("audit", "transport", "socket", "socket", f.auditSocket)
	}
	bundle := ""
	if sf.Policy != nil {
		bundle = sf.Policy.Bundle
	}
	return audit.New(audit.Options{Transport: tr, Pseudonyms: seal, Release: version, Scope: auditScope(f.environment), Policy: bundle})
}

func (a *app) run(ctx context.Context, f serveFlags) error {
	mux := http.NewServeMux()
	a.signin.Register(mux)
	admin := http.NewServeMux()
	admin.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	admin.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_ = a.core.Metrics().WritePrometheus(w, a.core.Rules().Site)
	})
	servers := []*http.Server{
		{Addr: f.listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second},
		{Addr: f.admin, Handler: admin, ReadHeaderTimeout: 10 * time.Second},
	}
	if f.checkHTTP != "" {
		servers = append(servers, &http.Server{Addr: f.checkHTTP, Handler: &envoy.HTTP{Core: a.core, Prefix: "/check"}, ReadHeaderTimeout: 10 * time.Second})
	}
	if f.checkNginx != "" {
		servers = append(servers, &http.Server{Addr: f.checkNginx, Handler: &nginx.Handler{Core: a.core, ErrorPage: a.core.Rules().ErrorPage},
			ReadHeaderTimeout: 10 * time.Second})
	}
	errs := make(chan error, len(servers)+1)
	for _, r := range a.runners {
		go func() {
			if err := r(ctx); err != nil {
				slog.Error("runner", "error", err.Error())
			}
		}()
	}
	if f.checkGRPC != "" {
		ln, err := net.Listen("tcp", f.checkGRPC)
		if err != nil {
			return err
		}
		gs := grpc.NewServer()
		authv3.RegisterAuthorizationServer(gs, &envoy.GRPC{Core: a.core})
		slog.Info("listening", "address", ln.Addr().String(), "service", "envoy.service.auth.v3.Authorization")
		go func() { errs <- gs.Serve(ln) }()
		defer gs.GracefulStop()
	}
	for _, s := range servers {
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			return err
		}
		slog.Info("listening", "address", ln.Addr().String())
		go func() { errs <- s.Serve(ln) }()
	}
	select {
	case <-ctx.Done():
	case err := <-errs:
		return err
	}
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shut)
	}
	return nil
}

// quietRefusals drops the store driver's warning for a refused condition (code aborted): a lost race on an idle refresh or a
// lock is normal, and would otherwise be a log line each (fit spike, section 2.3.2).
type quietRefusals struct{ slog.Handler }

func (q quietRefusals) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "refused" {
		aborted := false
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "code" && strings.EqualFold(a.Value.String(), "aborted") {
				aborted = true
				return false
			}
			return true
		})
		if aborted {
			return nil
		}
	}
	return q.Handler.Handle(ctx, r)
}

func (q quietRefusals) WithAttrs(as []slog.Attr) slog.Handler {
	return quietRefusals{q.Handler.WithAttrs(as)}
}
func (q quietRefusals) WithGroup(n string) slog.Handler { return quietRefusals{q.Handler.WithGroup(n)} }
