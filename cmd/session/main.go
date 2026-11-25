// Command session is the session service: the sign-in paths and the check, for Envoy over gRPC (--check-grpc) and HTTP
// (--check-http) and for nginx's auth_request (--check-nginx), with the exchange client and the identity header for the route modes exchange and identity-header.
// On AWS Lambda, the sign-in function is `session serve` behind the Lambda Web Adapter (decision 0012), and the API Gateway
// authorizer is `session authorizer`, a native Go handler of the same check (decision 0014).
//
//	session serve --config-dir DIR|--source-appconfig APP/ENV/PROFILE --dynamodb-table NAME [--key-dir DIR] [--key PURPOSE=DRIVER[:KEY] ...]
//	              --audit-socket PATH|--audit-nats URL ...|--audit-sqs QUEUE_URL|--audit-stdout [flags]
//	session authorizer --config-dir DIR|--source-appconfig APP/ENV/PROFILE --dynamodb-table NAME [...]   the API Gateway Lambda authorizer (a Lambda function only)
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
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/appconfigdata"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	awskmsapi "github.com/aws/aws-sdk-go-v2/service/kms"
	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"

	"github.com/truvity/atoom/key/awskms"
	sourcev1 "github.com/truvity/atoom/source/gen/atoom/source/v1alpha1"
	"github.com/truvity/atoom/transport/gen/atoom/transport/v1alpha1/transportv1alpha1connect"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/apigateway"
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
	case "authorizer":
		err = authorizer(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "usage: session serve|authorizer|check|version (session <command> -h for its flags)")
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
	configDir, sourceAppConfig       string
	keyDir, auditScope               string
	table, endpoint                  string
	listen, admin                    string
	checkGRPC, checkHTTP, checkNginx string
	storeTimeout, exchangeTimeout    time.Duration
	keys                             listFlag
	kmsAliasPrefix, kmsEndpoint      string
	audit                            auditFlags
}

// auditFlags are the start-up switches of the audit transport (decisions 0024 and 0032): exactly one place for the records.
type auditFlags struct {
	socket string // --audit-socket: the emit socket of a transport driver (transport-spool)
	stdout bool   // --audit-stdout: JSON lines on stdout, for local development
	sqs    string // --audit-sqs: the FIFO queue of atoom's Go transport/sqs, in this process
	nats   audit.NATSOptions
}

// listFlag is a flag that may be given more than once.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// commonFlags are the flags of every command that runs the check: the site, the drivers of the ports, audit and the timeouts.
func commonFlags(fs *flag.FlagSet, f *serveFlags) {
	fs.StringVar(&f.configDir, "config-dir", "", "the directory of the source port's file driver: site.jws (the site file, YAML) and the policy bundle; "+
		"refused with --source-appconfig")
	fs.StringVar(&f.sourceAppConfig, "source-appconfig", "", "APP/ENV/PROFILE: read the documents through atoom's AWS AppConfig driver in this process, "+
		"from the application APP and its environment ENV; the site file is the configuration profile PROFILE, every other document the profile of its name; "+
		"refused with --config-dir")
	fs.StringVar(&f.keyDir, "key-dir", "", "the state directory of the software key driver (mode 0700); required when a key purpose is on it")
	fs.Var(&f.keys, "key", "the key driver of a key purpose (client-assertion, identity-header, wrapping): PURPOSE=software, PURPOSE=awskms "+
		"(the KMS key under the alias alias/<kms-alias-prefix>/PURPOSE) or PURPOSE=awskms:KEY (a KMS key ID, key ARN or alias name); "+
		"repeatable; a purpose not named is on software")
	fs.StringVar(&f.kmsAliasPrefix, "kms-alias-prefix", "", "the alias prefix of the KMS keys of --key PURPOSE=awskms; empty is session/<site>")
	fs.StringVar(&f.kmsEndpoint, "kms-endpoint", "", "an AWS KMS endpoint other than AWS's")
	fs.StringVar(&f.audit.socket, "audit-socket", "", "the emit socket of atoom's transport port (a transport driver such as transport-spool: DIR/emit.sock), "+
		"to the audit writer; exactly one of --audit-socket, --audit-nats, --audit-sqs and --audit-stdout")
	fs.StringVar(&f.audit.nats.URL, "audit-nats", "", "the NATS server or servers (comma separated) of atoom's NATS JetStream transport driver, in this process, "+
		"to the audit writer; with --audit-nats-stream and --audit-nats-subject; exactly one of the four audit switches")
	fs.StringVar(&f.audit.nats.Stream, "audit-nats-stream", "", "the JetStream stream of the audit log, made by the deployment (with --audit-nats)")
	fs.StringVar(&f.audit.nats.Subject, "audit-nats-subject", "", "the subject the records are published to, which the stream captures (with --audit-nats)")
	fs.StringVar(&f.audit.nats.Creds, "audit-nats-creds", "", "a NATS credentials file, a user JWT and its seed (with --audit-nats); refused with --audit-nats-token-file")
	fs.StringVar(&f.audit.nats.TokenFile, "audit-nats-token-file", "", "a file holding the token to present to NATS, read at every connect (with --audit-nats)")
	fs.StringVar(&f.audit.nats.TLSCA, "audit-nats-tls-ca", "", "a PEM file of the CAs that sign the NATS server's certificate (with --audit-nats)")
	fs.StringVar(&f.audit.sqs, "audit-sqs", "", "the URL of the SQS FIFO queue (ending in .fifo) of atoom's SQS transport driver, in this process, "+
		"to the audit writer: the switch of a Lambda function; exactly one of the four audit switches")
	fs.BoolVar(&f.audit.stdout, "audit-stdout", false, "write each security-audit record as one JSON line to stdout, for local development: "+
		"no writer receives them; exactly one of the four audit switches")
	fs.StringVar(&f.auditScope, "audit-scope", "", "the scope of the security-audit log, a label of the installation (unset is local); "+
		"nothing in session decides by its value")
	fs.StringVar(&f.table, "dynamodb-table", "", "the DynamoDB table of the store driver")
	fs.StringVar(&f.endpoint, "dynamodb-endpoint", "", "a DynamoDB endpoint other than AWS's (DynamoDB Local)")
	fs.DurationVar(&f.storeTimeout, "store-timeout", core.DefaultStoreTimeout, "the timeout of every store call; shorter than the proxy's timeout for the check")
	fs.DurationVar(&f.exchangeTimeout, "exchange-timeout", core.DefaultExchangeTimeout,
		"the bound of a check's token exchange (lock, refresh, issuer call); store timeout plus this is shorter than the proxy's timeout for the check")
}

func (f serveFlags) required() error {
	if _, err := f.sourceChoice(); err != nil {
		return err
	}
	if f.table == "" {
		return errors.New("--dynamodb-table is required")
	}
	return nil
}

// sourceChoice is the driver of the source port that the flags select (decision 0032): exactly one of --config-dir and
// --source-appconfig.
func (f serveFlags) sourceChoice() (string, error) {
	switch {
	case f.configDir != "" && f.sourceAppConfig != "":
		return "", errors.New("--config-dir and --source-appconfig are both given: name one source of the site file")
	case f.configDir != "":
		return "file", nil
	case f.sourceAppConfig != "":
		if _, _, _, err := appConfigPath(f.sourceAppConfig); err != nil {
			return "", err
		}
		return "appconfig", nil
	default:
		return "", errors.New("--config-dir or --source-appconfig is required: the directory of the site file, or its AppConfig APP/ENV/PROFILE")
	}
}

// appConfigPath splits the value of --source-appconfig, APP/ENV/PROFILE, three identifiers (names or ids) none of them empty.
func appConfigPath(v string) (app, env, profile string, err error) {
	parts := strings.Split(v, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("--source-appconfig %q is not APP/ENV/PROFILE", v)
	}
	return parts[0], parts[1], parts[2], nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var f serveFlags
	commonFlags(fs, &f)
	fs.StringVar(&f.listen, "listen", ":8080", "the address of the sign-in paths")
	fs.StringVar(&f.checkGRPC, "check-grpc", ":9001", "the address of Envoy's gRPC external authorisation; empty turns it off")
	fs.StringVar(&f.checkHTTP, "check-http", "", "the address of Envoy's HTTP external authorisation (path prefix /check); empty turns it off")
	fs.StringVar(&f.checkNginx, "check-nginx", "", "the address of nginx's auth_request check (paths /auth and /error-page); empty turns it off")
	fs.StringVar(&f.admin, "admin", "127.0.0.1:9090", "the address of /metrics and /healthz")
	_ = fs.Parse(args)
	if err := f.required(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	app, err := build(ctx, f)
	if err != nil {
		return err
	}
	defer app.close()
	if err := app.signIn(ctx); err != nil {
		return err
	}
	return app.run(ctx, f)
}

// authorizer runs the API Gateway Lambda authorizer (decision 0014): a native Go handler of the check for both API Gateway
// products, not behind the Lambda Web Adapter, which cannot answer authorizer events. It has no listener and no sign-in paths;
// the sign-in function is `session serve` behind the adapter. It runs only as a Lambda function.
func authorizer(args []string) error {
	fs := flag.NewFlagSet("authorizer", flag.ExitOnError)
	var f serveFlags
	commonFlags(fs, &f)
	_ = fs.Parse(args)
	if err := f.required(); err != nil {
		return err
	}
	if os.Getenv("AWS_LAMBDA_RUNTIME_API") == "" {
		return errors.New("session authorizer runs as an AWS Lambda function: AWS_LAMBDA_RUNTIME_API is not set")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	app, err := build(ctx, f)
	if err != nil {
		return err
	}
	defer app.close()
	app.startRunners(ctx)
	lambda.StartWithOptions((&apigateway.Authorizer{Core: app.core}).Handle, lambda.WithContext(ctx))
	return nil
}

type app struct {
	core    *core.Core
	signin  *signin.Handler
	site    *site.File
	signer  signin.Signer
	ident   signin.Signer
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
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	src, err := openSource(f, cfg)
	if err != nil {
		return nil, err
	}
	a.closers = append(a.closers, src.Stop)
	doc, err := src.Source.Read(ctx, connect.NewRequest(&sourcev1.ReadRequest{Name: atoomx.SiteDocument}))
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
	keys, err := atoomx.OpenKeys(atoomx.KeyOptions{Purposes: keyPurposes, Choices: choices, StateDir: f.keyDir,
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
	// One exchange client for each issuer (decision 0034): a session's exchange and refresh go to its own issuer.
	issuers := map[string]core.Issuer{}
	for _, is := range sf.Issuers {
		ex, err := exchange.New(ctx, exchange.Options{Issuer: is.Issuer, ClientID: is.Client.ID, Asserter: signer})
		if err != nil {
			return nil, fmt.Errorf("issuer %s: %w", is.ID, err)
		}
		issuers[is.Issuer] = ex
	}
	auditor, err := openAudit(a, f, cfg, sf, sb.Sealer)
	if err != nil {
		return nil, err
	}
	c, err := core.New(core.Options{Rules: rules, Items: st.Items, Seal: sb.Sealer, Policy: pol, Issuers: issuers, Identity: identity,
		Audit: auditor})
	if err != nil {
		return nil, err
	}
	a.core, a.site, a.signer, a.ident = c, sf, signer, identity
	ok = true
	return a, nil
}

// signIn makes the handler of the sign-in paths, which reads each issuer's discovery document.
func (a *app) signIn(ctx context.Context) error {
	var issuers []signin.Issuer
	for _, is := range a.site.Issuers {
		issuers = append(issuers, signin.Issuer{ID: is.ID, Label: is.Label, URL: is.Issuer, ClientID: is.Client.ID, Scopes: is.Scopes})
	}
	h, err := signin.New(ctx, signin.Options{Core: a.core, Issuers: issuers, Remember: a.site.Remember(),
		Signer: a.signer, Identity: &a.ident})
	if err != nil {
		return err
	}
	a.signin = h
	return nil
}

// openSource mounts the driver of the source port, which serves the site file and the policy bundle (decision 0032): atoom's Go
// source/file over --config-dir, or atoom's Go source/appconfig over --source-appconfig, exactly one of them. On Lambda the
// directory is the configuration layer (decision 0012) until a site moves to AppConfig (decision 0030). The core, the policy loader
// and the authorizer read only the port's client, so the driver is mounted here and nothing else changes. The AppConfig client
// takes the region, the credentials and an endpoint of another place (AWS_ENDPOINT_URL_APPCONFIGDATA) from cfg.
func openSource(f serveFlags, cfg aws.Config) (*atoomx.Source, error) {
	kind, err := f.sourceChoice()
	if err != nil {
		return nil, err
	}
	if kind == "appconfig" {
		app, env, profile, _ := appConfigPath(f.sourceAppConfig)
		src, err := atoomx.AppConfigSource(appconfigdata.NewFromConfig(cfg), app, env, profile)
		if err != nil {
			return nil, fmt.Errorf("source appconfig: %w", err)
		}
		slog.Info("source", "driver", "appconfig", "application", app, "environment", env, "profile", profile)
		return src, nil
	}
	src, err := atoomx.FileSource(f.configDir)
	if err != nil {
		return nil, fmt.Errorf("config dir: %w", err)
	}
	return src, nil
}

// auditScope is the scope of the audit log: the label --audit-scope, or local when it is unset. It is a name only (decision 0027).
func auditScope(label string) string {
	if label == "" {
		return "local"
	}
	return label
}

// choice is the audit transport the flags select (decisions 0024 and 0032): exactly one of --audit-socket, --audit-nats,
// --audit-sqs and --audit-stdout, whatever --audit-scope says. The settings of NATS need --audit-nats.
func (a auditFlags) choice() (string, error) {
	var given []string
	for _, s := range []struct {
		name string
		set  bool
	}{{"--audit-socket", a.socket != ""}, {"--audit-nats", a.nats.URL != ""}, {"--audit-sqs", a.sqs != ""}, {"--audit-stdout", a.stdout}} {
		if s.set {
			given = append(given, s.name)
		}
	}
	switch len(given) {
	case 0, 1:
	case 2:
		return "", fmt.Errorf("%s and %s are both given: name one place for the security-audit records", given[0], given[1])
	default:
		return "", fmt.Errorf("%s are all given: name one place for the security-audit records", strings.Join(given, ", "))
	}
	if a.nats.URL == "" {
		for _, s := range []struct{ name, v string }{{"--audit-nats-stream", a.nats.Stream}, {"--audit-nats-subject", a.nats.Subject},
			{"--audit-nats-creds", a.nats.Creds}, {"--audit-nats-token-file", a.nats.TokenFile}, {"--audit-nats-tls-ca", a.nats.TLSCA}} {
			if s.v != "" {
				return "", fmt.Errorf("%s is given without --audit-nats", s.name)
			}
		}
	}
	if len(given) == 0 {
		return "", errors.New("an audit transport is required: --audit-socket (the emit socket of the transport driver whose consumer is the audit writer), " +
			"--audit-nats or --audit-sqs (a transport driver in this process); --audit-stdout writes the records to stdout instead, for local development")
	}
	switch given[0] {
	case "--audit-nats":
		switch {
		case a.nats.Stream == "" || a.nats.Subject == "":
			return "", errors.New("--audit-nats needs --audit-nats-stream and --audit-nats-subject")
		case a.nats.Creds != "" && a.nats.TokenFile != "":
			return "", errors.New("--audit-nats-creds and --audit-nats-token-file are both given: name one credential")
		}
		return "nats", nil
	case "--audit-sqs":
		return "sqs", nil
	case "--audit-socket":
		return "socket", nil
	default:
		return "stdout", nil
	}
}

// auditTransport is the client of the transport port (decisions 0024 and 0032), and the function that stops it: the emit socket of
// a transport driver (--audit-socket); atoom's Go transport/nats (--audit-nats) or transport/sqs (--audit-sqs, the switch of a
// Lambda function, which has no spool sidecar), mounted in this process; or, with --audit-stdout for local development, the driver
// Lines in this process, which writes each record as one JSON line to w. Exactly one of them. The connection and credentials of
// NATS, and the SQS client's region and credentials (from cfg), are the host's: atoom's drivers know no deployment.
func auditTransport(a auditFlags, cfg aws.Config, w io.Writer) (transportv1alpha1connect.TransportServiceClient, func(), error) {
	kind, err := a.choice()
	if err != nil {
		return nil, nil, err
	}
	switch kind {
	case "socket":
		return audit.Socket(a.socket), func() {}, nil
	case "nats":
		return audit.NATS(a.nats)
	case "sqs":
		return audit.SQS(awssqs.NewFromConfig(cfg), a.sqs)
	default:
		client, stop := audit.NewLines(w).Mount()
		return client, stop, nil
	}
}

// openAudit is the emitter of truvity/audit over the transport port (decisions 0023 and 0024), with the seal block's pseudonyms.
func openAudit(a *app, f serveFlags, cfg aws.Config, sf *site.File, seal *sealer.Sealer) (*audit.Auditor, error) {
	tr, stop, err := auditTransport(f.audit, cfg, os.Stdout)
	if err != nil {
		return nil, err
	}
	a.closers = append(a.closers, stop)
	kind, _ := f.audit.choice()
	switch kind {
	case "socket":
		slog.Info("audit", "transport", "socket", "socket", f.audit.socket)
	case "nats":
		slog.Info("audit", "transport", "nats", "stream", f.audit.nats.Stream, "subject", f.audit.nats.Subject)
	case "sqs":
		slog.Info("audit", "transport", "sqs", "queue", f.audit.sqs)
	default:
		slog.Info("audit", "transport", "lines", "to", "stdout")
	}
	bundle := ""
	if sf.Policy != nil {
		bundle = sf.Policy.Bundle
	}
	return audit.New(audit.Options{Transport: tr, Pseudonyms: seal, Release: version, Scope: auditScope(f.auditScope), Policy: bundle})
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
	a.startRunners(ctx)
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

// startRunners starts the runners beside the servers or the Lambda handler: the policy loader's refresh.
func (a *app) startRunners(ctx context.Context) {
	for _, r := range a.runners {
		go func() {
			if err := r(ctx); err != nil {
				slog.Error("runner", "error", err.Error())
			}
		}()
	}
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
