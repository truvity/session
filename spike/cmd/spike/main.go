// spike is the throwaway check service: sign-in, session store, and the HTTP and gRPC check adapters.
package main

import (
	"context"
	"crypto/sha256"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"

	"github.com/truvity/session/spike/internal/sess"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("eu-west-1"))
	if err != nil {
		log.Fatal(err)
	}
	db := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(env("DDB_ENDPOINT", "http://127.0.0.1:18000")) })
	table := env("TABLE", "sessions")
	if err := sess.EnsureTable(ctx, db, table); err != nil {
		log.Fatal(err)
	}
	// throwaway keys, derived from a fixed string so restarts keep sessions readable
	dk := sha256.Sum256([]byte("spike-data-key"))
	hk := sha256.Sum256([]byte("spike-hmac-key"))
	consist, _ := strconv.ParseBool(env("CONSISTENT", "true"))
	tomb, _ := strconv.ParseBool(env("TOMBSTONES", "true"))
	store := &sess.Store{DB: db, Table: table, HMACKey: hk[:], DataKey: dk[:], Consist: consist,
		IdleTTL: 30 * time.Minute, MaxTTL: 8 * time.Hour, TouchGap: time.Minute}
	core := &sess.Core{Store: store, CookieName: "__Host-spike", Tombstones: tomb}

	key, err := sess.LoadKey(env("CLIENT_KEY", "client-key.pem"))
	if err != nil {
		log.Fatal(err)
	}
	flow, err := sess.NewFlow(ctx, core, env("ISSUER", "http://127.0.0.1:18080/realms/spike"), "session-spike",
		env("SITE_URL", "http://127.0.0.1:18081")+"/_session/callback", key)
	if err != nil {
		log.Fatal(err)
	}
	flow.UsePAR, _ = strconv.ParseBool(env("PAR", "true"))

	mux := http.NewServeMux()
	flow.Routes(mux)
	mux.Handle("/check/", &sess.HTTPAdapter{Core: core, Prefix: "/check"})
	mux.Handle("/nginx/", &sess.HTTPAdapter{Core: core, Prefix: "/nginx", NginxMode: true})

	lis, err := net.Listen("tcp", env("GRPC_ADDR", "127.0.0.1:18091"))
	if err != nil {
		log.Fatal(err)
	}
	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, &sess.GRPC{Core: core})
	go func() { log.Fatal(gs.Serve(lis)) }()
	log.Printf("spike up: http %s grpc %s consistent=%v tombstones=%v par=%v", env("HTTP_ADDR", "127.0.0.1:18090"), lis.Addr(), consist, tomb, flow.UsePAR)
	log.Fatal(http.ListenAndServe(env("HTTP_ADDR", "127.0.0.1:18090"), mux))
}
