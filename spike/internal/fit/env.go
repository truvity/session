package fit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/truvity/atoom/common/call"
	storedyn "github.com/truvity/atoom/store/dynamodb"
	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"
)

// Endpoint is DynamoDB Local, as in the first spike.
func Endpoint() string {
	if v := os.Getenv("DDB_ENDPOINT"); v != "" {
		return v
	}
	return "http://127.0.0.1:18000"
}

// NewDynamoAWS returns a client of the real service, with the default credential chain and region (a Lambda function's own).
func NewDynamoAWS(ctx context.Context) (*awsdynamodb.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return awsdynamodb.NewFromConfig(cfg), nil
}

// NewDynamo returns an AWS SDK DynamoDB client for DynamoDB Local with static dummy credentials.
func NewDynamo(ctx context.Context) (*awsdynamodb.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("eu-west-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("x", "x", "")))
	if err != nil {
		return nil, err
	}
	return awsdynamodb.NewFromConfig(cfg, func(o *awsdynamodb.Options) { o.BaseEndpoint = aws.String(Endpoint()) }), nil
}

// Env is the atoom side of the check path: the DynamoDB driver on a counting client, mounted in-process,
// and the generated ItemService client that reaches it.
type Env struct {
	DB    *awsdynamodb.Client
	Count *Counting
	Items storev1alpha1connect.ItemServiceClient
	Store *Store
	Table string
	Stop  func()
}

// NewEnv makes a table of its own on DynamoDB Local (the driver never makes one by itself), mounts the driver in-process
// and returns the generated client. wrap, if not nil, wraps the driver's handler (a test uses it to watch what the driver
// receives).
func NewEnv(ctx context.Context, wrap func(http.Handler) http.Handler) (*Env, error) {
	db, err := NewDynamo(ctx)
	if err != nil {
		return nil, err
	}
	table := fmt.Sprintf("fit-%d", time.Now().UnixNano())
	if err := storedyn.EnsureTable(ctx, db, table); err != nil {
		return nil, err
	}
	return newEnvOn(ctx, db, table, wrap)
}

func newEnvOn(_ context.Context, db *awsdynamodb.Client, table string, wrap func(http.Handler) http.Handler) (*Env, error) {
	cnt := &Counting{In: db}
	svc, err := storedyn.New(storedyn.Options{DynamoDB: cnt, Table: table})
	if err != nil {
		return nil, err
	}
	path, h := svc.Handler()
	if wrap != nil {
		h = wrap(h)
	}
	hc, stop := Mount(path, h)
	items := storev1alpha1connect.NewItemServiceClient(hc, "http://store", call.ClientOptions()...)
	dk := sha256.Sum256([]byte("fit-data-key"))
	hk := sha256.Sum256([]byte("fit-hmac-key"))
	return &Env{DB: db, Count: cnt, Items: items, Table: table, Stop: stop,
		Store: &Store{Items: items, HMACKey: hk[:], DataKey: dk[:], IdleTTL: 30 * time.Minute, MaxTTL: 8 * time.Hour, TouchGap: time.Minute}}, nil
}

// Close stops the transport and drops the table.
func (e *Env) Close(ctx context.Context) {
	e.Stop()
	_, _ = e.DB.DeleteTable(ctx, &awsdynamodb.DeleteTableInput{TableName: &e.Table})
}
