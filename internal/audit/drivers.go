package audit

import (
	"errors"
	"net/http"
	"os"
	"strings"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/truvity/atoom/common/call"
	"github.com/truvity/atoom/transport/gen/atoom/transport/v1alpha1/transportv1alpha1connect"
	natstransport "github.com/truvity/atoom/transport/nats"
	sqstransport "github.com/truvity/atoom/transport/sqs"

	"github.com/truvity/session/internal/atoomx"
)

// Emitter is the name session gives itself to an in-process transport driver (the header Atoom-Emitter of NATS, the message
// attribute atoom-emitter of SQS): the product, as the audit writer knows it.
const Emitter = Product

// NATSConsumer is the durable consumer name the NATS driver's options require. session only emits, and an emit never reads it
// (atoom's transport/nats: Emit publishes to the subject); the consumer is the writer's, made by the deployment.
const NATSConsumer = "session-emits-only"

// NATSOptions are the host's side of the NATS JetStream driver: the connection and its credentials, and the stream and subject the
// deployment made. atoom's driver knows none of it; session is given it at start-up.
type NATSOptions struct {
	// URL is the NATS server or servers, comma separated.
	URL string
	// Stream is the JetStream stream of the log; Subject is the subject an emit publishes to, which the stream captures.
	Stream, Subject string
	// Creds is a NATS credentials file (a user JWT and its seed); TokenFile a file that holds a token, read at every connect.
	// At most one of the two.
	Creds, TokenFile string
	// TLSCA is a PEM file of the CAs that sign the server's certificate.
	TLSCA string
}

// NATS dials NATS and mounts atoom's Go transport/nats driver in this process over that connection, emit side only: the driver
// makes no stream or consumer (Create off), so the deployment's user needs only to publish on the subject and STREAM.INFO.
// The connection retries in the background, also at start: while NATS is down an emit fails (a sign-in fails closed, every other
// event is lost and counted) and the check goes on. stop stops the driver and closes the connection.
func NATS(o NATSOptions) (transportv1alpha1connect.TransportServiceClient, func(), error) {
	switch {
	case o.URL == "" || o.Stream == "" || o.Subject == "":
		return nil, nil, errors.New("audit: the NATS URL, stream and subject are required")
	case o.Creds != "" && o.TokenFile != "":
		return nil, nil, errors.New("audit: a NATS credentials file and a token file are exclusive")
	}
	copts := []natsgo.Option{natsgo.Name("session"), natsgo.MaxReconnects(-1), natsgo.RetryOnFailedConnect(true)}
	switch {
	case o.Creds != "":
		copts = append(copts, natsgo.UserCredentials(o.Creds))
	case o.TokenFile != "":
		// Read at every connect, so that a token the deployment renews is the current one.
		path := o.TokenFile
		copts = append(copts, natsgo.TokenHandler(func() string {
			b, err := os.ReadFile(path) //nolint:gosec // the path is the operator's flag
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(b))
		}))
	}
	if o.TLSCA != "" {
		copts = append(copts, natsgo.RootCAs(o.TLSCA))
	}
	nc, err := natsgo.Connect(o.URL, copts...)
	if err != nil {
		return nil, nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	svc, err := natstransport.New(natstransport.Options{JetStream: js, Stream: o.Stream, Subject: o.Subject, Consumer: NATSConsumer, Emitter: Emitter})
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	client, stop := mount(svc.Handler())
	return client, func() { stop(); nc.Close() }, nil
}

// SQS mounts atoom's Go transport/sqs driver in this process over the given client and FIFO queue (a Lambda function, which has no
// spool sidecar, decision 0030). The queue is the deployment's; the driver makes nothing and refuses a queue that is not FIFO.
func SQS(api sqstransport.API, queueURL string) (transportv1alpha1connect.TransportServiceClient, func(), error) {
	svc, err := sqstransport.New(sqstransport.Options{SQS: api, QueueURL: queueURL, Emitter: Emitter})
	if err != nil {
		return nil, nil, err
	}
	client, stop := mount(svc.Handler())
	return client, stop, nil
}

func mount(path string, h http.Handler) (transportv1alpha1connect.TransportServiceClient, func()) {
	hc, stop := atoomx.Mount(path, h)
	return transportv1alpha1connect.NewTransportServiceClient(hc, "http://transport", call.ClientOptions()...), stop
}
