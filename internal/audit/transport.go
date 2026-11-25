package audit

import (
	"context"
	"io"
	"sync"

	"connectrpc.com/connect"

	"github.com/truvity/atoom/common/call"
	"github.com/truvity/atoom/common/refusal"
	"github.com/truvity/atoom/socket"
	transportv1 "github.com/truvity/atoom/transport/gen/atoom/transport/v1alpha1"
	"github.com/truvity/atoom/transport/gen/atoom/transport/v1alpha1/transportv1alpha1connect"
)

// Socket is the client of a transport driver that serves the emit side of the port on the UNIX socket at path (atoom's
// transport-spool: DIR/emit.sock), the way to the audit writer of the environment. Nothing is dialled until the first emit.
func Socket(path string) transportv1alpha1connect.TransportServiceClient {
	return transportv1alpha1connect.NewTransportServiceClient(socket.Client(path), "http://transport", call.ClientOptions()...)
}

// Lines is a transport driver in this process for a run without a writer (development and the tests): it writes the record of
// each message, canonical JSON, as one line to w, and serves nothing to a consumer. A write that fails is an emit that failed.
type Lines struct {
	transportv1alpha1connect.UnimplementedTransportServiceHandler
	mu sync.Mutex
	w  io.Writer
}

// NewLines returns the driver over w.
func NewLines(w io.Writer) *Lines { return &Lines{w: w} }

// Emit writes the record as one line. The contract's refusals of an empty message hold.
func (l *Lines) Emit(_ context.Context, req *connect.Request[transportv1.EmitRequest]) (*connect.Response[transportv1.EmitResponse], error) {
	m := req.Msg.GetMessage()
	switch {
	case m == nil:
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "message")
	case m.GetUid() == "":
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "message.uid")
	case len(m.GetRecord()) == 0:
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "message.record")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(append(append([]byte(nil), m.GetRecord()...), '\n')); err != nil {
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	}
	return connect.NewResponse(&transportv1.EmitResponse{}), nil
}

// Mount mounts the driver in this process and returns its client and the function that stops it.
func (l *Lines) Mount() (transportv1alpha1connect.TransportServiceClient, func()) {
	return mount(transportv1alpha1connect.NewTransportServiceHandler(l))
}
