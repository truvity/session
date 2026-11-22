// Package atoomx mounts atoom drivers in this process. Every port is called through its generated ConnectRPC client, also when
// the driver runs here (decision 0006): the driver's handler is served on an in-memory transport and the client dials it. atoom
// ships no Go helper for this (socket/docs/in-process.md, "No Go helper is provided"), so the transport is the few lines of that
// page, as tested in atoom's source/file/memnet_test.go.
package atoomx

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/truvity/atoom/common/call"
)

type memListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

type memAddr struct{}

func (memAddr) Network() string { return "mem" }
func (memAddr) String() string  { return "mem" }

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *memListener) Addr() net.Addr { return memAddr{} }

func (l *memListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Mount serves h at path on an in-memory transport. It returns the http.Client that reaches it and a function that stops it.
// call.Inherit gives the handler the correlation id of the call; the Connect handler reads the caller's deadline on its own.
func Mount(path string, h http.Handler) (*http.Client, func()) {
	l := &memListener{conns: make(chan net.Conn), done: make(chan struct{})}
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := &http.Server{Handler: call.Inherit(mux), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(l) }()
	hc := &http.Client{Transport: &http.Transport{DialContext: l.dial, MaxIdleConnsPerHost: 64}}
	return hc, func() { _ = srv.Close() }
}
