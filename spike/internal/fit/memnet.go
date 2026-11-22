// Package fit is throwaway spike code for the fit spike (2026-11-22): the first spike's check path on
// atoom's ports, called through their generated ConnectRPC clients with the drivers in the same process.
package fit

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/truvity/atoom/common/call"
)

// memListener is a net.Listener whose connections are net.Pipe pairs: the in-process transport of
// atoom's socket/docs/in-process.md (the Go way), copied from the tested code in source/file/memnet_test.go.
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

// Mount serves h at path on an in-memory transport and returns the http.Client that reaches it and a stop function.
// call.Inherit puts the correlation id of the request in the context of the handler. The Connect handler reads
// the deadline of the caller (Connect-Timeout-Ms) on its own.
func Mount(path string, h http.Handler) (*http.Client, func()) {
	l := &memListener{conns: make(chan net.Conn), done: make(chan struct{})}
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := &http.Server{Handler: call.Inherit(mux), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(l) }()
	return &http.Client{Transport: &http.Transport{DialContext: l.dial, MaxIdleConnsPerHost: 64}}, func() { _ = srv.Close() }
}
