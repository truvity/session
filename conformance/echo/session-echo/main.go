// Command session-echo is the test backend of a deployed conformance site (decision 0029): an HTTP server that answers every
// request with its method, path and headers as JSON (package echo). It is the image ghcr.io/truvity/session-echo.
//
//	session-echo [-listen :8080]
//
// It stops on SIGTERM or SIGINT, letting the requests in flight finish for up to five seconds.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/truvity/session/conformance/echo"
)

func main() {
	listen := flag.String("listen", ":8080", "the address to listen on")
	flag.Parse()
	if err := run(*listen); err != nil {
		fmt.Fprintln(os.Stderr, "session-echo:", err)
		os.Exit(1)
	}
}

func run(listen string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	srv := &http.Server{Addr: listen, Handler: echo.Handler(), ReadHeaderTimeout: 5 * time.Second}
	errs := make(chan error, 1)
	go func() { errs <- srv.ListenAndServe() }()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shut); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
