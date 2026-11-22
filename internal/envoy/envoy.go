// Package envoy holds the adapters for Envoy's external authorisation (decision 0011): the gRPC service, which is preferred,
// and the HTTP service. They translate between Envoy and the check core and decide nothing themselves.
//
// gRPC: the allow answer sets headers and removes the owned ones with headers_to_remove, so a browser-sent Authorization or
// Cookie is removed, not left empty; Set-Cookie goes in response_headers_to_add. A deny carries its status, headers and body.
//
// HTTP: the check gets the original method, the path after the service's path prefix and the headers Envoy lets through. An
// allow is a 200 whose headers Envoy copies to the upstream request (allowed_upstream_headers); the headers to remove are
// named in x-envoy-auth-headers-to-remove, which Envoy applies to the upstream request. A deny is its status, Location,
// Content-Type and body (allowed_client_headers); Envoy keeps a 503's status but not its body.
package envoy

import (
	"context"
	"net/http"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/truvity/session/core"
)

// Checker is the check core as the adapters see it.
type Checker interface {
	Check(ctx context.Context, r core.Request) core.Decision
}

// GRPC is the gRPC external authorisation service (envoy.service.auth.v3.Authorization).
type GRPC struct {
	authv3.UnimplementedAuthorizationServer
	Core Checker
}

func header(k, v string, add bool) *corev3.HeaderValueOption {
	act := corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD
	if add {
		act = corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD
	}
	return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: k, Value: v}, AppendAction: act}
}

// Check answers one check request.
func (g *GRPC) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	h := req.GetAttributes().GetRequest().GetHttp()
	hdr := http.Header{}
	for k, v := range h.GetHeaders() {
		if strings.HasPrefix(k, ":") {
			continue // pseudo-headers: the method, path and authority come from their own fields
		}
		hdr.Set(k, v)
	}
	d := g.Core.Check(ctx, core.Request{Method: h.GetMethod(), Host: h.GetHost(), Path: h.GetPath(), Header: hdr})
	if d.Outcome == core.Allow {
		ok := &authv3.OkHttpResponse{HeadersToRemove: d.Remove}
		for k, v := range d.Set {
			ok.Headers = append(ok.Headers, header(k, v, false))
		}
		for _, c := range d.SetCookies {
			ok.ResponseHeadersToAdd = append(ok.ResponseHeadersToAdd, header("set-cookie", c, true))
		}
		return &authv3.CheckResponse{Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: ok}}, nil
	}
	den := &authv3.DeniedHttpResponse{Status: &typev3.HttpStatus{Code: typev3.StatusCode(d.Status)}, Body: string(d.Body)} //nolint:gosec // G115: an HTTP status
	den.Headers = append(den.Headers, header("cache-control", "no-store", false))
	if d.Location != "" {
		den.Headers = append(den.Headers, header("location", d.Location, false))
	}
	if d.ContentType != "" {
		den.Headers = append(den.Headers, header("content-type", d.ContentType, false))
	}
	for _, c := range d.SetCookies {
		den.Headers = append(den.Headers, header("set-cookie", c, true))
	}
	code := codes.PermissionDenied
	if d.Outcome == core.Unavailable {
		code = codes.Unavailable
	}
	return &authv3.CheckResponse{Status: &status.Status{Code: int32(code)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: den}}, nil
}

// HeadersToRemove is the header of an HTTP-mode allow answer that names the upstream request headers Envoy removes.
const HeadersToRemove = "x-envoy-auth-headers-to-remove"

// HTTP is the HTTP external authorisation service. Prefix is the path_prefix of Envoy's http_service.
type HTTP struct {
	Core   Checker
	Prefix string
}

func (a *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.RequestURI()
	if a.Prefix != "" {
		if !strings.HasPrefix(path, a.Prefix) {
			http.NotFound(w, r)
			return
		}
		path = strings.TrimPrefix(path, a.Prefix)
	}
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	d := a.Core.Check(r.Context(), core.Request{Method: r.Method, Host: r.Host, Path: path, Header: r.Header})
	for _, c := range d.SetCookies {
		w.Header().Add("Set-Cookie", c)
	}
	if d.Outcome == core.Allow {
		for k, v := range d.Set {
			w.Header().Set(k, v)
		}
		var remove []string
		for _, k := range d.Remove {
			if _, set := d.Set[k]; !set {
				remove = append(remove, k)
			}
		}
		if len(remove) > 0 {
			w.Header().Set(HeadersToRemove, strings.Join(remove, ","))
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if d.Location != "" {
		w.Header().Set("Location", d.Location)
	}
	if d.ContentType != "" {
		w.Header().Set("Content-Type", d.ContentType)
	}
	w.WriteHeader(d.Status)
	_, _ = w.Write(d.Body)
}
