package sess

import (
	"net/http"
	"strings"

	"context"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// ---- HTTP adapter: Envoy ext_authz (http_service) and nginx auth_request ----

// HTTPAdapter serves /check/... . Envoy forwards the original method, path and headers
// (path prefixed). nginx sends a GET subrequest; the original URI is in X-Original-URI.
type HTTPAdapter struct {
	Core   *Core
	Prefix string // "/check"
	// NginxMode: deny is always 401 plus X-Session-Action, since auth_request turns any
	// status but 2xx/401/403 into a 500 and drops the body.
	NginxMode bool
}

func (a *HTTPAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.RequestURI(), a.Prefix)
	method := r.Method
	if o := r.Header.Get("X-Original-URI"); o != "" {
		path = o
		method = r.Header.Get("X-Original-Method")
	}
	d := a.Core.Check(r.Context(), Request{Method: method, Host: r.Host, Path: path, Header: r.Header})
	for _, c := range d.SetCookies {
		w.Header().Add("Set-Cookie", c)
	}
	switch d.Kind {
	case Allow:
		for k, v := range d.Set {
			w.Header().Set(k, v)
		}
		// Header removal has no wire form in HTTP mode. An empty value is the closest thing:
		// the spike checks what Envoy and nginx do with it.
		for _, k := range d.Remove {
			if _, set := d.Set[k]; !set {
				w.Header().Set(k, "")
			}
		}
		w.WriteHeader(200)
	case Redirect:
		if a.NginxMode {
			w.Header().Set("X-Session-Action", "redirect")
			w.Header().Set("X-Session-Location", d.Location)
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Location", d.Location)
		w.WriteHeader(d.Status)
	default:
		if a.NginxMode {
			w.Header().Set("X-Session-Action", "deny")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(d.Status)
		w.Write(d.Body)
	}
}

// ---- gRPC adapter: Envoy ext_authz ----

type GRPC struct {
	authv3.UnimplementedAuthorizationServer
	Core *Core
}

func (g *GRPC) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	h := req.GetAttributes().GetRequest().GetHttp()
	hdr := http.Header{}
	for k, v := range h.GetHeaders() {
		hdr.Set(k, v)
	}
	d := g.Core.Check(ctx, Request{Method: h.GetMethod(), Host: h.GetHost(), Path: h.GetPath(), Header: hdr})
	hv := func(k, v string, appendIt bool) *corev3.HeaderValueOption {
		act := corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD
		if appendIt {
			act = corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD
		}
		return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: k, Value: v}, AppendAction: act}
	}
	switch d.Kind {
	case Allow:
		ok := &authv3.OkHttpResponse{}
		for k, v := range d.Set {
			ok.Headers = append(ok.Headers, hv(k, v, false))
		}
		ok.HeadersToRemove = d.Remove
		for _, c := range d.SetCookies {
			ok.ResponseHeadersToAdd = append(ok.ResponseHeadersToAdd, hv("set-cookie", c, true))
		}
		return &authv3.CheckResponse{Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: ok}}, nil
	default:
		den := &authv3.DeniedHttpResponse{Status: &typev3.HttpStatus{Code: typev3.StatusCode(d.Status)}, Body: string(d.Body)}
		if d.Location != "" {
			den.Headers = append(den.Headers, hv("location", d.Location, false))
		} else if len(d.Body) > 0 {
			den.Headers = append(den.Headers, hv("content-type", "application/json", false))
		}
		return &authv3.CheckResponse{Status: &status.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: den}}, nil
	}
}
