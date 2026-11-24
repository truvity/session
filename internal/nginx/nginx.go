// Package nginx holds the adapter for nginx's auth_request (decisions 0011 and 0018). It translates between nginx and the check
// core and decides nothing itself.
//
// nginx sends the check a subrequest without a body: the original method in X-Original-Method, the normalised path with its
// query in X-Original-URI ($uri$is_args$args, never $request_uri), the host in Host and the browser's headers as they came.
//
// auth_request takes only a 2xx, a 401 or a 403 from the check: any other status becomes a 500, and neither a body nor a
// Location reaches the browser. So:
//
//   - An allow is a 200 whose headers are the upstream request headers to set (cookie, authorization, x-session-identity),
//     and Set-Cookie. nginx reads each with auth_request_set and sets every owned header on every request; an empty variable
//     makes nginx drop the header, which is how a header the check removes is removed.
//   - Every other answer is a 401 with markers, which a named location of the nginx configuration turns into the answer:
//     X-Session-Action (redirect, deny or page), X-Session-Status (the status of the check's answer), X-Session-Location (the
//     sign-in address of a redirect) and X-Session-Body (the JSON body of a deny). A page is the site's error page for a
//     navigation whose exchange was refused: nginx fetches it from PathErrorPage, because a header cannot carry it.
package nginx

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/truvity/session/core"
)

// Checker is the check core as the adapter sees it.
type Checker interface {
	Check(ctx context.Context, r core.Request) core.Decision
}

// The request headers nginx sets on the subrequest, and the markers of a 401.
const (
	HeaderURI    = "X-Original-URI"
	HeaderMethod = "X-Original-Method"

	HeaderAction   = "X-Session-Action"
	HeaderStatus   = "X-Session-Status"
	HeaderLocation = "X-Session-Location"
	HeaderBody     = "X-Session-Body"
)

// The values of X-Session-Action.
const (
	ActionRedirect = "redirect" // a 302 to X-Session-Location
	ActionDeny     = "deny"     // X-Session-Status with the JSON body X-Session-Body
	ActionPage     = "page"     // X-Session-Status with the page at PathErrorPage
)

// The paths of the adapter's listener.
const (
	PathCheck     = "/auth"
	PathErrorPage = "/error-page"
)

// maxBody bounds the JSON body carried in a header. The check's bodies are a few dozen bytes; a longer one is replaced by the
// error word alone, so the header stays short and the body stays JSON.
const maxBody = 2048

// Handler serves nginx's auth_request subrequests at PathCheck, and the site's error page at PathErrorPage.
type Handler struct {
	Core Checker
	// ErrorPage is the HTML page a navigation gets when the issuer refuses the exchange of its route (the core's
	// Rules().ErrorPage: the site file's error_page, or the built-in page).
	ErrorPage []byte
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case PathCheck:
		h.check(w, r)
	case PathErrorPage:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(h.ErrorPage)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	path, method := r.Header.Get(HeaderURI), r.Header.Get(HeaderMethod)
	if path == "" || method == "" {
		// A configuration without the headers would check the subrequest's own path. Refuse, never guess: nginx shows it as 500.
		slog.Error("nginx: a check without " + HeaderURI + " or " + HeaderMethod + "; is proxy_set_header missing?")
		http.Error(w, "the check needs "+HeaderURI+" and "+HeaderMethod, http.StatusInternalServerError)
		return
	}
	hdr := r.Header.Clone()
	hdr.Del(HeaderURI)
	hdr.Del(HeaderMethod)
	d := h.Core.Check(r.Context(), core.Request{Method: method, Host: r.Host, Path: path, Header: hdr})
	// auth_request_set reads one value of a header: the first cookie, when there are several (decision 0011).
	for _, c := range d.SetCookies {
		w.Header().Add("Set-Cookie", c)
	}
	if d.Outcome == core.Allow {
		for k, v := range d.Set {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(HeaderStatus, strconv.Itoa(d.Status))
	switch {
	case d.Outcome == core.Redirect:
		w.Header().Set(HeaderAction, ActionRedirect)
		w.Header().Set(HeaderLocation, d.Location)
	case d.ContentType == "application/json":
		w.Header().Set(HeaderAction, ActionDeny)
		body := string(d.Body)
		if len(body) > maxBody {
			body = `{"error":` + strconv.Quote(d.Reason) + `}`
		}
		w.Header().Set(HeaderBody, body)
	default:
		w.Header().Set(HeaderAction, ActionPage)
	}
	w.WriteHeader(http.StatusUnauthorized)
}
