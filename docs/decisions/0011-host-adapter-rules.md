# 0011. Host adapter rules: Envoy, nginx, API Gateway and the store timeout

Status: accepted
Date: 2026-11-21

## Context

The first spike drove Envoy (HTTP and gRPC external authorisation) and nginx (`auth_request`) with one script, and read the API Gateway documentation. The hosts differ in how they strip headers, how they show a deny and which path they give the check. One path-confusion hole was reproduced on nginx. The API Gateway facts come from the AWS documentation, not from a real account.

## Decision

### Envoy

- **gRPC mode is preferred.** The allow answer removes headers with `headers_to_remove`, so a browser-sent `Authorization` or `Cookie` is removed, not left empty. `Set-Cookie` goes in `response_headers_to_add` and may hold several cookies.
- **HTTP mode stays supported**, documented with its limits. An HTTP answer can only set a header empty, so the example adds `request_headers_to_remove` on the route, or the allow answer sets every owned header. `Set-Cookie` needs `allowed_client_headers_on_success`, and a deny answer's `Location` and `Content-Type` need `allowed_client_headers`. A 503 from the check keeps its status but loses its body.
- The example uses the top-level `allowed_headers` (`cookie`, `accept`, `sec-fetch-mode`, `sec-fetch-site`, `origin`). Without `sec-fetch-mode` every navigation becomes a 401, so the conformance suite checks it. The older `authorization_request.allowed_headers` is deprecated in Envoy v1.34.
- `ExtAuthzPerRoute` with `disabled: true` excludes the sign-in prefix.
- The connection manager sets `normalize_path`, `merge_slashes` and `path_with_escaped_slashes_action: REJECT_REQUEST`, so the check gets the path the router uses.
- If the check cannot be reached, Envoy answers with `status_on_error` (503), and `failure_mode_allow` stays false.

### nginx

- `auth_request` accepts only 2xx, 401 and 403 from the check, turns any other status into a 500 and forwards neither a 302 nor a body. The adapter answers 401 with `X-Session-Action` and `X-Session-Location`. A named location makes the 302 for top-level navigations, and nginx writes the JSON `login_required` body itself.
- The check gets the normalised path: `X-Original-URI $uri$is_args$args`, never `$request_uri`. Encoded slashes are rejected.
- Every owned header, `Authorization` and `Cookie` included, is set from an `auth_request_set` variable on every request. An empty variable makes nginx drop the header, so a browser-sent value cannot pass.
- `Set-Cookie` from `auth_request_set` carries only the first cookie.
- Fail closed shows as 500 on nginx, not 503. This is documented, not fought.

### AWS API Gateway

- **Both products are supported:** the REST API `REQUEST` authorizer (also usable on an HTTP API with payload 1.0) and the HTTP API payload 2.0 authorizer with simple responses. The docs and examples default to the HTTP API. The HTTP API event carries the cookies in a separate `cookies` array, and the check joins them before it runs.
- "No session" is the error `Unauthorized`, which API Gateway turns into a 401. A deny policy is a 403 on the REST API and is not used for "no session".
- **The authorizer's result cache is set to 0 seconds explicitly on both products.** The REST API default is 300 seconds when `authorizerResultTtlInSeconds` is not set (maximum 3600, 0 disables). The HTTP API page states no default. The examples and the chart set 0, and the examples carry a test for it. A site may opt in later, with the logout lag documented: the cache key is the identity sources, such as the whole `Cookie` header, so a logout lags by the TTL.
- The authorizer cannot change the request or the response. Only `principalId` and `context` reach the integration, as `$context.authorizer.<key>`. Stripping browser headers (S8) is therefore the integration's parameter mapping, not the allow answer.
- The HTTP API reserves `Authorization` (and `Origin`, `Forwarded`, `X-Forwarded-*`, `Via`, among others) in parameter mapping. The per-API token travels in `X-Session-Token`, and the site ignores a browser-sent `Authorization`.
- A cookie-based identity source makes API Gateway skip the function when no cookie is present (401).
- **The sign-in paths** go to the service over an HTTP integration, or to the same function behind the Web Adapter, for each install. The default is the function where there is no cluster ([0012](0012-lambda.md)). It returns `Set-Cookie` lines in the response `cookies` array.

### All hosts

- The conformance suite sends dot-segment, encoded-dot and merged-slash paths to every host, and checks header stripping and `allowed_headers` on every host. It uses TLS or a real browser, not a Go cookie jar over plain HTTP, because a jar does not send `Secure` cookies over HTTP.
- Every store call has a timeout (the spike used 1.5 s). The proxy's timeout for the check is longer, so the check's own 503 is what the client gets.

Open, to check in a real AWS account: the HTTP API status for `isAuthorized: false`; the HTTP API default cache TTL; parameter mapping from `$context.authorizer.*`, including the non-reserved token header.

## Consequences

- The reproduced hole (`/assets/../private/x` allowed without a session on nginx with `$request_uri`) cannot ship in an example.
- One behaviour for S4 on both API Gateway products: a 401 the browser helper can act on.
- Envoy HTTP mode is a second-class path, kept because some installs cannot use gRPC.
- A 503 body from the check is lost in Envoy HTTP mode, and nginx turns it into 500. The status that matters, a refusal, is the same everywhere.

## Roads not taken

| Road | Why not |
| --- | --- |
| HTTP first for Envoy and gRPC later | HTTP mode alone cannot remove a header, and both modes are needed from the start |
| Only the HTTP integration for the sign-in paths | Needs a reachable service, which a Lambda-only install lacks |
| Only the function for the sign-in paths | No choice for installs that have a cluster |
| An authorizer cache of minutes | The logout lag would be too long |
| Relying on the REST API's default cache setting | The default is on (300 s), not off |
| A deny policy for "no session" | A 403 on the REST API, which the browser helper would not read as "sign in" |
| Stripping headers in the allow answer on API Gateway | Only `principalId` and `context` reach the integration |
