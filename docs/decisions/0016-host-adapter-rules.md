# 0016. Host adapter rules from the spike: Envoy, nginx, normalised paths, store timeout

Status: proposed, coordinator's call 2026-11-18, for review by the maintainers. Amends 0012 Q8 and the host rules of 0003 and 0005. Evidence: docs/spike-2026-11-18.md, section 3.

## Context

The spike drove Envoy (HTTP and gRPC external authorisation) and nginx (`auth_request`) with one script. The hosts differ in how they strip headers, how they show a deny, and which path they give the check. One path-confusion hole was reproduced on nginx.

## Decision

Envoy.

- gRPC mode is preferred: the allow answer removes headers with `headers_to_remove`. HTTP mode stays supported and its example adds `request_headers_to_remove` on the route (an HTTP answer can only set a header empty), or the allow answer sets every owned header.
- The example uses the top-level `allowed_headers` (`cookie`, `accept`, `sec-fetch-mode`, `sec-fetch-site`, `origin`), `allowed_client_headers` and `allowed_client_headers_on_success` in HTTP mode, `ExtAuthzPerRoute` with `disabled: true` for `/_session/`, and `normalize_path`, `merge_slashes` and `path_with_escaped_slashes_action: REJECT_REQUEST`.

nginx.

- The adapter answers 401 with `X-Session-Action` and `X-Session-Location`. nginx makes the 302 for top-level navigations and writes the JSON `login_required` body itself, because `auth_request` forwards neither a 302 nor a body.
- The check gets the normalised path: `X-Original-URI $uri$is_args$args`, never `$request_uri`. Encoded slashes are rejected.
- Every owned header is set from an `auth_request_set` variable on every request.
- Fail closed shows as 500 on nginx, not 503. This is documented, not fought.

All hosts.

- The conformance suite sends dot-segment, encoded-dot and merged-slash paths to every host, and checks header stripping and `allowed_headers` on every host. It uses TLS or a real browser, not a Go cookie jar over plain HTTP.
- The store port takes a timeout for each call (the spike used 1.5 s). The proxy's timeout for the check is longer, so the check's own 503 is what the client gets.

## Consequences

- The reproduced hole (`/assets/../private/x` allowed without a session on nginx with `$request_uri`) cannot ship in an example.
- Envoy HTTP mode is a second-class path, kept because some installs cannot use gRPC.
- A 503 body from the check is lost in Envoy HTTP mode, and nginx turns it into 500. The status that matters, a refusal, is the same everywhere.
