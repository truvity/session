# 0020. The conformance suite: the choices of step 3.4

Status: accepted, 2026-11-24 (owner decision on the pull request of step 3.4)
Date: 2026-11-24

Builds the conformance suite that [0004](0004-browser-session-contract.md), [0011](0011-host-adapter-rules.md) and design section 14 call for, for the hosts that run without AWS.

## Context

Step 3.4 of the plan is a headless browser through the real flows on every host. The integration tests of steps 2 to 3.3 drive each adapter with Go's HTTP client, on a test double of the check (`just test-envoy`, `just test-nginx`) or on the sign-in handler alone (`just test-keycloak`). None of them runs a browser through a host proxy against a real issuer. 0011 says the suite uses TLS or a real browser, sends the bad paths to every host, and checks header stripping on every host; 0018 says it accepts each host's answer to a bad path. Where the records are silent, the build chose.

## Decision

### The browser

| Subject | Choice |
| --- | --- |
| The tool | chromedp (Go, v0.22.0) driving Chromium's headless shell over the DevTools protocol |
| Where the browser runs | The image `chromedp/headless-shell` (157.0.8103.27, a stable Chromium), pinned by digest in the Justfile, in a container on the host network, removed at the end |
| One profile per host | Each host gets a new browser context, so no cookie of one host's run reaches the next |
| Names | The browser maps `docs.example.test` to the loopback (`--host-resolver-rules`), so the site's cookies and Keycloak's (at `127.0.0.1`) are apart |

### The stand of each host

| Subject | Choice |
| --- | --- |
| The proxy | The example configuration as it is (`examples/envoy/envoy.yaml`, `examples/nginx/nginx.conf`), with the addresses filled in, in the image the integration tests pin |
| TLS | A TLS front in the test process (`https://docs.example.test:PORT`, a test certificate the browser is told to accept) passes each request on to the proxy's plain listener as it came, `Host` included. In an install TLS ends at the proxy or at a load balancer in front of it; the front stands for that. The `__Host-` cookie is `Secure`, and the CSRF rule compares `Origin` with `https://<host>`, so the browser must be on HTTPS |
| session | Assembled in the test process as `session serve` does: the sign-in paths, the check on its three listeners, Keycloak's exchange and refresh, key files, and the in-process store double, so the suite can take the store down |
| The issuer | The test Keycloak 26.8.1 of `just test-keycloak`, one realm per host. Its back-channel logout goes to the proxy's plain listener, through the sign-in prefix |
| Containers | Keycloak and the browser for the whole run; the proxy of one host at a time |

### The scenarios

The same steps, in order, on Envoy over gRPC, Envoy over HTTP and nginx: a public route and the JSON 401 without a session; the sign-in redirect, Keycloak's form and the callback, with the S1 cookie read from the browser; a protected route, with forged owned headers and another cookie, and what the site gets (S8); the sign-in prefix (`whoami`, `jwks`) without a check; CSRF with and without the header, Origin and Sec-Fetch-Site set by the browser (S5); the exchange route (the token verified against the realm, audience `billing`) and the identity-header route (verified with `/_session/jwks` fetched through the host); a refused exchange, JSON to a fetch and the error page to a navigation; a store outage; the bad paths; the logout with and without CSRF, then Keycloak's end-session and its form again (S6); back-channel logout; and a session Keycloak ended without a back-channel call, which ends at its next refresh with the cookie cleared by the check's own `Set-Cookie`.

### What each host answers differently, by design

| Case | Envoy gRPC | Envoy HTTP | nginx |
| --- | --- | --- | --- |
| Store outage | 503 `{"error":"unavailable"}` | 503, empty body (0011) | 503 `{"error":"unavailable"}` (0018) |
| `/assets/../app/x`, `/./app/x`, `/assets/%2e%2e/app/x` (no session) | Normalised; the check sees `/app/x`: 401 `login_required` | as gRPC | 400 `{"error":"bad_path"}` (0018) |
| `/assets%2F..%2Fapp/x`, `/assets/%5c../app/x` | 400 from Envoy, empty body (`path_with_escaped_slashes_action`) | as gRPC | 400 `{"error":"bad_path"}` |
| `//assets//app.js` | 200; the site gets `/assets/app.js` | as gRPC | 200; the site gets `//assets//app.js` (nginx passes the URI as sent) |
| The check's `Set-Cookie` | Every cookie | Every cookie | The first only (0011); the check sets one today, so the cleared cookie arrives on every host |

### Bad paths outside the browser

A browser removes dot segments, decodes `%2e` and never sends a path it has not normalised, so the bad paths cannot come from it. The suite sends them with Go's client, which sends a path exactly as given, to the proxy's plain listener, with the site's `Host`. Everything else goes through the browser.

### Not in this suite

- **API Gateway and the Lambda authorizer.** The authorizer is not built (step 5), and API Gateway itself does not run without AWS: an emulator runs the function, not API Gateway's reading of its answer, its cache or its parameter mapping. The suite's scenarios run on it as part of the real-AWS check of step 5, with the open points of 0011.
- **A test sluis.** Design section 14 names one; sluis v2 has neither PAR nor `private_key_jwt` yet (section 12). The suite takes an issuer URL and will run against sluis v2 at step 6.
- Scenarios of design section 14 that wait for later work: back-channel logout across two replicas (one session service per host today; two need a shared store, DynamoDB Local, in the stand), session expiry in the browser, and policy decisions (no signed bundle until atoom's loader). Step-up (`passMaxAge`, a Keycloak finding of [0013](0013-reference-stand.md)) waits for step-up itself. The reference stand's own browser scenarios are not copied in: the suite's steps cover the ones the contract names.

## Consequences

- CI gains one job, `conformance`, beside the integration job; `just check` runs it.
- A change to an example configuration is checked in a browser on every host, not only by the adapter's own test.
- A difference between hosts is a row of the suite's table, so a new difference shows as a failure, not as a skip.
- `go.mod` gains chromedp and its protocol package, used by the tests only.

## Roads not taken

| Road | Why not |
| --- | --- |
| Playwright | Node or a driver that downloads its browsers at run time; chromedp is Go, like the rest of the tests, and the browser is one image pinned by digest |
| A browser from the devbox | A Chromium build per platform in the devbox, and the repo's other test services are containers |
| Go's cookie jar instead of a browser | A jar sets no `Origin` or `Sec-Fetch-*` and keeps no cookie attributes; 0011 asks for a real browser |
| TLS on the proxies' listeners | The examples would differ from what the integration tests run, and each host's TLS settings would be tested instead of the session rules |
| Plain HTTP with Chromium's localhost exception | `Origin` would be `http://`, which the CSRF rule refuses |
| One stand for all hosts | One realm and one host name for three proxies; a cookie of one run would reach the next |
| Skip a case where a host differs | 0018 asks for each host's answer to be accepted, and a skip hides a change |
