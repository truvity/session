# 0018. The nginx adapter: the choices of step 3.2

Status: accepted, 2026-11-24 (owner decision on the pull request of step 3.2); partly supersedes [0011](0011-host-adapter-rules.md)
Date: 2026-11-24

Builds the nginx rules of [0011](0011-host-adapter-rules.md), corrects how its `$uri$is_args$args` rule is written, and, if accepted, partly supersedes it: nginx shows a failure of the check as 503, not 500.

## Context

Step 3.2 of the plan builds the nginx adapter: `auth_request` to session's check, with the markers of 0011 and an example configuration that the integration test runs in nginx as it is (`just test-nginx`, nginx 1.30.8). 0011 fixes the shape from the first spike: a 401 with `X-Session-Action` and `X-Session-Location` for the redirect, the normalised path in `X-Original-URI`, every owned header set from an `auth_request_set` variable, one `Set-Cookie`, and a failure shown as 500. The build found one rule that did not hold as written and made choices where 0011 is silent: the refusals other than "no session", the refused exchange's page, and which raw paths nginx refuses.

## Decision

### The path the check sees (corrects how 0011 is written)

- **`$uri` is read in the protected location, not in the check's.** Inside the location of the `auth_request` subrequest, `$uri` is the subrequest's own path (`/_session_check`), not the browser's. The example sets `set $session_uri $uri$is_args$args` in the protected location, before `auth_request`, and the check's location sends `X-Original-URI $session_uri`; the method travels the same way, in `X-Original-Method`. The first spike wrote `$uri$is_args$args` in the check's location, so its check saw the subrequest's path on every request: its "normalised" runs refused the dot-segment cases because every request without a cookie was refused, not because the path was normalised. The integration test now shows the difference: a public route passes without a session only when the check sees the browser's path.
- **nginx passes the site the URI as the browser sent it** (a `proxy_pass` without a URI part), not `$uri`, and `$uri` is decoded, so the two can differ. The example therefore refuses, with `400 {"error":"bad_path"}`, every request whose path (the query is not looked at) has a dot segment, an encoded dot, slash or backslash, or a NUL: exactly the paths the check's own path rule refuses. A browser never sends such a path; Envoy normalises them instead, and nginx cannot do that for the site without decoding the rest of the path. Merged slashes are allowed: merging removes empty segments and cannot move a path from one prefix to another.

### The answers

| Subject | Choice |
| --- | --- |
| The check's listener | Its own address, `session serve --check-nginx` (off by default), with two paths: `/auth`, the check, and `/error-page`, the page of a refused exchange. Any other path is a 404 |
| An allow | A 200 whose headers are the upstream request headers to set (`cookie`, `authorization`, `x-session-identity`) and `Set-Cookie`. The example sets `Cookie`, `Authorization`, `X-Session-Token` and `X-Session-Identity` from them on every request, so an owned header the check removes is dropped |
| Every refusal | A 401 with markers: `X-Session-Action` (`redirect`, `deny` or `page`), `X-Session-Status` (the status of the check's own answer), `X-Session-Location` (a redirect's sign-in address) and `X-Session-Body` (a deny's JSON body, at most 2 KiB, else the error word alone), and `Cache-Control: no-store`. One status from the check, so one `error_page` in the configuration |
| What the browser gets | The named location `@session_answer` makes the check's own answer: a 302 to the relative sign-in address (`absolute_redirect off`), or the status (400, 401, 403, 404, 503) with the check's JSON body, so the bodies are the same as on Envoy. 0011 had nginx write the `login_required` body itself; carrying the check's body keeps one source and also covers `csrf`, `forbidden`, `exchange_refused` and `no_route`. A marker it does not know is a 503 |
| A refused exchange on a navigation | The site's error page (the site file's `error_page`, or the built-in page) with 403. A header cannot carry an HTML page, so `@session_answer` rewrites to an internal location that fetches it from the check's `/error-page`. The page is static: the second request reads nothing from the store |
| `Set-Cookie` | Every cookie of the decision is in the check's answer; nginx passes the first (0011). The check sets a cookie only to clear the session cookie when a refresh ends the session, so one is enough today |
| A check without `X-Original-URI` or `X-Original-Method` | A 500 and an error in the log: a configuration that forgot them would check the subrequest's own path |

### Fail closed shows as 503 (partly supersedes 0011)

0011 says a failure shows as 500 on nginx, "documented, not fought". With the markers it costs nothing to fight:

- A failure inside the check (the store, the key driver, the issuer) is a refusal like the others: `X-Session-Status: 503`, and the browser gets 503 with `{"error":"unavailable"}`.
- A check that cannot be reached, or does not answer within the example's 4 seconds (the store timeout plus the exchange timeout, as on Envoy), makes `auth_request` a 500, which `error_page 500 = @session_unavailable` turns into the same 503. It catches only errors nginx makes itself: the site's own 500 passes as it is, because `proxy_intercept_errors` is off, and the test checks it.

So every host shows a failed check as 503, and the conformance suite needs no case for nginx.

## Consequences

- The nginx example runs in the integration test as it is, like the Envoy one, and CI runs `just test-nginx`.
- A site on nginx copies one `map`, the server's settings and six locations. Every protected location sets `$session_uri` and `$session_method` before `auth_request`; the example says so.
- A request with a dot segment or an encoded dot gets 400 on nginx and 401 or 400 on Envoy. Both refuse it; the conformance suite (step 3.4) accepts either.
- The check's listener for nginx answers with tokens in its headers, as Envoy's HTTP check does: it must be reachable by nginx only (a NetworkPolicy, as for the Envoy check).
- The first spike's nginx findings on path confusion stand as a threat but not as a measurement; the measurement is this test.
- When this record is accepted, 0011's status line names it, as it names 0015.

## Roads not taken

| Road | Why not |
| --- | --- |
| `$uri$is_args$args` in the check's location, as the spike had it | The subrequest's own path; every check of a site sees the same path |
| `proxy_pass` to the site with `$uri` | `$uri` is decoded: `%3F` would reach the site as a query, a space as a broken request line |
| Normalise and pass dot segments, as Envoy does | nginx cannot pass the site a normalised path without decoding it (above); refusing is what the check does with such a path anyway |
| Answer 403 as 403 and only the rest with markers | Two `error_page` branches and two ways to read a refusal, for no gain |
| nginx writes the JSON bodies from the error word | A second copy of the bodies, which would drift from the check's |
| Carry the error page in a header | A header cannot hold an HTML page's line breaks; base64 needs a module stock nginx lacks |
| The site's error page configured in nginx | A second copy of the site file's `error_page` |
| Keep 500 for a failed check (0011) | The markers make 503 free, and one status on every host keeps the conformance suite simple |
| The check on the HTTP listener of Envoy (`--check-http`) | Its answers are Envoy's; a listener of its own keeps the two protocols apart |
