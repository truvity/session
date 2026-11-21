# 0004. The browser session contract

Status: accepted
Date: 2026-11-18

## Context

Every host must give the browser the same session behaviour, whatever the proxy. The rules must be short enough to test, and the same tests must run on every host.

## Decision

One contract, set by the check core and tested by the conformance suite. The ids S1 to S8 are the ones the conformance suite and the examples cite. There is no S7.

| Id | Rule |
| --- | --- |
| S1 | Cookie `__Host-<site>`: an opaque id, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` |
| S2 | Sessions live on the server, sealed, in an atoom store driver ([0006](0006-built-on-atoom.md)). Each site has an idle and a maximum lifetime |
| S3 | Sign-in uses authorisation code with PKCE, always. PAR and `private_key_jwt` are used |
| S4 | A page without a session gets a sign-in redirect. An API call gets a JSON 401. API Gateway's authorizer cannot redirect, so it answers the error `Unauthorized` (a 401, never a deny policy) and the browser helper starts sign-in. nginx makes the redirect and the 401 body itself from a marker in the check's 401 |
| S5 | State-changing requests need CSRF protection: a custom header plus `Origin` and `Sec-Fetch-Site` checks. Headers only, because the check never sees the body |
| S6 | Logout is a POST with CSRF, then the issuer's end-session. Back-channel logout deletes the session for all replicas ([0010](0010-logout-pointer-items.md)) |
| S8 | The browser's `Authorization`, cookies and identity headers are stripped. In external authorisation the host strips them and the allow answer sets them. How each host does it is in [0011](0011-host-adapter-rules.md) |

Defaults:

| Default | Value |
| --- | --- |
| Paths | One prefix, `/_session/`, on every site: `login`, `callback`, `logout`, `backchannel-logout`, `whoami` and `jwks` |
| Store key | A keyed hash of the cookie id, so a store leak gives no usable cookie |
| Record protection | The record is sealed by atoom's `seal` block and bound to its address (the session id and the purpose) as authenticated data ([0006](0006-built-on-atoom.md)) |
| Lifetimes | 30 minutes idle and 8 hours maximum, set for each site. Idle time is refreshed at most once a minute, to keep writes down |
| Site file | YAML |
| Store failure | Fail closed: the answer is 503, never allow |
| No session | A redirect for a top-level navigation (`GET`, `Sec-Fetch-Mode: navigate`, `Accept` includes `text/html`), a JSON 401 for everything else. The 401 body has `error: login_required` and a `login_url`. A route may say `redirect` or `401` to override |
| Sites and hosts | One site per host, because the `__Host-` cookie needs `Path=/` |
| Fixation | A new session id is issued at sign-in |

A site may change the lifetimes. The paths, the fail-closed rule and the cookie rules are not per site.

## Consequences

- One behaviour on Envoy, nginx and API Gateway, checked by the same tests.
- Replicas keep no session state of their own, so logout is immediate on all of them.
- Sites on API Gateway need the browser helper to start sign-in.
- The CSRF rule depends on the host forwarding the headers it needs.
- The design, the conformance suite and the examples can rely on these values.

## Roads not taken

| Road | Why not |
| --- | --- |
| Rules chosen by each adapter | Behaviour would differ by host, and the suite could not test one contract |
| Tokens in cookies, as the Envoy filter does | Any script on the page can steal them |
| A path for each adapter | One prefix is simpler to route and to test |
| The cookie id as the store key | A store leak would give usable cookies |
| Fail open on a store failure | A store outage would let everyone in |
| A flag only, or always 401, for a missing session | Navigations need a redirect, API calls need a body they can act on |
| Path-based sites with a `__Secure-` cookie | Sites would share a cookie scope |
