# 0005. Browser session behaviour contract

Status: accepted, 2026-11-18 (decision E3)

## Context

Every host must give the browser the same session behaviour, whatever the proxy. The rules must be short enough to test.

## Options considered

| Option | Meaning |
| --- | --- |
| A | Rules chosen by each adapter |
| B | One contract, set by the check core, tested by the conformance suite |
| C | Tokens in cookies, as the Envoy filter does |

## Decision

B. The contract:

| Id | Rule |
| --- | --- |
| S1 | Cookie `__Host-<site>`, opaque id, `Secure`, `HttpOnly`, `SameSite=Lax` |
| S2 | Sessions live on the server, encrypted, in Valkey (DynamoDB for API Gateway installs). Idle and maximum lifetimes for each site |
| S3 | Authorisation code with PKCE always. PAR and `private_key_jwt` are used (E7 B: issuers have them) |
| S4 | A page without a session gets a sign-in redirect. An API call gets a JSON 401. API Gateway's authorizer cannot redirect, so it returns 401 and the browser helper starts sign-in |
| S5 | CSRF on state-changing requests: a custom header plus `Origin` and `Sec-Fetch-Site` checks. Headers only, because the check never sees the body |
| S6 | Logout is a POST with CSRF, then the issuer's end-session. Back-channel logout deletes the session for all replicas |
| S8 | The browser's `Authorization`, cookies and identity headers are stripped. In external authorisation the host strips them and the allow answer sets them. The example configs ship this |

## Consequences

- One behaviour on Envoy, nginx and API Gateway, checked by the same tests.
- Replicas keep no session state of their own, so logout is immediate on all of them.
- Sites on API Gateway need the browser helper to start sign-in.
- The CSRF rule depends on the host forwarding the headers it needs.
