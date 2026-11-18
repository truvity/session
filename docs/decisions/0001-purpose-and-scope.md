# 0001. Purpose and scope

Status: accepted, 2026-11-18

## Context

Envoy Gateway's OIDC filter keeps the tokens in browser cookies. Tokens in the browser can be stolen by any script that runs on the page, and one token works for every API behind the site. We want the browser to hold nothing but a session id.

sluis is our issuer. It already signs people in. It does not keep a website's browser session.

## Options considered

| Option | Meaning |
| --- | --- |
| A | Keep Envoy Gateway's OIDC filter |
| B | A relying-party component that keeps the session on the server |
| C | Add website sessions to the sluis issuer core |

## Decision

B. `session` is a relying-party component that keeps a website's browser session on the server after the issuer signed the person in.

- It replaces Envoy Gateway's OIDC filter.
- It replaces no part of the sluis issuer core. sluis is its issuer.

## Consequences

- Tokens stay on the server. The browser holds an opaque cookie.
- The issuer stays small. Website sessions are a client concern.
- We own one more service to run and secure.
- Sites that use the Envoy filter today must move to the check (see 0003).
