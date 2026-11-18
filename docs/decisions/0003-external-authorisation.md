# 0003. Deployment is external authorisation

Status: accepted, 2026-11-18 (decision E6, option C)

## Context

The proxy in front of a site must decide, for each request, whether it may pass. `session` can be in the request path, or the proxy can ask it.

## Options considered

| Option | Meaning |
| --- | --- |
| A | `session` is always a reverse proxy in the path |
| B | `session` is only a library inside each site |
| C | External authorisation: the host proxy asks before each request. An in-path mode exists for some sites |

## Decision

C. The host proxy asks `session` before each request.

Hosts:

- Envoy external authorisation
- AWS API Gateway Lambda authorizer
- self-hosted nginx `auth_request`

The in-path mode exists for sites where a hop is fine.

## Consequences

- No extra data-path hop for most sites. The proxy keeps its own routing and limits.
- The check sees only headers, never the body.
- API Gateway's authorizer cannot redirect. It returns 401 and the browser helper starts sign-in.
- The sign-in paths are routed to the service without a check.
- The host must strip browser-sent security headers. The example configs ship this.
