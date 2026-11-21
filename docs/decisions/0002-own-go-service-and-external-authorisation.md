# 0002. Our own Go service, deployed as external authorisation

Status: accepted
Date: 2026-11-18

## Context

We need a component that signs a person in, keeps the session and answers a proxy's check. It must work behind Envoy Gateway, nginx and AWS API Gateway.

The proxy in front of a site must decide, for each request, whether it may pass. `session` can sit in the request path, or the proxy can ask it.

## Decision

**Our own service, in Go.** One service on `coreos/go-oidc`, `golang.org/x/oauth2` and `go-jose`. We write the glue, not the cryptography.

- One check core.
- Adapters for Envoy external authorisation (HTTP and gRPC), nginx `auth_request` and an AWS API Gateway Lambda authorizer.
- Go is the language of the sluis sign-in and exchange code. Its OIDC libraries are mature, and it builds static binaries, which suits Lambda.
- The code of the group SSO reference stand may be reused where it fits ([0013](0013-reference-stand.md)).

**Deployed as external authorisation.** The host proxy asks `session` before each request. The hosts:

- Envoy external authorisation;
- AWS API Gateway Lambda authorizer;
- self-hosted nginx `auth_request`.

An in-path reverse-proxy mode runs the same check and then forwards the request. It exists for sites where one more hop is fine.

## Consequences

- One codebase covers every host. No module's internal format leaks into our design.
- We own the code and its security. The libraries carry the protocol and the crypto.
- Most sites get no extra data-path hop, and the proxy keeps its own routing and limits.
- The check sees only headers, never the body.
- API Gateway's authorizer cannot redirect. It returns 401, and the browser helper starts sign-in.
- The sign-in paths are routed to the service without a check.
- The host must strip browser-sent security headers. The example configs ship this. The rules for each host are in [0011](0011-host-adapter-rules.md).

## Roads not taken

| Road | Why not |
| --- | --- |
| Apache with `mod_auth_openidc`, adapted to checks | Needs a Go exchange hop and a Lambda authorizer that reads the module's internal session format: three pieces, about as much work as our own service |
| Apache in the request path | No API Gateway authorizer; a container for each Lambda-shape site; two hops |
| oauth2-proxy | No API Gateway authorizer; back-channel logout and `private_key_jwt` are doubtful |
| Rust, TypeScript or Envoy Wasm | No advantage that outweighs the shared language and libraries |
| C or C++ | Memory-unsafe on untrusted input |
| `session` always a reverse proxy in the path | An extra hop on every request |
| `session` only a library inside each site | One implementation per site language; no shared behaviour |
