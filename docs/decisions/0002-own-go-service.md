# 0002. Our own Go service on well-tested libraries

Status: accepted, 2026-11-18 (decision E1, option B, with Go)

## Context

We need a component that signs a person in, keeps the session, and answers a proxy's check. It must work behind Envoy Gateway, nginx and AWS API Gateway.

## Options considered

| Option | For | Against |
| --- | --- | --- |
| A. Apache with `mod_auth_openidc`, adapted to checks | Mature module | Needs a spike. Needs a Go exchange hop and a Lambda authorizer that reads the module's internal session format. Three pieces, about 9 to 11 agent-days |
| A2. Apache in the request path | Proven in a working stand, about 6 to 7 days | No API Gateway authorizer. Containers for each Lambda-shape site. Two hops |
| oauth2-proxy | Widely used | No API Gateway authorizer. Back-channel logout and `private_key_jwt` are doubtful |
| B. Our own service | One check core, all adapters | We write and maintain it |
| Other languages | Rust, C, C++, TypeScript, Envoy Wasm | See below |

Languages: Go is the same language as the sluis session and exchange code. Its OIDC libraries are mature. It builds static binaries, which suits Lambda. C and C++ are rejected as memory-unsafe for untrusted input. Rust, TypeScript and Wasm have no advantage that outweighs the shared language and libraries.

## Decision

B, in Go. A single service on `coreos/go-oidc`, `golang.org/x/oauth2` and `go-jose`.

- One check core.
- Adapters for Envoy external authorisation (HTTP and gRPC), nginx `auth_request`, and an AWS API Gateway Lambda authorizer.
- An in-path reverse-proxy mode.

## Consequences

- One codebase covers every host. No module's internal format leaks into our design.
- We own the code and its security. The libraries carry the protocol and crypto parts.
- Estimated work is comparable to the Apache options, with fewer moving pieces.
