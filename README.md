# session

Browser sessions for websites behind Envoy Gateway, nginx or AWS API Gateway.

`session` is an OIDC client that keeps a website's browser session on the server and answers "may this request pass?" for the proxy in front of the site (external authorisation: Envoy `ext_authz`, nginx `auth_request`, an API Gateway Lambda authorizer). It can also run in the request path as a reverse proxy.

It is a Go service built on [atoom](https://github.com/truvity/atoom): its stores, keys, sealing and configuration come from atoom's ports, drivers and blocks. Who may reach a route is decided by Cedar, as a library. Its security-audit events go to [audit](https://github.com/truvity/audit). It never emits usage records.

Status: being built (step 2 of the [plan](docs/design.md#16-status-and-next-steps)). `core/` is the session core, the block of [0009](docs/decisions/0009-session-core-block.md). `spike/` holds throwaway prototype code from the first spike and the fit spike.

## Layout

| Path | Content |
| --- | --- |
| `core/` | The session core: records, cookie, idle and absolute expiry, logout pointers and tombstones, the check |
| `cmd/session` | The service: `session serve`, `session check --site FILE`, `session seal-root FILE` |
| `internal/signin` | The sign-in handler: login (PAR, PKCE, `private_key_jwt` through the key port), callback, logout, back-channel logout, whoami, jwks |
| `internal/audit` | The stand-in for truvity/audit's emitter: security events as JSON lines |
| `internal/kctest` | The test Keycloak: realms through the admin API, a browser at the login form |
| `internal/envoy` | The Envoy adapters: gRPC (`envoy.service.auth.v3.Authorization`, preferred) and HTTP external authorisation |
| `examples/` | A site file and a policy bundle; `envoy/envoy.yaml`, the Envoy configuration the tests run; `envoy-gateway/`, the same rules in Envoy Gateway's API (not run) |
| `internal/atoomx` | atoom's drivers mounted in this process, called through their generated clients |
| `internal/localseal` | The stand-in for atoom's `seal` block, behind the core's `Sealer` interface |
| `internal/policy` | The Cedar route policy ([docs/policy.md](docs/policy.md)) |
| `internal/site` | The site file |
| `internal/storetest` | A test double of the store port (atoom's memory store driver is Rust only) |

## Building

Inside `devbox shell` (or `devbox run -- just <recipe>`): `just build`, `just test` (no container), `just test-dynamodb` (the core on atoom's `store/dynamodb` driver against DynamoDB Local), `just test-keycloak` (the sign-in handler against Keycloak 26.8), `just test-envoy` (the adapters through Envoy 1.39; all in containers pinned by digest and removed at the end), `just lint`, `just vuln`, and `just check` for all of them.

atoom is pinned to its release 0.3.0 in `go.mod`; an upgrade is a deliberate bump (decision 0006).

## Documents

- [Design](docs/design.md): purpose, behaviour contract, flows, the use of atoom, site file, repository contents, threat model, next steps and open questions.
- [Decision records](docs/decisions/README.md): 13 records, one for each subject, with the table that maps the old numbers.
- [Fit spike](docs/spike-2026-11-22.md): the check core on atoom drivers in-process, authorizer events through the Lambda Web Adapter, and the script for the real-AWS checks.
- [Archive](docs/archive/): the findings of the first spike and its run notes. Superseded records are in [docs/decisions/archive](docs/decisions/archive/).
- [spike/](spike/): the throwaway prototype of the first spike and the code of the fit spike.

## Licence

MIT. See [LICENSE](LICENSE).
