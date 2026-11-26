# session

Browser sessions for websites behind Envoy Gateway, nginx or AWS API Gateway.

`session` is an OIDC client, of one issuer or several per site, that keeps a website's browser session on the server and answers "may this request pass?" for the proxy in front of the site (external authorisation: Envoy `ext_authz`, nginx `auth_request`, an API Gateway Lambda authorizer). It can also run in the request path as a reverse proxy.

It is a Go service built on [atoom](https://github.com/truvity/atoom): its stores, keys, sealing and configuration come from atoom's ports, drivers and blocks. Who may reach a route is decided by Cedar, as a library. Its security-audit events go to [audit](https://github.com/truvity/audit). It never emits usage records.

Status: being built (step 3 of the [plan](docs/design.md#16-status-and-next-steps): the exchange client, the identity header, the nginx adapter, the signing keys on AWS KMS, the conformance suite and the move to atoom 0.5.0's policy loader and seal block are built; the first version is next). `core/` is the session core, the block of [0009](docs/decisions/0009-session-core-block.md). `spike/` holds throwaway prototype code from the first spike and the fit spike.

## Layout

| Path | Content |
| --- | --- |
| `core/` | The session core: records, cookie, idle and absolute expiry, logout pointers and tombstones, the exchange cache and lock, the identity header, the check |
| `cmd/session` | The service: `session serve`, `session check --site FILE`, `session catalogue` (the payload of session's audit catalogue) |
| `internal/signin` | The sign-in handler: the sign-in page of a site of several issuers, login (PAR, PKCE, `private_key_jwt` through the key port) at the issuer chosen, callback, logout, back-channel logout, whoami, jwks; the JWT signer over the key port |
| `internal/audit` | truvity/audit's emitter over atoom's transport port: session's action table, the pseudonyms, the transport client and a local driver of JSON lines, and the catalogue made from the table |
| `deploy/audit/audit-catalogue.json` | session's committed audit catalogue for the release 0.0.0; `just check-catalogue` holds it to the table (decision 0036) |
| `internal/kctest` | The test Keycloak: realms through the admin API, a browser at the login form |
| `internal/envoy` | The Envoy adapters: gRPC (`envoy.service.auth.v3.Authorization`, preferred) and HTTP external authorisation |
| `internal/nginx` | The nginx adapter: the check for `auth_request`, answering every refusal as a 401 with markers |
| `internal/exchange` | The exchange client: the RFC 8693 token exchange and the refresh at the issuer's token endpoint, for the route mode `exchange` |
| `examples/` | A site file and the payload of a policy bundle; `envoy/envoy.yaml` and `nginx/nginx.conf`, the Envoy and nginx configurations the tests run; `envoy-gateway/`, the same rules in Envoy Gateway's API (not run) |
| `internal/atoomx` | atoom's drivers mounted in this process, called through their generated clients; the key driver of each purpose (`--key`: software or AWS KMS) |
| `conformance/` | The conformance suite: the same scenarios in a headless browser through Envoy (gRPC and HTTP) and nginx, against Keycloak, and a site of two issuers (two realms) |
| `internal/kmstest` | A test double of AWS KMS for atoom's `key/awskms` driver (atoom's own is internal to its module); no AWS is called |
| `internal/sealer` | atoom's `seal` block in this process, as the core's `Sealer`: session's purposes and rules, the wrapping key on the key port |
| `internal/policy` | The Cedar route policy on atoom's loader: the signed bundle, the entities and their schema ([docs/policy.md](docs/policy.md)) |
| `internal/site` | The site file: its issuers (one or more, decision 0034), lifetimes, policy and routes |
| `internal/storetest` | A test double of the store port (atoom's memory store driver is Rust only) |

## Building

Inside `devbox shell` (or `devbox run -- just <recipe>`): `just build`, `just test` (no container), `just test-dynamodb` (the core on atoom's `store/dynamodb` driver against DynamoDB Local), `just test-keycloak` (the sign-in handler, the token exchange and the identity header against Keycloak 26.8), `just test-envoy` (the adapters through Envoy 1.39), `just test-nginx` (the adapter through nginx 1.30), `just test-conformance` (the conformance suite in Chromium's headless shell through every host; all in containers pinned by digest and removed at the end), `just lint`, `just vuln`, and `just check` for all of them.

atoom is pinned to its release 0.5.0 in `go.mod`, one version for every atoom module; an upgrade is a deliberate bump (decision 0006). `spike/` keeps the pins it ran with.

## Documents

- [Design](docs/design.md): purpose, behaviour contract, flows, the use of atoom, site file, repository contents, threat model, next steps and open questions.
- [Decision records](docs/decisions/README.md): 32 records, one for each subject (0017 is reserved), with the table that maps the old numbers.
- [Changelog](CHANGELOG.md).
- [Fit spike](docs/spike-2026-11-22.md): the check core on atoom drivers in-process, authorizer events through the Lambda Web Adapter, and the script for the real-AWS checks.
- [Archive](docs/archive/): the findings of the first spike and its run notes. Superseded records are in [docs/decisions/archive](docs/decisions/archive/).
- [spike/](spike/): the throwaway prototype of the first spike and the code of the fit spike.

## Licence

MIT. See [LICENSE](LICENSE).
