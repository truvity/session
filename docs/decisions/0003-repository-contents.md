# 0003. Repository contents

Status: accepted
Date: 2026-11-18

## Context

A site owner needs more than a binary to put a site behind `session`: a chart, host configs, a config format, a browser helper and tests. The service is built on [atoom](https://github.com/truvity/atoom) ([0006](0006-built-on-atoom.md)), and its core is a block built inside this repository until a second consumer needs it ([0009](0009-session-core-block.md)).

## Decision

One repository holds the service and everything a site needs around it. Paths are planned; nothing here is built yet except the throwaway code in `spike/`.

| In the repository | Path |
| --- | --- |
| The check service: image and Helm chart (2 replicas, Service, NetworkPolicy, store and key driver settings, cloud identity) | `cmd/session`, `charts/session` |
| The session core, the block of [0009](0009-session-core-block.md) | `core/` |
| The Lambda packaging: the Web Adapter layer pin, the configuration layer and the function definitions ([0012](0012-lambda.md)). The authorizer is the same binary unless the fit spike says otherwise | `lambda/` |
| Example host configs: Envoy `SecurityPolicy`, nginx, API Gateway | `examples/` |
| The site file schema, the `session check` validator and a generator | `schema/`, `cmd/session` |
| A small TypeScript browser helper: `apiFetch` (401 gives a re-login hint), `whoami`, `signOut` as POST with CSRF | `web/` |
| The conformance suite: a headless browser, run in CI against a test sluis and a test Keycloak | `conformance/` |
| The decision test cases for the route policy ([0007](0007-policy.md)) and the policy bundle used by the examples | `policy/` |
| Docs: site file reference, "put a site behind it" guide, threat model | `docs/` |

The atoom pin: `go.mod` requires one atoom release (0.2.0 first). An upgrade is a deliberate bump ([0006](0006-built-on-atoom.md)).

Not in the repository:

- the per-API door for API callers (the sluis resource-proxy sidecar);
- Keycloak realm configuration;
- Envoy routing and cluster configuration, which belong to the repositories of whoever deploys a site.

## Consequences

- Examples and tests change together with the code.
- The repository stays public and reusable. Deployment-specific routing stays out of it.
- The conformance suite is the contract for every adapter.
- `session` has no copy of a port interface. It depends on atoom's generated clients.

## Roads not taken

| Road | Why not |
| --- | --- |
| Only the service and its chart | A site owner would write the host configs, schema and helper again each time |
| Several repositories | Examples and tests must change together with the code |
