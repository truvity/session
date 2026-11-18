# 0004. Repository contents

Status: accepted, 2026-11-18 (decision E2). Amended 2026-11-18: Valkey dropped, see 0010

## Context

A site owner needs more than a binary to put a site behind `session`: a chart, host configs, a config format, a browser helper and tests.

## Options considered

| Option | Meaning |
| --- | --- |
| A | Only the service and its chart |
| B | The service, the adapters, examples, schema, browser helper, tests and docs |
| C | Split into several repositories |

## Decision

B, one repository.

In the repo:

- The check service: image and Helm chart (2 replicas, Service, NetworkPolicy, DynamoDB table name and cloud identity).
- The Lambda authorizer package, and the same binary as a second Lambda handler for the sign-in paths.
- Example host configs: Envoy `SecurityPolicy`, nginx, API Gateway.
- The site config schema, the `session check` validator and a generator.
- A small TypeScript browser helper: `apiFetch` (401 gives a re-login hint), `whoami`, `signOut` as POST with CSRF.
- A conformance suite using a headless browser, run in CI against a test sluis and a test Keycloak.
- Docs: site file reference, "put a site behind it" guide, threat model.

Not in the repo:

- The per-API door for API callers (the sluis resource-proxy sidecar).
- Keycloak realm configuration.
- Envoy routing, which belongs to the platform's own repositories.

## Consequences

- Examples and tests change together with the code.
- The repo stays public and reusable. Platform-specific routing stays out of it.
- The conformance suite is the contract for every adapter.
