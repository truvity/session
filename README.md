# session

Browser sessions for websites behind Envoy Gateway, nginx or AWS API Gateway.

`session` is an OIDC client that keeps a website's browser session on the server and answers "may this request pass?" for the proxy in front of the site (external authorisation: Envoy `ext_authz`, nginx `auth_request`, an API Gateway Lambda authorizer). It can also run in the request path as a reverse proxy.

Status: design, amended after the first spike. No production code yet; `spike/` holds throwaway prototype code.

## Documents

- [Design](docs/design.md): purpose, behaviour contract, flows, ports, repository contents, threat model, decisions after review, next steps and open questions.
- Decisions, 2026-11-18:
  - [0001 Purpose and scope](docs/decisions/0001-purpose-and-scope.md)
  - [0002 Our own Go service](docs/decisions/0002-own-go-service.md)
  - [0003 Deployment is external authorisation](docs/decisions/0003-external-authorisation.md)
  - [0004 Repository contents](docs/decisions/0004-repository-contents.md)
  - [0005 Browser session behaviour contract](docs/decisions/0005-browser-session-contract.md)
  - [0006 Per-API tokens by token exchange](docs/decisions/0006-per-api-token-exchange.md)
  - [0007 Issuers, and the sluis v1 check](docs/decisions/0007-issuers-and-sluis-v1-check.md)
  - [0008 Name](docs/decisions/0008-name.md)
  - [0009 Ports shaped like the sluis v2 building blocks](docs/decisions/0009-ports.md)
  - [0010 Sessions in DynamoDB on every shape](docs/decisions/0010-dynamodb-sessions-everywhere.md)
  - [0011 Defaults accepted](docs/decisions/0011-defaults-accepted.md)
  - [0012 Answers to the first open questions](docs/decisions/0012-answers-to-first-open-questions.md)
  - After the first spike (proposed, coordinator's call 2026-11-18, for review):
    - [0013 Logout without a secondary index: pointer items](docs/decisions/0013-logout-race-pointer-items.md)
    - [0014 Installs without AWS](docs/decisions/0014-installs-without-aws.md)
    - [0015 API Gateway: both handlers, HTTP API by default, caching set to zero](docs/decisions/0015-api-gateway-handlers-and-caching.md)
    - [0016 Host adapter rules from the spike](docs/decisions/0016-host-adapter-rules.md)
  - 2026-11-20, after atoom 0.2.0:
    - [0017 session is built on atoom: ports, blocks, sealing, policy, audit, Lambda](docs/decisions/0017-atoom-ports-and-blocks.md) (supersedes 0009 and 0014)
- [Spike findings, 2026-11-18](docs/spike-2026-11-18.md), with the throwaway prototype in [spike/](spike/).

## Licence

MIT. See [LICENSE](LICENSE).
