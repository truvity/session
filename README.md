# session

Browser sessions for websites behind Envoy Gateway, nginx or AWS API Gateway.

`session` is an OIDC client that keeps a website's browser session on the server and answers "may this request pass?" for the proxy in front of the site (external authorisation: Envoy `ext_authz`, nginx `auth_request`, an API Gateway Lambda authorizer). It can also run in the request path as a reverse proxy.

It is a Go service built on [atoom](https://github.com/truvity/atoom): its stores, keys, sealing and configuration come from atoom's ports, drivers and blocks. Who may reach a route is decided by Cedar, as a library. Its security-audit events go to [audit](https://github.com/truvity/audit). It never emits usage records.

Status: design. No production code yet. `spike/` holds throwaway prototype code from the first spike.

## Documents

- [Design](docs/design.md): purpose, behaviour contract, flows, the use of atoom, site file, repository contents, threat model, next steps and open questions.
- [Decision records](docs/decisions/README.md): 13 records, one for each subject, with the table that maps the old numbers.
- [Archive](docs/archive/): the findings of the first spike and its run notes. Superseded records are in [docs/decisions/archive](docs/decisions/archive/).
- [spike/](spike/): the throwaway prototype of the first spike.

## Licence

MIT. See [LICENSE](LICENSE).
