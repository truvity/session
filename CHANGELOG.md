# Changelog

What changed in session, newest first. session has no release yet; each entry names the pull request's step of the
[plan](docs/design.md#16-status-and-next-steps).

## Unreleased

### Step 3.1: the exchange client and the identity header

- **The route modes `exchange` and `identity-header` start** ([0016](docs/decisions/0016-exchange-client-and-identity-header.md)); until now they were refused at start ([0015](docs/decisions/0015-envoy-http-mode-csrf-header-and-step-2-choices.md)).
- **`exchange`:** the allow answer carries `Authorization: Bearer` with a token of the route's `audience`, from an RFC 8693 token exchange at the issuer (`internal/exchange`), in the request the sluis v2 exchange serves. The token is cached under the session in the store, sealed, until its end minus 30 seconds; a lock in the store makes parallel checks exchange once; an old sign-in token is refreshed first under the same lock. A refused exchange is a 403 (the site's `error_page` to a navigation, JSON otherwise) and the session stays; a refresh refused with `invalid_grant` ends the session; an issuer outage is a 503.
- **`identity-header`:** the allow answer carries `X-Session-Identity`, a JWS of `typ` `session-identity+jwt` signed by the new key purpose `identity-header`, with the person's subject, name, email and groups, living a minute. `/_session/jwks` publishes it beside the client key.
- Logout, back-channel logout and a failed refresh delete the cached tokens with the session.
- New: `session serve --exchange-timeout` (2 s), the site file's `error_page`, the audit events `token-exchange` and `refresh-failed`, the metric `session_exchange_cache_write_failed_total`.
- The Envoy example's check timeout is 4 s (store timeout plus exchange timeout).
- Fix: deletes go in chunks of 100, DynamoDB's limit for one transaction; a back-channel logout of a person with more than 99 sessions failed on DynamoDB.

### Step 2: the check core, the sign-in handler and the Envoy adapters

- The check core on atoom's ports, the sign-in handler against Keycloak, and the Envoy gRPC and HTTP adapters ([0015](docs/decisions/0015-envoy-http-mode-csrf-header-and-step-2-choices.md)).
