# Changelog

What changed in session, newest first. session has no release yet; each entry names the pull request's step of the
[plan](docs/design.md#16-status-and-next-steps).

## Unreleased

### Step 3.3: signing keys on AWS KMS

- **The key driver of each signing purpose is a start-up setting** ([0019](docs/decisions/0019-signing-keys-on-aws-kms.md), proposed): `session serve --key client-assertion=awskms` and `--key identity-header=awskms:<key ID, ARN or alias>`, repeatable, on atoom's `key/awskms` driver in-process. A purpose not named stays on the key file (`--key-dir`, now required only then). Without a named key, a purpose's KMS key is the alias `alias/<--kms-alias-prefix>/<purpose>`, `session/<site>` by default; `--kms-endpoint` names another endpoint.
- session never makes a KMS key: the deployment makes them (`ECC_NIST_P256`, `SIGN_VERIFY`), and the role needs `kms:DescribeKey`, `kms:GetPublicKey` and `kms:Sign`. A missing, disabled or wrong key fails the start.
- The kid is the key port's `key_id` as before (on KMS the key ARN and the fingerprint); the identity header's 30 s reuse keeps KMS off the request path.
- New: `internal/kmstest`, an in-process KMS double; the tests count KMS signatures and run sign-in, exchange and the identity header against Keycloak with both keys on it. No test calls AWS.
- atoom: `key/awskms` added at 0.3.0, the other pins unchanged.

### Step 3.2: the nginx adapter

- **nginx `auth_request`** ([0018](docs/decisions/0018-nginx-adapter.md), proposed): `session serve --check-nginx` serves the check at `/auth` and the refused exchange's page at `/error-page`. An allow carries the headers to set; every refusal is a 401 with markers (`X-Session-Action`, `X-Session-Status`, `X-Session-Location`, `X-Session-Body`) that `examples/nginx/nginx.conf` turns into the check's own answer and body, as on Envoy.
- The example reads `$uri$is_args$args` in the protected location (inside the check's own location `$uri` is the subrequest's path, which the first spike missed), refuses raw paths with dot segments or encoded dots, slashes or backslashes, and sets every owned header on every request.
- A failed or unreachable check is a 503 on nginx too, not 500.
- New: `just test-nginx`, the example run in nginx 1.30.8 (pinned by digest), in CI.

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
