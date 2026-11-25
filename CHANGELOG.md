# Changelog

What changed in session, newest first. session has no release yet; each entry names the pull request's step of the
[plan](docs/design.md#16-status-and-next-steps).

## Unreleased

### The claim `idp`

- Added (not breaking): the identity header (`X-Session-Identity`) and `/_session/whoami` carry `idp`, the site file's id of the session's issuer ([0035](docs/decisions/0035-the-idp-claim.md), owner decision D115 A), on every site, with one issuer too. An app that keys data by person uses `idp` and `sub` together.
- Go API: `core.Rules.Issuers` is a list of `core.SiteIssuer` (the id and the identifier), no longer of identifiers.
- The conformance suite checks `idp` in whoami and in the identity header, locally and through the remote runner (the id `ISSUER=` names).

### atoom 0.9.0, audit 0.21.0 and the audit catalogue

- **Every atoom module at 0.9.0** and `truvity/audit/emitter` at 0.21.0 ([0036](docs/decisions/0036-atoom-0.9.0-and-the-audit-catalogue.md), owner decision D118 A). `go list -m all` lists one atoom version. `spike/` keeps its pins. The transport message is atoom's generic `Message{id, payload}` (B12). Its bytes are the same as before, so no flag, record or queue changes. `internal/audit.Lines` refuses an empty message with `message.id` and `message.payload`.
- New: `session catalogue [--release V]` writes the payload of session's `AuditCatalogue`, the one item `default` with `release`, `policy`, `table` and `schemas`, made from the action table in `internal/audit`. The release defaults to the binary's version. The command refuses a release that is not a semantic version, and schemas that fail audit's schema policy. audit's writer quarantines every record of a project without a catalogue.
- New: the committed catalogue `deploy/audit/audit-catalogue.json`, for the release 0.0.0, which covers every build before the first tag. `just catalogue` writes it, and `just check-catalogue` fails in the CI job `lint` while it is not what the table makes. Signing it as `AuditCatalogue` and publishing it to the writer's source as `audit-catalogue.jws` is the deployment's work, described in 0036.

### sluis v1 as an issuer

- New, site file: an issuer entry's `client.par`, `required` (the default) or `unavailable` ([0033](docs/decisions/0033-sluis-v1-as-an-issuer.md), owner decisions D92 A and O2 A). With `unavailable` the sign-in at that issuer sends the authorization request on the browser's URL instead of by PAR; the callback's checks are the same (the binding cookie, the state once, the nonce, PKCE S256, RFC 9207 `iss`, the code redeemed with the client's `private_key_jwt` assertion). session refuses to start with `unavailable` when the issuer's discovery offers PAR, so the setting never turns PAR off where the issuer has it, and logs a warning at start for each issuer that signs in without it. Any other value is refused.
- New: `just test-sluis-v1`, the sign-in handler against sluis v1 in a container (no PAR, `private_key_jwt`): the authorization request on the URL taken by sluis, session's client assertion accepted at its revocation endpoint and refused the second time, and the logout to its end-session. The image pin is a placeholder until a sluis release has `private_key_jwt`; until then the recipe says so and passes. `SESSION_TEST_SLUIS_V1_BIN` runs the same test against a sluis binary.

### Several issuers per site

- **Breaking, site file:** a site names its issuers in a list, `issuers` ([0034](docs/decisions/0034-several-issuers-per-site.md), owner decision D84 A). Each entry has an `id`, a `label`, the issuer identifier `issuer`, its `client` and its `scopes`. The top-level `issuer`, `client` and `scopes` are gone, and a file that still has them is refused with a message that names 0034: move them into one entry of `issuers` and give it an `id` and a `label`. With one issuer, behaviour is as before. No migration: nothing is deployed.
- New: `/_session/signin`, the sign-in page of a site of several issuers: one plain link for each, "Sign in with \<label\>", no script, session's own neutral template, with a strict `Content-Security-Policy`. `/_session/login` without `issuer=` sends the browser there; `?issuer=<id>` on either path goes to that issuer at once.
- New: `signin.remember_choice`, a duration, off by default: the issuer a person signed in with is kept in `__Host-<site>-issuer`, and a login that names no issuer goes to it. The check strips the cookie from what the site gets.
- Each sign-in is a PAR and PKCE flow at the issuer chosen, with the site's client there and an assertion for that issuer; the transaction records the issuer, and a callback whose `iss` names another issuer is refused (the mix-up defence). A session whose issuer the site file no longer names is no session.
- The exchange, the refresh, the revocation and the end-session go to the session's own issuer. Without a live session, a site of several issuers ends at the remembered issuer, or sends the browser back to the site. A back-channel logout token is verified by the site's issuer its `iss` names, and ends only that issuer's sessions; a token of another issuer is refused with the audit reason `issuer`.
- Go API: `core.Options.Issuer` is now `Issuers`, by issuer identifier; `core.Rules.Issuers` lists the site's issuers; `signin.Options` takes `Issuers` and `Remember`.
- **Breaking, remote runner:** `ISSUER=` is the id of the site file's issuer to sign in through (needed when the file has several), no longer a URL; the runner adds `?issuer=<id>` to the sign-in page.
- New: `TestConformanceTwoIssuers`, two Keycloak realms through Envoy over gRPC: the page, `?issuer=`, a sign-in through each, a mix-up refused, a policy by issuer, the exchange at the session's issuer, logout and back-channel logout through the right issuer.

### atoom 0.8.0: the audit transports NATS and SQS, and the AppConfig source

- **Every atoom module at 0.8.0** ([0032](docs/decisions/0032-atoom-0.8.0-transports-and-the-appconfig-source.md)); `go.mod` adds atoom's `transport/nats`, `transport/sqs` and `source/appconfig`. `spike/` keeps its pins. The token block's rotation ring (atoom's B8b) is not adopted: the first sites rotate no signing key ([0025](docs/decisions/0025-first-version-for-the-first-sites.md)); it is the next step.
- New: `--audit-nats URL`, atoom's Go NATS JetStream transport driver in the process (D65 A), with `--audit-nats-stream`, `--audit-nats-subject` (required), `--audit-nats-creds` or `--audit-nats-token-file`, and `--audit-nats-tls-ca`. The stream is the deployment's; session only publishes, and JetStream drops a retry by the message's uid.
- New: `--audit-sqs QUEUE_URL`, atoom's Go SQS transport driver in the process on a FIFO queue, the audit switch of a Lambda function (D44 A).
- The audit transport is exactly one of `--audit-socket`, `--audit-nats`, `--audit-sqs` and `--audit-stdout`; none or several are refused at start, and so is a `--audit-nats-*` setting without `--audit-nats`. The message for none changed: "an audit transport is required".
- New: `--source-appconfig APP/ENV/PROFILE`, atoom's Go AWS AppConfig source driver in the process (D71 A): the site file is the profile `PROFILE`, every other document the profile of its name. Exactly one of `--config-dir` and `--source-appconfig`; the message for none is "--config-dir or --source-appconfig is required".
- New: `just test-nats`, `--audit-nats` against a NATS server with JetStream in a container, in the CI job of the containers: a sign-in's record lands once.

### Logout across hosts

- **The back-channel logout lookup uses atoom's index entries** ([0031](docs/decisions/0031-logout-across-hosts.md)), in place of the pointer items of [0010](docs/decisions/0010-logout-pointer-items.md): each session item carries the entries `sid` and `sub` (keyed hashes of the issuer and the value), resent by every put of it, the idle refresh and the write of refreshed tokens included; a back-channel logout finds the sessions with a linearizable `Query` by entry. A sign-in no longer reads or rewrites a shared item, so parallel sign-ins of one subject never retry. No migration: nothing is deployed.
- **A logout without a live session goes to the issuer's end-session** too (without `id_token_hint`), so "sign out" always ends the issuer's session.
- **The person's logout revokes the refresh token** at the issuer's `revocation_endpoint` (RFC 7009, with the client's assertion), best effort and bounded by the exchange timeout, when discovery names one. A failure is counted in the new `session_logout_revocation_failed_total` and the logout goes on.
- The logout answer also clears the sign-in binding cookie `__Host-<site>-signin`.

### Step 5, part one: the API Gateway authorizer

- New: `session authorizer`, the API Gateway Lambda authorizer as a native Go handler of the check ([0014](docs/decisions/0014-authorizer-native-go-handler.md), [0030](docs/decisions/0030-lambda-handlers-step-5-choices.md)), for the HTTP API (payload 2.0, simple responses) and the REST API (REQUEST authorizer, and payload 1.0). It runs only as a Lambda function. No session is the error `Unauthorized` (401), every other refusal a deny (403), an unavailable check a function error (500); an allow carries the token, the identity header and the site's cookies in the context keys `authorization`, `identity` and `cookie`, for the integration's parameter mapping.
- New: `internal/apigateway`, the adapter, beside `internal/envoy` and `internal/nginx`. `go.mod` gains `github.com/aws/aws-lambda-go` 1.55.1.
- The sign-in function on Lambda is `session serve --check-grpc ''` behind the Lambda Web Adapter; no code of its own.
- Not yet deployable with audit to a writer: on Lambda the transport is atoom B9's `transport/sqs`, not yet released; `--audit-stdout` serves the emulator and local runs only.

### Step 4: the image

- **The image** `ghcr.io/truvity/session` ([0028](docs/decisions/0028-the-image.md)): `.github/workflows/image.yaml` publishes `master-<commit>` on a push to `master` (version `0.0.0-master.<commit>`) and `X.Y.Z` on a tag `vX.Y.Z`, for `linux/amd64` and `linux/arm64`, from `just build-image`. A pull request publishes nothing.
- **The remote runner** ([0029](docs/decisions/0029-the-remote-runner.md)): `just test-remote HOST=...` runs the remote-capable conformance scenarios against a deployed site, with the site file `conformance/remote/site.yaml`. Each scenario says where it runs; the local suite is unchanged.
- **The test backend** `ghcr.io/truvity/session-echo` (`conformance/echo`), published beside `ghcr.io/truvity/session` with the same tag; the local stand serves the same handler.

### atoom 0.7.0: the key drivers are told no installation

- **atoom 0.7.0** for every atoom module ([0027](docs/decisions/0027-atoom-0.7.0-and-the-audit-scope-flag.md)). `spike/` keeps the pins it ran with. `truvity/audit/emitter` stays at 0.19.0 and runs on it.
- **Breaking, start-up:** `--environment` is renamed `--audit-scope`. It is the scope of the security-audit log only (`local` when unset); nothing in session decides by its value. `--environment` is no longer a flag, so a deployment that passes it fails to start: rename it to `--audit-scope` with the same value, and the records keep the same scope.
- session tells no key driver an installation: atoom 0.7.0's `key/software` has no environments, and `atoomx.KeyOptions.Environment` and the environment argument of `atoomx.SoftwareKeys` are gone. Any label now works with a purpose on the software driver. A deployment that must not hold keys in files puts its purposes on AWS KMS with `--key PURPOSE=awskms[:KEY]`.
- atoom's clients send the correlation header `Atoom-Correlation-Id`; session reads no correlation header itself.

### The audit transport is an explicit switch

- **Breaking, start-up:** `session serve` takes exactly one of `--audit-socket PATH` and the new `--audit-stdout` ([0024](docs/decisions/0024-audit-transport-is-an-explicit-switch.md)). With neither it refuses to start, and with both too, whatever `--environment` says. `--audit-stdout` writes each security-audit record as one JSON line to stdout, for local development; a local run that relied on an unset `--environment` now adds `--audit-stdout`.
- **Breaking, start-up:** `--environment local` is no longer special. `--environment` is a label: the scope of the audit log (`local` when unset) and, until atoom 0.7.0, the environment the software key driver is told, verbatim. atoom 0.6.0's software driver takes only unset, `development`, `staging` or `production`, and refuses any other value when a purpose is on it.

### Step 3.7: the emitter of truvity/audit

- **Security-audit records go through the emitter of `truvity/audit`** (`github.com/truvity/audit/emitter` 0.19.0, [0023](docs/decisions/0023-audit-emitter.md)), over atoom's `transport` port, in place of the stand-in. Every atoom module stays at 0.6.0; `transport` and `socket` are added.
- **Breaking, audit:** each record is an OCSF 1.9.0 record in RFC 8785 canonical JSON, of session's action table: `sign-in` (with its failure, the old `sign-in-failed`), `logout`, `back-channel-logout`, `denied` (API Activity, with the policy decision), `token-exchange` and `refresh` (the old `refresh-failed`). The site, the issuer, the route and the audience are in `unmapped.session`; a policy denial's digest is `policy.version`, with the bundle's name as `policy.uid`. A reason that is not a closed word is `unrecognised`.
- **Breaking, audit:** the subject is never in a record: it is a pseudonym, `p1.<YYYYMM>.<value>`, made by the seal block under the new keyed-hash purpose `pseudonym`, one data key a month, label `session-pseudonym-v1`.
- A sign-in waits until the transport says its record is durable, and fails closed with 503 when it does not; every other event is best effort, bounded by a second, counted in `session_audit_dropped_total` when lost, and reported by the emitter's next record.
- New: `session serve --audit-socket PATH`, the emit socket of the environment's transport driver (atoom's `transport-spool`). Without it, a driver in the process writes each record as one JSON line to stdout, for local development only.
- **Breaking, start-up:** `--environment` is unset by default (it was `development`); unset or `local` is local development, where the drivers are told no environment. Every named environment (`devel`, `stage`, `production` or any other value) refuses to start without `--audit-socket`.
- New: `internal/audit` holds session's action table and its schemas (`Table`, `Schemas`), the client of an emit socket and `Lines`; the seal block's `Pseudonym`; the conformance suite runs the emitter and checks its records after each host.
- The default build's version is `0.0.0-dev` (it was `dev`): the records name it, and the writer takes only a semantic version.

### atoom 0.6.0: the token block

- **atoom 0.6.0** for every atoom module, and one new one: `blocks/token` ([0022](docs/decisions/0022-atoom-token-block.md)). `spike/` keeps the pins it ran with.
- **The client assertion and the identity header are signed by atoom's `token` block**, in place of session's own JWS code: in process, over the seal block session already runs, which signs through the key port. `key/route` gives the seal block one key client in front of the drivers, so each purpose stays on the driver `--key` chose.
- **`/_session/jwks` is the block's key set** of the two purposes, with the same `Cache-Control: max-age=300`. The keys and their members are the same; only the order of the members inside each key differs.
- Unchanged for issuers and apps: the header (`alg` ES256, `kid` the key port's `key_id`, `typ` `JWT` or `session-identity+jwt`, in that order), the claims, the lifetimes and the identity header's 30-second reuse.
- The seal block's rules now allow `Sign` and `PublicKey` under the two signing purposes, and nothing more. The block reads each public key at its start and for each key set rather than for each signature, and checks each signature before it answers. The start ensures the signing keys with the wrapping key: a missing or wrong KMS key fails it as before.
- New: `sealertest.Tokens`, the seal and token blocks over the signing keys a test chose; a test that the headers are byte for byte the earlier ones.

### atoom 0.5.0: the policy loader and the seal block

- **atoom 0.5.0** for every atoom module (`common`, `key`, `key/awskms`, `key/software`, `source`, `source/file`, `store`, `store/dynamodb`, `socket`), and two new ones: `policy` and `blocks/seal` ([0021](docs/decisions/0021-atoom-policy-loader-and-seal-block.md)). `spike/` keeps the pins it ran with.
- **The policy bundle is atoom's signed bundle**, loaded by atoom's `policy` library in place of the interim loader: a JWS of the kind `PolicyBundle` (ES384), read through the source port as `policy-bundle`, verified under the one key the site file pins, validated against its schema in strict mode, swapped in atomically and refreshed on the file driver's watch. A failed reload keeps the last good set; a cold start without a valid set refuses to run.
- **Breaking, site file:** `policy.verify_key` is required with `policy.bundle`: a `kid` and the publisher's P-384 public key as PEM. `policy-bundle.jws` is now the signed document, not Cedar text; its payload carries the schema and the policies by id (`examples/policy-bundle.json`, with session's schema, `internal/policy.Schema`).
- **Breaking, audit:** `policy_digest` is the SHA-384 of the bundle's payload in lower-case hex (96 characters), in place of `sha256:` and the SHA-256 of the Cedar text. A request that does not fit the bundle's schema is a 403, audited as `denied` with the reason `misfit`.
- **Sealing is atoom's `seal` block**, in place of the local sealer: data keys for each purpose of the installation `session/<site>`, wrapped by the new key purpose `wrapping` (ECDH-P384: the key file, or `--key wrapping=awskms` on an `ECC_NIST_P384` `KEY_AGREEMENT` key with `kms:DeriveSharedSecret`), with the wraps in session's store under `seal/`. Store keys are HMAC-SHA384.
- **Breaking, start-up:** `--seal-root` and `session seal-root` are gone. Items sealed by the local sealer do not open, and the store keys change: nothing is deployed, so nothing is migrated.
- New: `internal/sealer` (and `sealertest`), `internal/policy/policytest`, which signs bundles in tests; the KMS double answers `DeriveSharedSecret` for a key-agreement key.

### Step 3.4: the conformance suite

- **The conformance suite** ([0020](docs/decisions/0020-conformance-suite.md), proposed): `conformance/`, one set of scenarios run in a real headless browser (Chromium's headless shell 157, pinned by digest, driven by chromedp) against Keycloak through Envoy over gRPC, Envoy over HTTP and nginx, each running its example configuration as it is.
- The scenarios: a public route and the JSON 401; the sign-in redirect, Keycloak's form and the callback, with the S1 cookie read from the browser; a protected route with header stripping; the sign-in prefix; CSRF with and without the header; the exchange and identity-header routes, verified against the realm and `/_session/jwks`; a refused exchange; a store outage; bad paths; logout and Keycloak's end-session; back-channel logout; a refresh refused after an unseen logout, with the cookie cleared by the check.
- Where hosts differ by design, the suite asserts each host's answer: the empty 503 of Envoy's HTTP mode, Envoy's normalised dot segments and its own 400 on an encoded slash or backslash, nginx's 400 `bad_path` and the raw merged-slash path it passes the site.
- API Gateway and the Lambda authorizer are not in it: they need AWS, and run the scenarios in step 5's real-AWS check.
- New: `just test-conformance`, and the CI job `conformance`; `go.mod` adds chromedp v0.22.0 (tests only).

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
