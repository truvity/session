# 0030. The Lambda handlers: the choices of step 5, before atoom's B9

Status: accepted, 2026-11-25 (owner decision on the pull request)
Date: 2026-11-25

Builds the part of step 5 (design section 16) that needs no new atoom driver: the API Gateway authorizer as a native Go handler ([0014](0014-authorizer-native-go-handler.md)) and the sign-in function behind the Lambda Web Adapter ([0012](0012-lambda.md)). It keeps every rule of [0011](0011-host-adapter-rules.md) for API Gateway, and it names the two places where atoom's B9 plugs in ([0025](0025-first-version-for-the-first-sites.md)). The run in a real AWS account is not part of it.

## Context

The fit spike answered authorizer events with a native Go handler (`spike/cmd/authorizer-lambda`, `spike/internal/sess/lambda.go`) on its own check core and an in-memory store ([spike of 2026-11-22](../spike-2026-11-22.md), section 3). session's check core, its atoom drivers and its audit emitter are now built, and the Envoy and nginx adapters show how an adapter translates a `core.Decision` into a host's protocol. 0011 fixes what API Gateway can do: no redirect, no header change, no `Set-Cookie`; only `principalId` and `context` reach the integration; the HTTP API reserves `Authorization` in parameter mapping; no session is the error `Unauthorized`; the cache is 0 seconds.

Step 5 depends on atoom's B9: a Go `transport/sqs` driver for audit, because a function has no spool sidecar, and a Go `source/ssm` or `source/appconfig` driver for the site file and the policy bundle. Neither is released. Everything else a function needs is built.

## Decision

### The authorizer

| Subject | Choice |
| --- | --- |
| The entry point | `session authorizer`, a command of the same binary, with the flags of `session serve` that are not listeners: the site (`--config-dir`), the store, the keys, audit and the timeouts. It runs only as a Lambda function (it refuses to start without `AWS_LAMBDA_RUNTIME_API`), and serves the handler with `aws-lambda-go` 1.55.1 |
| What it builds | The same check core as `session serve`, with the same policy loader, seal and token blocks, exchange client and audit emitter. It has no sign-in paths, so it does not make the sign-in handler |
| The adapter | `internal/apigateway`, as `internal/envoy` and `internal/nginx` are: it translates and decides nothing |
| The shapes | One handler for both products. It reads the raw event: `version` `2.0` is the HTTP API payload 2.0 with simple responses; `type` `REQUEST` is the REST API's REQUEST authorizer, or an HTTP API authorizer on payload 1.0, answered with a policy. A `TOKEN` authorizer is refused, because it sees no cookie |
| The request the check gets | REST: `httpMethod`, `path` with the query rebuilt from `multiValueQueryStringParameters` (keys sorted), the `multiValueHeaders`, `Host` from them. HTTP API: `requestContext.http.method`, `rawPath` without the stage on a named stage, `rawQueryString`, the `headers`, the host `requestContext.domainName`, and the cookies from the `cookies` array joined into one `Cookie` header; a `Cookie` header of the event is not read |

### The answers

| Check's decision | REST API | HTTP API (payload 2.0) | Status the browser sees |
| --- | --- | --- | --- |
| Allow | Policy `Allow` for `execute-api:Invoke` on the `methodArn`; `principalId` the subject, or `anonymous` on a public route | `isAuthorized: true` | the integration's |
| No session (the core's redirect or 401) | The error `Unauthorized` | The error `Unauthorized` | 401 (S4); the browser helper starts the sign-in |
| Any other refusal: CSRF, policy, a refused exchange, a path the check refuses, no route | Policy `Deny`, context `error` the check's reason | `isAuthorized: false`, context `error` | 403 |
| Unavailable: the store, the policy, the issuer | A function error | A function error | 500, fail closed |

An authorizer has no 400, no 404 and no error page, so every refusal that is not "no session" is a 403, and a navigation whose exchange is refused gets API Gateway's 403, not the site's error page. A `Set-Cookie` of the check (the cleared cookie of a session that ended at a refresh) cannot reach the browser and is dropped; the next sign-in replaces the cookie.

### The context and the integration's parameter mapping

Only the context reaches the integration, as `$context.authorizer.<key>`, so an allow carries there what the other hosts set as headers. Every key is present on every allow, empty when the route sets nothing, so the mapping always overwrites a browser-sent value (S8).

| Key | Value | REST API integration request | HTTP API parameter mapping |
| --- | --- | --- | --- |
| `subject` | The session's subject; empty on a public route | (for logs) | (for logs) |
| `authorization` | `Bearer <token>`, the per-API token of a route of mode `exchange` | `integration.request.header.Authorization` = `context.authorizer.authorization` | `overwrite:header.x-session-token` = `$context.authorizer.authorization` (the HTTP API reserves `Authorization`) |
| `identity` | The signed identity header of a route of mode `identity-header` | `integration.request.header.X-Session-Identity` = `context.authorizer.identity` | `overwrite:header.x-session-identity` = `$context.authorizer.identity` |
| `cookie` | The `Cookie` header without session's cookies | `integration.request.header.Cookie` = `context.authorizer.cookie` | `overwrite:header.cookie` = `$context.authorizer.cookie` |

`X-Session-Token` carries `Bearer <token>`, the same value as `Authorization` on the other hosts, so a site reads either header with the same code (owner decision, 2026-11-25).

### The sign-in function

| Subject | Choice |
| --- | --- |
| The entry point | `session serve --check-grpc ''` (no check listener; the sign-in paths on `--listen`, 8080), behind the Lambda Web Adapter's layer, as 0012 says. No code of its own: the adapter turns each HTTP API request into an HTTP request (the `cookies` array joined into `Cookie`), and each `Set-Cookie` of the answer into the `cookies` array of the response |
| The adapter's settings | `AWS_LWA_PORT=8080`; readiness on the admin listener, `AWS_LWA_READINESS_CHECK_PORT=9090` and `AWS_LWA_READINESS_CHECK_PATH=/healthz` |
| The routes | The HTTP API sends `/_session/{proxy+}` to it without the authorizer, as the other hosts route the sign-in prefix without a check |

### HTTP API first, then REST API

The two handlers share everything but the event and the answer, so both are built and tested in one change. The documentation and the examples default to the HTTP API (0011); the REST API is the second, supported shape.

### The seams that wait for atoom's B9

| Seam | Where | Today | When B9 is released |
| --- | --- | --- | --- |
| Audit on Lambda | `auditTransport` in `cmd/session/main.go`, beside `--audit-socket` and `--audit-stdout` | A function has no socket. `--audit-stdout` works, for the emulator and local runs; it is not for a deployment (0024) | atoom's Go `transport/sqs` is mounted in the process, as `audit.Lines` is, and selected by a third switch of its own; still exactly one of the three. The emitter, the action table and the blocking sign-in stay as they are |
| The site file and the policy bundle | `openSource` in `cmd/session/main.go` | atoom's Go `source/file` over `--config-dir`; on Lambda, the configuration layer of 0012 | atoom's Go `source/appconfig` is mounted there instead, by a start-up switch beside `--config-dir`. The core, the policy loader and the authorizer read the port's client only |

### The source of the Lambda shape

Decided by the owner on 2026-11-25, which settles what [0025](0025-first-version-for-the-first-sites.md) left to step 5:

| Option | Pros | Cons |
| --- | --- | --- |
| The configuration layer on `source/file` (0012) | Works today; no call at start or refresh | A change of the site file or the bundle is a new layer version and a function update |
| `source/ssm` | Simple | A parameter holds at most 8 KB in the advanced tier, which a signed policy bundle can exceed |
| **`source/appconfig`** | Documents of a megabyte and more in hosted configuration; versions, validators and staged deployments with rollback | A call to AppConfig's data API at each refresh |

**The Lambda shape reads the site file and the policy bundle through atoom's Go `source/appconfig` once B9 ships it, and through the configuration layer on `source/file` (0012) until then.** `source/ssm` is not used for the Lambda shape. The switch that selects `source/appconfig`, and its settings, follow the driver's own options when it is released.

## Consequences

- One binary with the two entry points of 0014, `session serve` and `session authorizer`; the authorizer's unit tests run the check core, the in-process store double and the emitter of `truvity/audit` over the in-process transport driver `Lines`, with the fit spike's sample events (`internal/apigateway/testdata`).
- `go.mod` gains `github.com/aws/aws-lambda-go`.
- An authorizer function cannot be deployed with its audit records going to a writer until B9's `transport/sqs` is released: a deployment fails at start without a transport switch, as 0024 meant.
- The parameter mapping is written down here; the examples of API Gateway (a deployable definition) and the packaging under `lambda/` (the zip, the Web Adapter layer pin, the configuration layer, the function definitions) come with the real-AWS run.

## Roads not taken

| Road | Why not |
| --- | --- |
| `isAuthorized: false` for no session on the HTTP API, as the spike's handler did | A 403, which the browser helper would not read as "sign in"; 0011 and S4 say `Unauthorized` on both products. The real-AWS check (part A3) observes the HTTP API's status for it |
| A deny for the check's 400 (`bad_path`) and 404 (`no_route`) as an error instead | API Gateway turns any error but `Unauthorized` into a 500, which reads as an outage |
| Only the context keys a route sets | What a mapping does with a key that is absent is not documented; every key on every allow makes the overwrite the same on every route |
| The bare token in `X-Session-Token` | A site behind two hosts would read the two headers differently |
| A second Lambda handler for the sign-in paths | 0012: a second entry point to keep in step with the HTTP server |
| Choosing the SQS or AppConfig driver's settings now | The drivers are atoom's, and not released |
| `source/ssm` for the Lambda shape | A signed policy bundle can exceed a parameter's 8 KB |

## Open

- To observe in a real AWS account (0011, design section 17, `spike/scripts/aws-check.sh`): the HTTP API status for `Unauthorized` and for `isAuthorized: false`; the HTTP API default cache TTL; parameter mapping from `$context.authorizer.*`, an empty value included; whether `rawPath` begins with the stage on a named stage; the REST API's `path` under a custom domain's base path mapping.
