# 0015. Envoy HTTP mode and the CSRF header; the choices of step 2

Status: accepted
Date: 2026-11-22

Partly supersedes [0011](0011-host-adapter-rules.md) (its Envoy section) and decides the open point of [0008](0008-audit.md).

## Context

Step 2 of the plan built the check core, the sign-in handler and the Envoy adapters against Keycloak 26.8.1 and Envoy 1.39.6, with integration tests that run `examples/envoy/envoy.yaml` in Envoy as it is (`just test-envoy`). Two rules of 0011 did not hold in that Envoy, and the build made choices where the records were silent. The owner accepted them on 2026-11-22.

## Decision

### Envoy (corrects 0011)

- **HTTP mode removes headers.** 0011 says an HTTP answer "can only set a header empty", so the example would need `request_headers_to_remove` on the route. That is not so: Envoy applies the header `x-envoy-auth-headers-to-remove` of the check's allow answer to the upstream request. The HTTP adapter names the owned headers there (`authorization`, `x-session-token`, `x-session-identity`, and `cookie` when no other cookie is left), and the test shows them removed. The example sets no `request_headers_to_remove`. The rest of 0011's HTTP mode stands: `Set-Cookie` needs `allowed_client_headers_on_success`, and a 503 keeps its status but loses its body.
- **`allowed_headers` includes `x-requested-with`.** The CSRF header of S5 is `X-Requested-With: XMLHttpRequest` (the value the reference stand's browser library sends). 0011's list (`cookie`, `accept`, `sec-fetch-mode`, `sec-fetch-site`, `origin`) left it out, so the check would never see it and every state-changing request would be refused. The list is `cookie`, `accept`, `sec-fetch-mode`, `sec-fetch-site`, `origin`, `x-requested-with`, and the integration test checks a POST with and without it.

Everything else in 0011 stands.

### Audit while the transport is down (decides the open point of 0008)

- **A sign-in fails closed in the first version.** The callback emits the sign-in event and waits for the transport to accept it. If it is refused, the new session is deleted and the browser gets 503. Checks are not affected: they never wait on audit.

### Choices of step 2

| Subject | Choice |
| --- | --- |
| The person's logout answer | A `POST /_session/logout` with `Accept: application/json` (the browser helper's `fetch`, which cannot follow a cross-origin redirect) gets `200 {"logout_url": ...}`, and the helper navigates there. Any other request gets `303` to the same address, the issuer's end-session with `id_token_hint` |
| Site file and policy bundle names | atoom's `source/file` driver serves `<name>.jws`: the site file is `site.jws`, the bundle `policy-bundle.jws`. Today they hold plain YAML and Cedar text; whether they are signed waits for atoom's bundle format and loader |
| Audience of the client assertion | The issuer's identifier (FAPI 2.0), for PAR and the token endpoint; Keycloak 26.8 accepts it. A new `jti` for every request |
| Route modes `exchange` and `identity-header` | Refused at start until step 3 builds the exchange client and the identity header |
| A request without a session | Counted as a metric (`login_required`), not an audit event: it follows traffic. Policy and CSRF denials are events |
| "The sealed cookie" of 0006 and 0009 | The cookie holds an opaque random id (S1). What protects it is the keyed hash (`Mac`) that turns the id into the store key, so a store leak gives no usable cookie |
| Logout lookup | Pointer items, as 0010 says. The fit spike's index entries replace them at step 5 of the plan, by a new record then |

## Consequences

- The Envoy example and the conformance suite carry `x-requested-with` and no `request_headers_to_remove`.
- HTTP mode is no longer second-class for stripping; it stays second-class for 503 bodies and for installs that can use gRPC.
- An audit outage stops new sign-ins until it ends. Existing sessions keep working.
- The browser helper (`web/`) reads the JSON logout answer.

## Roads not taken

| Road | Why not |
| --- | --- |
| `request_headers_to_remove` on every route of HTTP mode | Not needed, and it would have to be kept in step with the check's owned headers by hand |
| Any non-empty `X-Requested-With` | The reference stand's broker wants the exact value; an exact value is as easy to send and easier to test |
| A sign-in that completes when audit is down, with the drop counted | A sign-in without its security event; the first version prefers to fail closed |
| Always a 303 at logout | A `fetch` cannot follow it to the issuer |
