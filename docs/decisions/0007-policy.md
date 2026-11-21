# 0007. Policy: Cedar as a library, with a shared bundle

Status: accepted
Date: 2026-11-20

## Context

`session` must decide, for a request on a route, whether this person may reach it. The decision runs on every request, in Envoy's external authorisation and in the Lambda authorizer. sluis and ritueel also decide with Cedar.

Cedar is a library by design, with no loader and no network API. `cedar-policy` (Rust) is the reference. `cedar-go` is a separate native implementation that lags in places. A ConnectRPC policy-engine port would restate Cedar's model in proto, and every feature Cedar added later would wait for the proto.

## Decision

- **Cedar is used as a library**: `cedar-go` in `session`, in-process. This is the one named exception to "always the ConnectRPC contract" ([0006](0006-built-on-atoom.md)). Cedar keeps all of its types and features.
- **atoom shares four things around the engine:**
  1. The **signed policy bundle**: schema, policies, templates and links in one signed document, read through the `source` port.
  2. The **loading rules**: verify the signature before parsing; validate against the schema in strict mode; compile once and swap atomically; keep the last good set when a reload fails; refuse a cold start with no valid set; refresh on watch or by ETag with a minimum interval; no I/O during a decision; audit each decision with the digest of its policy set.
  3. The **loader library** in Go (and in Rust, for the other consumers).
  4. A **decision test set** that runs against `cedar-go` and the Rust `cedar-policy` in CI.
- **The decision runs in-process on every request.** The entities come from the session item the check already read (the person's claims, cached at sign-in) and from the route in the site file. There is no extra read, and there is no call to sluis's policy actor on the request path.
- **The route table keeps what is structure:** does a route need a session, and which audience's token does it need. Cedar decides who may reach a route.
- What a person may do inside an API stays the API's decision.

State: the bundle format, the loading rules, the Go loader and the test set are planned in atoom ([0006](0006-built-on-atoom.md)). Until the loader exists, the first version decides from the route table alone.

## Consequences

- No hop and no extra read on the request path.
- `session` depends on `cedar-go`, and on the test set to stay in step with the Rust engine.
- A tampered or broken bundle never replaces the last good one, and a cold start without a valid bundle refuses to run.
- Each decision is audited with the digest of the policy set that made it ([0008](0008-audit.md)).
- sluis keeps its layers, grants and policy actor. They are one possible source of a bundle, not a dependency of `session`.

## Roads not taken

| Road | Why not |
| --- | --- |
| A ConnectRPC policy-engine port | It re-describes Cedar's API and loses features as Cedar grows |
| Only the Rust engine, over a socket | A hop on every request |
| A call to sluis's policy actor on every request | A hop, a dependency on sluis and an extra read |
| A plain route table only | No per-person decisions |
