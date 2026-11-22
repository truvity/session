# 0014. The authorizer is a native Go handler

Status: accepted
Date: 2026-11-22

## Context

Record [0012](0012-lambda.md) put every Lambda function of `session` behind the Lambda Web Adapter and left the authorizer open, because the adapter does not list API Gateway authorizer events among the events it supports. The [fit spike of 2026-11-22](../spike-2026-11-22.md), section 3, sent authorizer events through the adapter (tag 1.1.0) in the Lambda emulator:

- **REST API authorizer events are HTTP requests to the adapter, always.** The event parses as an API Gateway v1 proxy request, so the app's answer comes back in an HTTP envelope with no `policyDocument`, and the error `Unauthorized` that [0011](0011-host-adapter-rules.md) uses for "no session" cannot be returned. No setting changes this.
- **HTTP API payload 2.0 authorizer events reach the pass-through path `/events` only by a type mismatch.** `identitySource` is an array in the event and a string in the crate's request type, so parsing fails and the event falls through. A crate that types the field correctly, or an event without the field, silently turns it back into an HTTP request. The adapter has no test for this path.
- With `AWS_LWA_ERROR_STATUS_CODES` a failing app becomes a function error, but the message is never `Unauthorized`.
- A native Go handler (`aws-lambda-go`) given the same events answered every shape correctly, the REST policy and `Unauthorized` included.

## Decision

- **The authorizer function, for both API Gateway products, is a native Go handler** (`aws-lambda-go`) in the same binary as the HTTP server, chosen by a start-up setting.
- **The authorizer function is the app zip and the configuration layer.** It has no adapter layer.
- **The sign-in function stays behind the adapter**, as 0012 says. So does every other function.
- The handler calls the same check core as the HTTP server. Only the event and answer shapes differ.

This decides the open case of 0012. Its roads-not-taken row "A native handler for the authorizer from the start" was left for the spike to decide, and the spike decided it.

## Consequences

- One binary with two entry points: the HTTP server and the authorizer handler. Both are tested with the same sample events (`spike/lwa/events/`); the unit tests call the handler directly.
- The authorizer does not depend on how the adapter's crates type `identitySource`.
- The real-AWS check (`spike/scripts/aws-check.sh`, parts A and B) still observes how API Gateway reads the native answers: the statuses, the default caching and the event without an identity source.

## Roads not taken

| Road | Why not |
| --- | --- |
| The HTTP API authorizer through `/events`, with `AWS_LWA_ERROR_STATUS_CODES` | It works by a type mismatch that a crate update can undo without warning. It cannot return `Unauthorized`, and it does not cover the REST API at all |
| The REST API authorizer through the adapter | The adapter answers in the HTTP shape and nothing in its configuration changes that |
| A separate binary for the authorizer | A second build and release for the same check core |
