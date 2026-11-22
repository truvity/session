# 0008. Audit: the security class only, never usage

Status: accepted
Date: 2026-11-20

## Context

A browser-session service sees sign-ins, logouts and denials, which security audit needs. It also sees every allowed request, which would be a durable write each if logged one by one. The audit product, [`truvity/audit`](https://github.com/truvity/audit), is built on atoom's ports. It has two classes: the security-audit class (loss is counted, and it never blocks) and the usage class (never dropped, a blocking emit).

## Decision

- `session` emits **security-audit events** through the emitter of `truvity/audit`, over atoom's `transport` port. Events: sign-in, logout (local and back-channel), refresh failures, token exchanges and denials.
- A check **never waits on audit** for a decision.
- A sign-in completes only after its event is accepted by the transport.
- **Allowed requests are counted as metrics.** They are not logged one by one.
- The events go to the **audit writer of the environment**.
- When the transport is down, checks keep being answered. Dropped events are counted and raise an alert.
- **`session` never emits usage or billing records.** A product behind `session` meters its own usage.
- Each Cedar decision is audited with the digest of its policy set ([0007](0007-policy.md)).

Decided by [0015](0015-envoy-http-mode-csrf-header-and-step-2-choices.md): in the first version a sign-in fails closed while the transport is down.

State: the emitter in Go is planned in `truvity/audit`.

## Consequences

- An audit outage does not stop sites. Its cost is counted loss, which the alert makes visible.
- The volume of audit follows sign-ins and denials, not traffic.
- `session` needs no audit writer of its own.

## Roads not taken

| Road | Why not |
| --- | --- |
| A writer for each `session` installation | Many writers to run and secure, and the log of the environment would be split |
| Log each allowed request | The volume follows traffic |
| Each allowed request as a usage record | A durable write on every request |
