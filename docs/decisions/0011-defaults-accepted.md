# 0011. Defaults of the first draft accepted

Status: accepted, 2026-11-18

## Context

The first draft of the design chose defaults where the maintainer's list was silent. The maintainers reviewed them.

## Decision

Accepted as written:

| Default | Value | Road not taken |
| --- | --- | --- |
| Paths | Under `/_session/`: login, callback, logout, backchannel-logout, whoami (and `jwks`, see 0012) | A path for each adapter |
| Store key | A keyed hash of the cookie id, so a store leak gives no usable cookie | The id itself |
| Record encryption | AES-256-GCM, the session id as associated data, data keys from the key port | Plain records |
| Lifetimes | 30 minutes idle, 8 hours maximum, set for each site | No defaults |
| Site config | YAML | JSON, or a custom format |
| Store failure | Fail closed: 503, never allow | Fail open |
| No session | Redirect for a top-level navigation (`GET`, `Sec-Fetch-Mode: navigate`, `Accept` has `text/html`), JSON 401 otherwise | A flag only, or always 401 |

## Consequences

- The design, the conformance suite and the examples can rely on these values.
- A site may change the lifetimes. The paths, the fail-closed rule and the cookie rules are not per site.
