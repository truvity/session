# 0007. Issuers, and the sluis v1 check

Status: accepted, 2026-11-18 (decisions E7 B, E9 A, E8). Amended after the first spike, coordinator's call 2026-11-18, for review: E8 is answered, see the end

## Context

`session` needs an issuer with PAR and `private_key_jwt`. sluis v2 will have them once its FAPI work lands. Keycloak has them now. Some sites still run on sluis v1.

## Options considered

| Option | Meaning |
| --- | --- |
| E7 A | Plain client secret, no PAR |
| E7 B | PAR and `private_key_jwt`, because the issuers have them |
| E9 A | Issuers are sluis v2 (once FAPI lands) and Keycloak (used to build and test first) |
| E9 B | sluis only, wait for it |

## Decision

- E7 B: use PAR and `private_key_jwt`.
- E9 A: the issuers are sluis v2 once its FAPI work lands, and Keycloak. Keycloak is used to build and test first.
- E8: the first spike checks one thing. Does the token exchange of sluis v1 accept the proxy's sign-in token? The answer tells us whether sites on v1 can use `session` before the switch.

## Consequences

- No shared client secret in the service.
- The first version does not wait for sluis v2.
- Keycloak stays in the test suite as a second issuer, which keeps `session` from depending on sluis quirks.
- If the E8 check fails, sites on sluis v1 wait for v2.

## E8 answered by the first spike (coordinator's call 2026-11-18, for review)

Question: does the token exchange of sluis v1 accept the proxy's sign-in token as subject token for another audience?

**No.** Source: github.com/truvity/sluis, branch `master`, commit `2057194b1` (v1.85.0), read-only. No live call was made.

| Finding | Evidence |
| --- | --- |
| The feature is `sign_in_exchange`. The subject token must be the access token of a live sign-in, never an ID token | `internal/issuer/storage.go:3088` (`signInProof`), `:3092-3096` |
| The token must be one the issuer recorded, and its client must declare `sign_in_exchange` | `storage.go:3099-3111` |
| It must be presented by the client it was issued to | `storage.go:3113-3117` |
| The subject must be a person with a live session. Agent-class, recovery and conformance sessions are refused | `storage.go:3119-3151` |
| `sign_in_exchange: true` is refused at policy load on any client that is not `public` | `policy/policy.go:1217-1219` (field documented at `:615-624`); with `session: agent` at `:1243-1247` |
| v1 has no `private_key_jwt` at the token endpoint (a client's method is none or Basic) | `internal/issuer/provider.go:59`, `internal/issuer/client.go:51-62` |
| v1 has no PAR (`request_uri` is refused) | `internal/issuer/surface.go:106-108`, `docs/concepts/sluis/not-served.md:29` |
| One audience for each exchange, gated by the target client's `requires` | `storage.go:2979-2990`, `:3000-3008` |

`session` as designed is a confidential `private_key_jwt` client with PAR, so v1 refuses its sign-in as a subject token and offers neither PAR nor `private_key_jwt`.

Decision: sites on sluis v1 wait for v2, as foreseen for the "no" case. A workaround that registers `session` as a `public` client with PKCE and `sign_in_exchange: true` is rejected: it means no client authentication and no PAR, and the issuer checks only the client id of a public client, so the access token is exchangeable by whoever holds it. That is the CLI model, not a web service's.

What `session` needs from sluis v2: the token exchange accepts the access token of a confidential `private_key_jwt` client as subject token, presented by the same client, and refuses an ID token. The coordinator files this with the sluis v2 owners.
