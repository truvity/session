# 0007. Issuers, and the sluis v1 check

Status: accepted, 2026-11-18 (decisions E7 B, E9 A, E8)

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
