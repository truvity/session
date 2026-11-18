# 0006. Per-API tokens by token exchange

Status: accepted, 2026-11-18 (decision E4, option A, with C as opt-in)

## Context

A site's pages call several APIs. The session holds the person's sign-in token. Each API should get a token meant for it only.

## Options considered

| Option | Meaning |
| --- | --- |
| A | Exchange the session token for a token of each API's audience (RFC 8693), cache it, carry it in the allow answer's headers |
| B | Forward the session token to every API |
| C | A signed identity header with user and groups, made by the check |

## Decision

A for every API route. C as an opt-in for each route, for apps that cannot handle tokens. B is rejected: one token would be valid everywhere, so a leak in one API opens all of them.

## Consequences

- A leaked token works for one API only.
- The check needs a cache and a lock, so parallel requests make one exchange.
- The issuer must allow the exchange for each client and audience.
- Apps using C trust the check's signing key. The key and its lifetime are an open question in the design.
