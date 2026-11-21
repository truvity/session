# 0009. Ports shaped like the sluis v2 building blocks

> Archived. Kept as history; the current decision is [0006](../0006-built-on-atoom.md). The numbers in this file are those before the clean rewrite of the records (see the [renumbering table](../README.md#renumbering-in-the-clean-rewrite)).

Status: accepted, 2026-11-18 (decision P1, option A). Superseded by [0006 (renumbered)](../0006-built-on-atoom.md) on 2026-11-20: session uses atoom's ports and blocks, not interfaces of its own.

## Context

`session` needs a place for sessions, keys to sign and encrypt with, and a policy for each route. sluis v2 is being built from building blocks with the same needs: `store`, `key` and `policy`. Its core is not finished (alpha.2 is the target).

## Options considered

| Option | For | Against |
| --- | --- | --- |
| A. Go interfaces in `truvity/session` shaped like the sluis blocks. Switch to the blocks once the sluis core is done | We start now. The switch is a change of implementation | We keep a small copy of the shapes until the switch |
| B. Use the sluis building blocks now | No duplicate interfaces | Waits for a sluis alpha. Couples us to APIs that still change |
| C. Our own interfaces for good | Full independence | Duplicates sluis for ever |

## Decision

A. Three ports:

| Port | Shaped like | Job |
| --- | --- | --- |
| Session store | sluis `store` | get, put, delete, conditional update, expiry |
| Key | sluis `key` | sign, public keys (JWKS), data keys for record encryption |
| Policy | sluis `policy` | per-route decisions: which API token a route needs, who may reach it |

First implementations: DynamoDB for sessions, a key file and AWS KMS for keys, policy from the site file. Switch to the sluis building blocks once the sluis core is done (alpha.2).

## Consequences

- The check core depends on interfaces only. Storage, keys and policy can change without touching it.
- The shapes follow sluis, so the later switch is small.
- Until the switch we maintain the interfaces and watch the sluis ones for changes.
- Resolves the questions about the `private_key_jwt` key and the identity-header key: both go through the key port (0012).
