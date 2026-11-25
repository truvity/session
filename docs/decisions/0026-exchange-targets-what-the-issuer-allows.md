# 0026. The route mode `exchange` targets what the site's issuer allows: with sluis v2, resource clients only

Status: accepted, 2026-11-25 (owner decision)
Date: 2026-11-25

Adds a constraint per issuer to the per-API exchange of [0005](0005-tokens-per-api-and-issuers.md) and [0016](0016-exchange-client-and-identity-header.md). It keeps every rule of those records: how the check exchanges, caches, locks and refreshes is unchanged. It settles what sluis v2 as an issuer can be asked for, which design section 17, open question 3, left open, and it names what is still to ask the sluis side.

## Context

[0005](0005-tokens-per-api-and-issuers.md) decided that the check exchanges the session's token for a token of each API's audience (RFC 8693) at the site's issuer, and it named sluis v2 as the target issuer. It asked whether sluis v2's exchange would take the access token of a confidential `private_key_jwt` client as subject token. A site file names one issuer, and the exchange of a route of mode `exchange` goes to that issuer.

sluis's own records on its v2 branch `main` (read 2026-11-25) decide what its exchange serves:

- **What it issues for.** sluis's exchange issues tokens only for resource clients (an AWS role, Kubernetes, a database, SSH, a vendor minter, KV), whatever the subject token is, and never for a sign-in client. A product API takes the group identity provider's tokens, never a sluis token ([sluis 0051](https://github.com/truvity/sluis/blob/main/docs/decisions/0051-exchange-targets-resource-clients-only-and-policy-decides-who-gets-what.md), [sluis 0048](https://github.com/truvity/sluis/blob/main/docs/decisions/0048-product-apis-take-the-identity-providers-tokens.md), requirement REQ-EXCH-030).
- **What it takes as subject.** Until `private_key_jwt` client authentication exists, the exchange accepts as subject token only a token issued to a public client of the native profile, and lifting that rule needs a marker against exchanging an exchanged token first ([sluis 0022](https://github.com/truvity/sluis/blob/main/docs/decisions/0022-workload-identity-and-host-enrolment.md), requirement REQ-EXCH-020). session is a confidential `private_key_jwt` client, so it is refused today.

## Decision

### The audience of a route of mode `exchange` is one the site's issuer allows

| The site's issuer | What a route of mode `exchange` may name as its audience |
| --- | --- |
| sluis v2 | A resource client only: an AWS role, Kubernetes, a database, SSH, a vendor minter or KV. Never a product API and never another sign-in client |
| Keycloak, or another issuer whose exchange allows it | What that issuer allows for the site's client, product APIs included, as today ([0005](0005-tokens-per-api-and-issuers.md), [0016](0016-exchange-client-and-identity-header.md)) |

### Product APIs behind session

A product API behind session takes the group identity provider's tokens, not a sluis token. It gets the person in one of two ways, as today:

- **The identity header** (route mode `identity-header`), signed by session ([0005](0005-tokens-per-api-and-issuers.md), [0016](0016-exchange-client-and-identity-header.md)), on a site of any issuer.
- **An exchange at an issuer that allows it,** such as Keycloak: the route of mode `exchange` names the product API's audience on a site whose issuer is that one.

A site whose issuer is sluis v2 therefore uses the identity header for its product APIs, and the mode `exchange` for its resource clients only.

### What sluis v2 as an issuer waits for

Step 6 of the plan, sluis v2 as an issuer, is scoped to resource-client audiences. It waits for sluis's exchange to accept session's subject token, which the sluis side plans as the row REQ-EXCH-032: once `private_key_jwt` and the marker against re-exchange exist, a confidential sign-in client that authenticates by `private_key_jwt` may present the access token of its live sign-in as subject token, for a resource client's audience, and an ID token and a token the exchange itself issued are refused. Until that row is built, a site on sluis v2 has no route of mode `exchange`.

## Consequences

- No change to session's code. The exchange, its cache, its lock and its refresh are the same for every issuer.
- session does not refuse a product API's audience on a sluis v2 site at start: the site file does not say which kind of client an audience is, and only sluis knows it. sluis refuses such an exchange (REQ-EXCH-030), and the route answers 403 as for any refused exchange; the conformance run of the deployed site shows the mistake. A check at start would need sluis's client registry, and is not worth that today.
- Sites whose product APIs need a token rather than the identity header keep an issuer that allows the exchange for them, such as Keycloak.
- The question that 0005 left open is answered for the targets (resource clients only) and narrowed for the subject to the one row on the sluis side.

## Roads not taken

| Road | Why not |
| --- | --- |
| Ask sluis to issue tokens for product APIs too | Against sluis 0051 and 0048: a product API never receives a sluis token, and a sign-in client's token comes by sign-in only |
| Forward the session's own sluis token to product APIs | Refused by [0005](0005-tokens-per-api-and-issuers.md): one token would be valid on every API, and a product API takes the group identity provider's tokens |
| A second issuer per site, sluis for resource clients and Keycloak for product APIs | A site signs in at one issuer, and a token of one issuer is not a subject token at the other; the identity header serves product APIs on a sluis site without it |
| Refuse at start, in the site file, an audience that is not a resource client | session cannot tell from the audience; it would need a kind per route or sluis's client registry, and sluis refuses the exchange anyway |
| Register session at sluis as a public native client, to pass REQ-EXCH-020 today | Rejected in [0005](0005-tokens-per-api-and-issuers.md): no client authentication and no PAR, and the token would be exchangeable by whoever holds it |

## Open

- On the sluis side, the row REQ-EXCH-032: when `private_key_jwt` and the marker against re-exchange are built, and with them the exchange of a confidential sign-in client's live sign-in token. Also there: whether that client signs in by the authorization code with PAR, which sluis serves only to public clients today.
