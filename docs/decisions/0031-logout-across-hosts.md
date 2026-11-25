# 0031. Logout across hosts: the issuer's end-session, back-channel logout, tombstones, cookies and audit

Status: proposed, 2026-11-25; needs the owner's choices L1 to L3
Date: 2026-11-25

Collects logout in one place for every host (Envoy, nginx, API Gateway on Lambda) and proposes what to change. It keeps S6 of [0004](0004-browser-session-contract.md), the tombstone read at creation of [0010](0010-logout-pointer-items.md) and the logout answer of [0015](0015-envoy-http-mode-csrf-header-and-step-2-choices.md). It is the "new record then" that 0015 named for the logout lookup. The number 0017 is reserved (the decisions README); 0028 to 0030 are other records, so this record is 0031.

## Context

What session does today, built and run in the conformance suite on Envoy (gRPC and HTTP) and nginx against Keycloak:

| Part | Today |
| --- | --- |
| The person's logout | `POST /_session/logout` with CSRF (S5). It loads the session, deletes it and the items under its key (cached tokens, locks), emits `logout`, clears `__Host-<site>`, and sends the browser to the issuer's `end_session_endpoint` with `client_id`, `post_logout_redirect_uri` (the site's `/`) and `id_token_hint`: as `200 {"logout_url"}` to a request that accepts JSON, as `303` otherwise (0015). Without a live session it clears the cookie and sends the browser to the site's `/`, not to the issuer |
| Back-channel logout | `POST /_session/backchannel-logout` (OIDC Back-Channel Logout 1.0): the logout token's signature, `iss`, `aud`, `exp`, `typ`, the `events` claim, no `nonce`, a `sid` or a `sub`, a `jti` and an `iat`. The `jti` is claimed once until the token ends (a replay is refused). Then `LogoutBy`: a tombstone by `sid` (or by subject when there is no `sid`), a linearizable read of the pointer item, and the deletion of the sessions it lists with their items and the pointer. It answers 200, 400 for a refused token and 503 for a store outage, so the issuer retries |
| Tombstones | Written by every back-channel logout, living as long as the maximum session lifetime, read once by the callback: a sign-in that started before a logout of its `sid` or subject ends at once (`logged_out`) |
| The lookup | Pointer items under `p/sid/` and `p/sub/`, keyed hashes of issuer and value, written in the session's creation transaction with a version condition on each pointer; a lost race reads again (20 tries) |
| Audit | `logout` (success, the person's pseudonym), `back-channel-logout` (success, or failure with the reason), `denied` with the operation `logout` for a CSRF refusal (0023). Best effort: a logout never waits on the transport |
| What a check sees after a logout | The session item is gone, so the next check on any replica is a redirect or a 401. There is no local cache (section 8) |

What differs by host:

| | Envoy | nginx | API Gateway and Lambda |
| --- | --- | --- | --- |
| The logout paths | `/_session/` is routed to the service without a check (`ExtAuthzPerRoute` disabled) | `location /_session/` is a `proxy_pass` without `auth_request`, so every `Set-Cookie` of the answer passes (the single-cookie limit of 0011 is `auth_request_set`'s only) | The HTTP API sends `/_session/{proxy+}` to the sign-in function behind the Web Adapter without the authorizer; each `Set-Cookie` becomes an entry of the response's `cookies` array ([0030](0030-lambda-handlers-step-5-choices.md)) |
| Where the issuer posts back-channel logout | The proxy's sign-in prefix, or the Service | The proxy's sign-in prefix | The API's public endpoint: the issuer must reach it |
| The next request after a logout | The check's redirect or 401 | The same, through the markers | The authorizer's `Unauthorized`, because its cache is 0 seconds (0011); a site that opts into a TTL logs out up to that TTL late |
| A cookie the check clears | Every cookie | The first only (0011) | Not at all: an authorizer cannot send `Set-Cookie` (0030) |

What is not settled:

- **The lookup.** 0015 kept 0010's pointer items "as 0010 says" and said atoom's index entries would replace them by a new record. The fit spike ([section 2.3.1](../spike-2026-11-22.md)) found index entries a fit and better: no read-modify-write at sign-in (sixteen parallel sign-ins of one subject: 16 tries against 64), no bound of the item size on the set. The trap it found: every `Put` of an item must resend all its entries, the idle refresh too.
- **A logout without a live session** does not reach the issuer, so the person's session at the issuer stays and the next sign-in passes without a form.
- **The refresh token** stays valid at the issuer after the person's logout until the issuer's end-session ends the issuer session. If the browser never reaches end-session (the helper's navigation fails, the tab is closed), the token lives on at the issuer, though session no longer holds it.

## Decision (proposed)

### L1. The lookup of a back-channel logout: owner choice

| Option | Pros | Cons |
| --- | --- | --- |
| **A. Pointer items (today, 0010)** | Built and tested; a logout is one linearizable `Get` | A read-modify-write on every sign-in, retried on a lost race (64 tries for 16 parallel sign-ins of one subject); the set grows inside one item (400 KB on DynamoDB); a stale member costs a failed delete |
| **B. atoom's index entries** (spike 2.3.1) | The store's own feature: the session `Put` carries two entries, `sid` and `sub`, whose values are the keyed hashes of issuer and value (never the plain `sid` or subject); a logout is a linearizable `Query` by entry and one `Transact` of deletes; no pointer to keep; no size bound; no retries at sign-in | Every `Put` of the session (the idle refresh, the rotated refresh token) must resend both entries, or they are deleted; a logout is a `Query` and a `BatchGetItem` instead of one `GetItem` (logout is rare); the linearizable `Query` seeing a session committed a moment before is documented by atoom's driver but must be observed on the real service (DynamoDB Local cannot show it); the store double must keep entries (it does) |

**Pick B**, before the first site has sessions that matter: nothing sealed or stored needs to be read again, and sessions end within the maximum lifetime (8 hours by default). The tombstone and its one read at creation stay as they are. A test asserts that an idle refresh and a refresh-token rotation keep both entries.

### L2. A logout without a live session: owner choice

| Option | Pros | Cons |
| --- | --- | --- |
| A. Local only, to the site's `/` (today) | No page at the issuer | The issuer's session stays: "sign out" does nothing visible, and the next sign-in passes without a form |
| **B. Always to the issuer's end-session**, with `client_id` and `post_logout_redirect_uri`, and `id_token_hint` when the session is live | "Sign out" always ends the issuer's session when the person confirms | Without `id_token_hint`, Keycloak asks the person to confirm (a finding of the reference stand, [0013](0013-reference-stand.md)) |
| C. To end-session only when a cookie was sent | Fewer confirmation pages | A person whose session ended at session (idle, back-channel of another site) still keeps the issuer's |

**Pick B.** The JSON and `303` answers of 0015 stay; only the target changes when there is no live session. An issuer without `end_session_endpoint` still gets the site's `/`.

### L3. The refresh token at the person's logout: owner choice

| Option | Pros | Cons |
| --- | --- | --- |
| A. Nothing (today): the end-session ends it | No issuer call at logout | The token stays valid at the issuer if the browser never reaches end-session |
| **B. Revoke it, best effort** (RFC 7009 at the issuer's `revocation_endpoint`, with the client's `private_key_jwt` assertion), after the session is deleted and before the answer, bounded by the exchange timeout | The token is dead whatever the browser does next; an issuer may also end the client's session with it | One issuer call at each logout; an issuer that does not answer delays the logout by the bound |
| C. Revoke, and fail the logout when the issuer refuses | The strongest | A logout that fails while the issuer is down keeps nothing alive at session (the session is already deleted) but tells the person it failed |

**Pick B.** Only when the discovery document names a `revocation_endpoint`; a failed revocation is counted (`session_logout_revocation_failed_total`) and logged, and the logout goes on. sluis v2's revocation endpoint is not known yet; without one, B is A.

### L4. Cookies at logout

**Clear both of session's cookies**: `__Host-<site>` (today) and the sign-in binding cookie `__Host-<site>-signin`, which a sign-in left unfinished may still hold. Every host passes both, because the logout answer is not a check answer (the table above). No `Clear-Site-Data`.

| Road | Why not |
| --- | --- |
| `Clear-Site-Data: "cookies"` | It clears the site's own cookies too, which session does not own |
| `Clear-Site-Data: "cache"` | The pages the site serves behind session and their caching are the site's; a site that wants it sets it on its own logout page |

### L5. A cookie whose session is gone

**Leave it** (today). After a back-channel logout, an idle end or a deleted session, the cookie stays in the browser until the next sign-in replaces it; each check with it costs the one read the check makes anyway, and answers a redirect or a 401.

| Road | Why not |
| --- | --- |
| Clear it on a check that finds no session | A check of a request sent before a sign-in in another tab, answered after the callback, would clear the new cookie and sign the person out; and API Gateway cannot send it anyway |

The one place the check clears the cookie stays: a session that ends at a refused refresh (0016).

### L6. Audit

**Unchanged events, best effort, never blocking.** A logout that waited on the transport would keep a session alive while audit is down, the opposite of what blocking buys at a sign-in. `logout` stays one outcome, success, emitted after the deletion; a logout without a live session emits nothing (there is no person to name). `back-channel-logout` stays as it is. A revocation (L3) is not an event: it is part of a logout that already has its record, and its failure is a metric.

### L7. Hosts

Nothing new per host. On API Gateway the authorizer cache stays 0 (0011), so a logout is seen at the next request; the back-channel path must be reachable from the issuer on every host; the HTTP API route of the sign-in prefix has no authorizer. The conformance suite's logout and back-channel scenarios run on API Gateway with the real-AWS check of step 5.

## Consequences

- L1 B changes `core/store.go`: `Create` puts the session with two index entries and no pointer items, `touch` and the refresh resend them, `LogoutBy` queries by entry; the pointer code goes. The store tests and `just test-dynamodb` cover it; the real service's linearizable `Query` joins the real-AWS check (design section 17).
- L2 B and L3 B change `internal/signin`'s `Logout` and need the issuer's `revocation_endpoint` from discovery. The conformance suite's logout scenario then also asserts the end-session without a live session and, on Keycloak, that the refresh token is refused after a logout.
- L4 adds one `Set-Cookie` to the logout answer.
- Nothing changes for a site's configuration, the site file or the start-up flags.

## Roads not taken

| Road | Why not |
| --- | --- |
| Front-channel logout (OIDC Front-Channel Logout 1.0) | It needs the issuer's page to load session's page in an iframe with session's cookie; browsers block third-party cookies, and back-channel logout already reaches every replica |
| A tombstone at the person's own logout | The session is deleted by its own key; a tombstone by `sid` would also end other browsers' sessions of the same issuer session, which the issuer's end-session and its back-channel logout do when the person confirms |
| "Sign out everywhere" (every session of the subject) at the person's logout | Not asked for; the issuer's end-session and back-channel logout are the way to end the person's other sessions |
| A logout over `GET` | CSRF (S5); a link or an image could sign the person out |
| A blocking `logout` event | See L6 |

## Open

- The owner's choices L1, L2 and L3.
- sluis v2's end-session, back-channel logout and revocation endpoints: what session needs is in this record; when sluis serves them is sluis's to say (step 6).
