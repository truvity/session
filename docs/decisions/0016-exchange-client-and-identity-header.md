# 0016. The exchange client and the identity header: the choices of step 3.1

Status: accepted, 2026-11-24 (owner decision on the pull request of step 3.1)
Date: 2026-11-24

Builds what [0005](0005-tokens-per-api-and-issuers.md) decides for the route modes `exchange` and `identity-header`, and ends the refusal of those modes at start that [0015](0015-envoy-http-mode-csrf-header-and-step-2-choices.md) set "until step 3".

## Context

Step 3 of the plan lists four parts: the nginx adapter, AWS KMS, the exchange client and the conformance suite. They do not depend on one another in that order, and each is a pull request of its own, as step 2 was three. The exchange client and the identity header come first: they are what 0015 waited for, and the nginx adapter and the conformance suite test the headers they set.

0005 and the design (sections 7 and 9) fix the rules: the cache key, the lock in the store, deletion with the session, a 403 when the exchange is refused, the refresh under the same lock, the identity header signed through the key port and published at `/_session/jwks`, about a minute of life. Where they are silent, the build chose. The issuer of the exchange is sluis v2 once its FAPI work lands, so where a choice touches the request, it follows what the sluis v2 exchange actor serves today (`actors/exchange`, `checkRequest` and `successReply`), and the test issuer is Keycloak 26.8.1's standard token exchange.

## Decision

### The exchange

| Subject | Choice |
| --- | --- |
| The request | RFC 8693 at the issuer's token endpoint with the client's `private_key_jwt` assertion: `subject_token` the session's access token, `subject_token_type` and `requested_token_type` `access_token`, `audience` the route's. No `scope`, `resource` or actor token: sluis refuses each of them |
| The answer | `access_token`, `token_type` Bearer, `issued_token_type` `access_token` when present, and `expires_in`. Any other answer is an outage |
| A refusal | An OAuth error answer (a 4xx with an error code) is a refusal: 403 for the route, the audit event `token-exchange` with the code, the session stays. A 5xx, a timeout or an answer that is not one is an outage: 503 |
| Where the cache lives | Items under the session's store key: `<session key>/e/<keyed hash of audience and scope>`, sealed by the purpose `exchanged` and bound to their key. Not in the session record: a cache write would rewrite the record and race the idle refresh |
| The scope in the cache key | Empty in this version, because the request carries none. The key keeps the place for it |
| Cache life | The token's `expires_in` minus a skew of 30 seconds. A token that lives no longer than the skew is used for its request only |
| The lock | `<session key>/l/<same hash>`, a put on the condition that the key is absent, ending on its own after the exchange timeout. A check that finds it taken looks at the cache every 50 ms until the exchange timeout. The holder looks at the cache once more before it asks the issuer |
| Deletion with the session | The person's logout, a back-channel logout and a failed refresh delete the session item and every item under its key, found by one linearizable `Query` by prefix. Only on a site with an exchange route |
| The exchange timeout | 2 seconds by default (`--exchange-timeout`): the lock, a refresh, the issuer call and the cache write of one check. Every store call inside keeps its own store timeout. The proxy's timeout for the check is longer than both together: 4 seconds in the Envoy example |
| What a refused exchange shows | A navigation (the rule of section 5.3) gets the site's error page, a document of the source port named by `error_page` in the site file, or a built-in page; anything else a JSON `{"error": "exchange_refused"}` |
| The refresh | Before the exchange, under the same lock, when the sign-in access token ends within the skew. The rotated refresh token is written back at the version read; a lost race with an idle refresh reads the session again, so it is never lost |
| A failed refresh | `invalid_grant`, or a session without a refresh token, ends the session (the audit event `refresh-failed`): the check answers as without a session and clears the cookie. Any other refusal (`invalid_client` is a fault of the installation, not of the person) and an outage are 503, and the session stays |
| Audit | `token-exchange` for each exchange, issued or refused, and `refresh-failed`. A cache hit is not an event: it follows traffic |

### The identity header

| Subject | Choice |
| --- | --- |
| The header | `X-Session-Identity`: a compact JWS, ES256, `typ` `session-identity+jwt`, so that an app never takes another JWT of the service for it |
| The claims | `iss` the site's origin (`https://<host>`); `aud` the route's `audience`, or the site's origin when the route names none; `sub`, `name`, `email`, `groups` (always a list) from the claims cached at sign-in; `iat` and `exp`, 60 seconds apart |
| The key | Its own key of the key port, purpose `identity-header`, apart from the client assertion's `client-assertion`. `/_session/jwks` publishes both, each with its kid |
| Reuse | A process keeps each signed header for half its life (30 seconds) for the session and the audience, so a remote key (AWS KMS) signs about twice a minute for each, not on every request. It is asked only after the check has read the session, so a logout is seen at once |
| A key driver that fails | 503 |

### Small fixes on the way

- Deletes go in chunks of 100, DynamoDB's limit for one transaction, not the store contract's 256. The back-channel logout of a person with more than 99 sessions failed on DynamoDB before.
- The allow answer never names a header both to set and to remove, so the result does not depend on the order in which a proxy applies the two lists.

## Consequences

- The modes `exchange` and `identity-header` start. A site file that uses them needs the issuer to allow the exchange for the client and each audience (Keycloak: standard token exchange on the client, and the audience in its access tokens).
- A check on an exchange route reads the session and the cached token: two reads, not one. A miss adds the lock, the issuer call and a write. Session routes still read the session item only.
- An exchange that is in flight when its session is deleted may still write its token under the deleted session's key. Nothing reads it, because no cookie leads to that key any more, and it ends with the token.
- An app that uses the identity header trusts `/_session/jwks` and checks `typ`, `iss`, `aud` and `exp`.
- Against sluis v2, whether its exchange takes the access token of a confidential `private_key_jwt` client (design section 17, question 3) is still open; nothing in this record depends on the answer.
- Nothing here needs atoom's Cedar loader (atoom record 0019, being merged now): the exchange runs after the route policy and does not change it.

## Roads not taken

| Road | Why not |
| --- | --- |
| Exchanged tokens inside the session record | A cache write rewrites the record and races the idle refresh; a record of several tokens grows past one read unit |
| An in-process cache of exchanged tokens | A logout on one replica would leave tokens on the others (decision 0006: no local session state). The identity header's reuse is safe because it is only asked after the session read |
| Wait on the lock without a bound | A dead holder would stall every check of its session until the lock ends |
| End the session on any failed refresh | An issuer outage or a wrong client key would sign everyone out |
| One key for the client assertion and the identity header | One key, two audiences: a key used for both cannot be rotated or moved to KMS on its own |
| Sign the identity header on every request | One KMS call per request once the key is on AWS KMS |
| Send `scope` or `resource` in the exchange | sluis refuses both (`invalid_scope`, `invalid_target`) |
