# 0005. Per-API tokens by token exchange, and the issuers

Status: accepted
Date: 2026-11-18

## Context

A site's pages call several APIs. The session holds the person's sign-in token. Each API should get a token meant for it only.

`session` also needs an issuer with PAR and `private_key_jwt`. sluis v2 will have them once its FAPI work lands. Keycloak has them now. Some sites still run on sluis v1.

## Decision

### Tokens

- **Exchange per API.** For every API route, the check exchanges the session token for a token of that API's audience (RFC 8693), caches it and carries it in the allow answer's headers.
- **Identity header, opt-in.** A route may ask for a signed identity header with the user and groups, for apps that cannot handle tokens. The service signs it through the key port with its own key. The public keys are at `/_session/jwks`. The header lives about a minute.
- **Rules of the exchange.**
  - The cache key is session id, audience and scope. An entry expires with the token, minus a skew.
  - A short lock (single flight) in the store stops parallel requests from exchanging at once. The same lock serves the refresh.
  - Cache entries are deleted with the session, at logout and at back-channel logout.
  - A refused exchange gives a JSON 403 on an API route and a plain error page on a page route, from a template for each site. The session stays.
- **Refresh.** The refresh token is stored. It is refreshed under the lock when the access token is old. If the refresh fails, the session ends.
- **Where the token travels.** On the API Gateway HTTP API the per-API token travels in `X-Session-Token`, because `Authorization` is reserved in parameter mapping ([0011](0011-host-adapter-rules.md)). The site ignores a browser-sent `Authorization`.

### Issuers

- Sign-in uses PAR and `private_key_jwt`, so the service holds no shared client secret. The `private_key_jwt` key lives behind the key port ([0006](0006-built-on-atoom.md)): a key file for a simple start and for Keycloak, AWS KMS where the key must never leave the HSM.
- The issuers are sluis v2, once its FAPI work lands, and Keycloak. Keycloak is the first issuer to build against and stays in the test suite as a second issuer, so `session` does not depend on sluis quirks.
- **Sites on sluis v1 wait for v2.** v1 cannot serve `session`:

  | Finding | Source in sluis v1.85.0 |
  | --- | --- |
  | Token exchange works only for a sign-in access token (feature `sign_in_exchange`), never an ID token | `internal/issuer/storage.go`, `signInProof` |
  | The token must be one the issuer recorded, presented by the client it was issued to, for a person with a live session | the same function |
  | `sign_in_exchange: true` is refused at policy load on any client that is not `public` | `policy/policy.go` |
  | No `private_key_jwt` at the token endpoint, and no PAR | `internal/issuer/provider.go`, `surface.go` |

  `session` is a confidential `private_key_jwt` client with PAR, so v1 refuses it. A workaround that registers `session` as a `public` client with `sign_in_exchange: true` is rejected: it means no client authentication and no PAR, and the access token would be exchangeable by whoever holds it. That is the model of a command-line tool, not of a web service.
- **What `session` needs from sluis v2.** Its token exchange accepts the access token of a confidential `private_key_jwt` client as subject token, presented by the same client, and refuses an ID token. Open: whether sluis v2 provides this. It is a request to the sluis v2 owners.

## Consequences

- A leaked token works for one API only.
- The check needs a cache and a lock, so parallel requests make one exchange.
- The issuer must allow the exchange for each client and audience.
- Apps that use the identity header trust the service's signing key.
- No shared client secret is in the service, and the first version does not wait for sluis v2.
- If sluis v2 does not provide the exchange above, sites on sluis wait, and Keycloak stays the issuer.

## Roads not taken

| Road | Why not |
| --- | --- |
| Forward the session token to every API | One token would be valid everywhere, so a leak in one API opens all of them |
| Only a signed identity header | Apps that can handle tokens should get a token meant for them. The header is an opt-in |
| A shared HMAC for the identity header | Every app would become a signer |
| An exchanged token for the identity header | That is the exchange mode itself |
| A plain client secret, no PAR | A shared secret in the service, and the parameters on the browser's URL bar |
| sluis only, wait for it | Nothing could be built or tested before v2 |
| No refresh | Sessions as short as one access token |
