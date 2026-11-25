# 0033. sluis v1 as an issuer: the gaps, and what session and sluis v1 each change

Status: accepted, 2026-11-25 (owner decision: D92 A, session supports sluis v1 as an issuer now; on this record O1 A, O2 A, O3 A, O4 B, O5 A)
Date: 2026-11-25

Supersedes, for sites whose issuer is sluis v1, the row "The issuer" of [0025](0025-first-version-for-the-first-sites.md) and the line "Sites on sluis v1 wait for v2" of [0005](0005-tokens-per-api-and-issuers.md) and design sections 12 and 16. It keeps every other rule of those records, and every rule of [0016](0016-exchange-client-and-identity-header.md), [0019](0019-signing-keys-on-aws-kms.md), [0026](0026-exchange-targets-what-the-issuer-allows.md) and [0031](0031-logout-across-hosts.md). Keycloak stays the issuer of the first sites; sluis v2 stays step 6.

## Context

The owner decided (D92 A) that session supports sluis v1 as an issuer now, so that an internal staff tool which trusts sluis directly can go behind session on the development environment. A technical service never trusts a Keycloak realm (the group architecture's rule), so Keycloak is not an answer for it, and sluis v2 is not ready.

[0005](0005-tokens-per-api-and-issuers.md) found, in sluis v1.85.0, that v1 has no PAR and no `private_key_jwt`, and that its token exchange takes a sign-in token only from a `public` client. This record reads sluis v1.87.1 (branch `master`, read 2026-11-25) again, against everything session asks of an issuer today, and lists what is missing.

The multi-issuer work (D84) is record 0034, in its own pull request. On `master` a site file names one issuer. Each choice below is a property of the site's issuer: under 0034, each per-issuer entry carries its own `par` and its own scopes.

### What session asks of an issuer today

| Need | Where in session |
| --- | --- |
| Discovery, with `pushed_authorization_request_endpoint`; start fails without it | `internal/signin` `New` (S3) |
| PAR (RFC 9126) with the client's `private_key_jwt` assertion; the browser carries only `client_id` and `request_uri` | `Login` |
| PKCE S256, `state`, `nonce` | `Login` |
| `iss` in the authorization response (RFC 9207), strict when discovery says so | `Callback` |
| The code redeemed with `private_key_jwt`; an ID token with `aud`, `azp`, `nonce`, and `sid` for back-channel logout | `Callback` |
| `client.auth: private_key_jwt`, the only value the site file accepts | `internal/site` |
| A `groups` claim in the ID token, read by the Cedar policy and the identity header | `Callback`, `core/identity.go` |
| Refresh tokens, refreshed with `private_key_jwt` before an exchange | `internal/exchange` (0016) |
| Token exchange (RFC 8693) of the session's access token, with `private_key_jwt` | route mode `exchange` (0016, 0026) |
| `end_session_endpoint` with `client_id`, `post_logout_redirect_uri`, `id_token_hint` | `Logout` (0031 L2) |
| `revocation_endpoint` with `private_key_jwt`, best effort | `Logout` (0031 L3) |
| Back-channel logout to `/_session/backchannel-logout`, a logout token with `sid` or `sub`, `jti`, `iat`, the event | `BackChannel` (0031 L1) |

### What sluis v1.87.1 serves

The OpenID provider is the zitadel-oidc `op` package v3.51.16, vendored under `third_party/zitadel-oidc` with six small patches, assembled in `internal/issuer/provider.go`, with sluis's own checks in front of it.

| Feature | sluis v1.87.1 | Source |
| --- | --- | --- |
| Client authentication of a confidential client | `client_secret_basic` (the client's method); `client_secret_post` is also accepted (`AuthMethodPost: true`); a public client uses `none` with PKCE | `client.go` `AuthMethod`, `provider.go` |
| `private_key_jwt` | **Off**: `AuthMethodPrivateKeyJWT: false` ("stays off until a client needs it"); the storage hook `GetKeyByIDAndClientID` answers "not wired"; discovery withdraws `token_endpoint_auth_signing_alg_values_supported` | `provider.go`, `storage.go`, `provider.go` `unservedDiscoveryFields` |
| The vendored library and `private_key_jwt` | Supported at the code, refresh and revocation grants (`AuthorizePrivateJWTKey`: `iss` = `sub` = the client, `aud` the issuer, `exp`, `iat` within an hour, signature by a key from `GetKeyByIDAndClientID`; ES256 is in its default list). **Not** at the token exchange grant, whose client check takes an id and a secret only. It never checks `jti` for replay | `third_party/zitadel-oidc/pkg/op/token_request.go`, `token_code.go`, `token_refresh.go`, `token_revocation.go`, `token_exchange.go` `AuthorizeTokenExchangeClient`, `verifier_jwt_profile.go` |
| PAR (RFC 9126) | **No**: the library has none, and `/authorize` refuses `request_uri` (`request_uri_not_supported`) | `surface.go` `authorizeSurface` |
| PKCE | S256 only; `plain` never. Required for a public client, and for a confidential one that declares `pkce: required` | `provider.go` `CodeMethodS256`, `policy/policy.go` `PKCERequired` |
| `iss` in the authorization response (RFC 9207) | Yes, on every success and error redirect, and `authorization_response_iss_parameter_supported: true` | `issparam.go`, `provider.go` `truthfulDiscovery` |
| Redirect URIs | Exact match for a web (confidential) client; a loopback port is free for a native client only | the library, `surface.go` |
| End-session | `/end_session`; `post_logout_redirect_uri` must be one of the client's `signed_out` (not its redirects); a page asks the person unless the `id_token_hint` names the person signed in in that browser | `client.go`, `surface.go` `confirmedEndSession` |
| Revocation | `/revoke` (RFC 7009); `private_key_jwt` there once it is on | `provider.go` |
| Back-channel logout | Yes, per client and opt-in (`backchannel_logout_uri`): `typ` `logout+jwt`, `iss`, `aud` the client, `iat`, `exp`, `jti`, `sub`, `sid` when the sign-in opened a session, the event, no `nonce`. Posted within 5 seconds, no redirect followed, private addresses allowed | `backchannel.go` |
| `sid` in the ID token | Only when the code opens a session, which takes `offline_access`; `openid` alone opens none | `storage.go` `SetUserinfoFromRequest`, `sessionOf` |
| Refresh tokens | Yes, with `offline_access`, rotated, with reuse detection | `provider.go`, `refresh_*` |
| `groups` | Yes, in the ID token and userinfo (`groups` is a supported claim; claims are asserted in the ID token), the internal group names, with an optional per-client delimiter | `provider.go`, `client.go`, `claims.go` |
| `sub` of a person | The person's email address | `exchange.go` `Proof.Subject` |
| ID token signing | ES384 by default; a client may pin another algorithm (`signing_alg`) | `policy/policy.go` |
| Token exchange | Subject tokens: a GitHub Actions token, a Kubernetes service account token, an AWS outbound identity token, or the access token of a live sign-in to a **`public`** client with `sign_in_exchange`, presented by that client (refused at policy load on any other kind). Audience: exactly one declared client that admits the subject's groups and its exchange limits. No actor token | `storage.go` `signInProof`, `ValidateTokenExchangeRequest`, `exchange.go`, `policy/policy.go` |

## The gaps

| # | session needs | sluis v1.87.1 | Options | Pick |
| --- | --- | --- | --- | --- |
| G1 | `private_key_jwt` at the token, refresh and revocation endpoints | Off, though the vendored library supports it | (a) a `client_secret_basic` mode in session for this issuer only; (b) turn it on in sluis v1 | **(b)** |
| G2 | PAR | None, and `request_uri` refused | (a) a no-PAR mode in session for an issuer whose discovery has no PAR endpoint; (b) build PAR in sluis v1 | **(a)** |
| G3 | Token exchange of a confidential client's sign-in token (route mode `exchange`) | Refused: only a `public` client's sign-in; and the library's exchange grant takes no `private_key_jwt` | (b) open `sign_in_exchange` to a confidential `private_key_jwt` client in sluis v1; (c) no route of mode `exchange` on a sluis v1 site | **(c)** |
| G4 | `sid` in the ID token, and a refresh token to revoke at logout | Only with `offline_access` | Configuration only: the site's `scopes` name `offline_access` | Configuration |
| G5 | Back-channel logout, end-session, revocation, PKCE S256, RFC 9207 `iss`, `groups` | Served | None: configuration of the sluis client (below) | None |

### G1. Client authentication

| Option | Pros | Cons |
| --- | --- | --- |
| (a) `client.auth: client_secret_basic` in session, allowed only when the issuer's discovery does not offer `private_key_jwt`; the secret read from a file (`--client-secret-file`), sent at the token, refresh and revocation endpoints | No change to sluis v1; sluis already makes and rotates confidential secrets (sluis 0039) | A shared secret in session, which [0005](0005-tokens-per-api-and-issuers.md) and S3 exist to avoid; it cannot live in KMS, so a leaked pod spec or disk can sign in as the site; a second code path for client authentication in session, kept and tested only for v1 |
| **(b) `private_key_jwt` in sluis v1**: `AuthMethodPrivateKeyJWT: true`; a client field (for example `auth: private_key_jwt` with an inline `jwks` of the public key, no `jwks_uri` fetch) that makes `AuthMethod` answer `private_key_jwt` and refuses a `secret` beside it; `GetKeyByIDAndClientID` answering from that `jwks`; the `jti` of each assertion claimed once until its `exp` in sluis's state store, because the library does not; discovery advertising `token_endpoint_auth_signing_alg_values_supported` | session unchanged: the same assertion as against Keycloak, signed on KMS ([0019](0019-signing-keys-on-aws-kms.md)); no shared secret anywhere; the library already does the protocol at the code, refresh and revocation grants, so the change is the storage hook, a policy field, the replay check and tests | A sluis v1 change and release before the first site; sluis's front-of-library checks at the token endpoint must be read for any assumption of a secret; an inline `jwks` means a key change is a sluis policy change (session's keys do not rotate at the first sites anyway, [0025](0025-first-version-for-the-first-sites.md)); the key's `kid` (on KMS, the key ARN and fingerprint, [0019](0019-signing-keys-on-aws-kms.md)) goes into the sluis policy |

**Pick (b).** It keeps session's bar: no shared secret, the key on KMS, one client authentication path. The work in sluis v1 is small because the vendored library carries the protocol. If (b) cannot land before the site is needed, (a) is the fallback, documented as a weaker mode and removed when (b) lands; that is an owner choice (O1).

### G2. PAR

| Option | Pros | Cons |
| --- | --- | --- |
| **(a) `client.par: unavailable` in the site file** (default `required`): session sends the authorization request on the browser's URL (`response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method`), and starts only when the issuer's discovery has **no** PAR endpoint, so the setting can never turn PAR off at an issuer that has it | No sluis v1 change; the protections that stop a forged or replayed callback stay: the binding cookie, `state` used once, `nonce`, PKCE S256, the exact redirect URI, the RFC 9207 `iss` check, the code redeemed with `private_key_jwt` | The request's parameters are on the URL bar and in the issuer's access log (no secret among them: the challenge, not the verifier); the request is not authenticated before the person sees the sign-in page, so a crafted link can start a sign-in for the site's client with other scopes the client is allowed; below FAPI 2.0, which requires PAR |
| (b) PAR in sluis v1: an endpoint in front of the library that authenticates the client, checks the parameters as `/authorize` would, keeps them once under a `request_uri` for about a minute, and expands `client_id` and `request_uri` at `/authorize` | session unchanged; FAPI 2.0's PAR at v1 | Not in the library: a new endpoint, its storage, its expiry and one-time use, a change to `/authorize`'s refusal of `request_uri`, discovery, and the conformance tests; several times the size of G1 (b), for an issuer that v2 replaces |

**Pick (a).** The weaker mode is narrow, named in the site file, refused where PAR exists, and the callback's checks are unchanged. session logs at start that the site signs in without PAR. A site on sluis v2 or Keycloak keeps `required`.

### G3. Token exchange

| Option | Pros | Cons |
| --- | --- | --- |
| (b) Let a confidential `private_key_jwt` client's live sign-in be a subject token in sluis v1, and teach the library's exchange grant `private_key_jwt` | Route mode `exchange` on v1 sites | A security rule of v1 lifted (sluis plans its equivalent for v2 as REQ-EXCH-032, with a marker against re-exchange first); the library's exchange grant is a patch of its own; nothing on the first v1 site needs it |
| **(c) No route of mode `exchange` on a sluis v1 site** | Nothing to build; the same answer [0026](0026-exchange-targets-what-the-issuer-allows.md) gives sluis v2 until REQ-EXCH-032 | An app behind a v1 site gets the person by the identity header, not by a token of its own |

**Pick (c).** The modes `public`, `session` and `identity-header` work on a sluis v1 site. As in [0026](0026-exchange-targets-what-the-issuer-allows.md), session does not refuse a route of mode `exchange` at start; sluis v1 refuses the exchange and the route answers 403. The conformance run of the deployed site shows the mistake.

### The refresh token on a site without an exchange route

With no route of mode `exchange`, session refreshes nothing ([0016](0016-exchange-client-and-identity-header.md) refreshes before an exchange only). `offline_access` is still asked (G4): it is what makes sluis open a session, put `sid` in the ID token and post a logout token with it, and it gives [0031](0031-logout-across-hosts.md) L3 a refresh token to revoke at the person's logout.

## Decision

1. **sluis v1 gets `private_key_jwt`** (G1 b), in a sluis v1 release before the first sluis v1 site. session's code does not change for it.
2. **session gets `client.par`** in the site file, `required` (default) or `unavailable` (G2 a). `unavailable` is accepted only when the issuer's discovery has no `pushed_authorization_request_endpoint`; with it, `Login` sends the authorization request on the URL, and everything after the callback is unchanged.
3. **No route of mode `exchange` on a sluis v1 site** (G3 c).
4. **The sluis client of a session site** is declared as: `kind: confidential`, `private_key_jwt` with the public key of session's `client-assertion` purpose, `pkce: required`, `redirects: [https://<host>/_session/callback]` (matched exactly), `signed_out: [https://<host>/]`, `backchannel_logout_uri: https://<host>/_session/backchannel-logout`, and `requires` naming the groups that may sign in. The site file's `scopes` are `openid profile email offline_access`.
5. **The Cedar policy of a sluis v1 site** matches sluis's group names as the ID token carries them, and a person's `sub` is their email address.
6. **Tests**: session's CI runs the sign-in, logout and back-channel logout against a sluis v1 issuer at a pinned release, beside Keycloak, as `just test-keycloak` does today; the deployed site passes the conformance scenarios ([0020](0020-conformance-suite.md), [0029](0029-the-remote-runner.md)) through its Envoy against sluis v1.

The order: the sluis v1 release with `private_key_jwt`; then session's `client.par` and the sluis v1 test job; then the site on the development environment.

## Owner choices (answered)

| | Question | Options | Recommended |
| --- | --- | --- | --- |
| O1 | Client authentication (G1) | A: `private_key_jwt` in sluis v1 first, the site waits for it. B: `client_secret_basic` in session for sluis v1 now, `private_key_jwt` later. C: B only if A is not released by a date the owner names | A |
| O2 | PAR (G2) | A: `client.par: unavailable`, refused where PAR exists. B: build PAR in sluis v1 first | A |
| O3 | Token exchange (G3) | A: none on sluis v1 sites. B: open the sign-in exchange to a confidential `private_key_jwt` client in sluis v1 | A |
| O4 | What the first sluis v1 site's app receives | A: route mode `session` only (session admits by the Cedar policy over sluis's groups; the app sees no identity). B: `identity-header` (the app verifies session's `/_session/jwks`, a session-signed statement of the sluis sign-in, not a sluis token) | B if the app needs the person, else A; the owner confirms that a session-signed header meets "trusts sluis directly" |
| O5 | sluis v1 testing in session's CI | A: a job against a pinned sluis v1 image. B: the deployed site's conformance run only | A |

The owner's answers, 2026-11-25: **O1 A**, **O2 A**, **O3 A**, **O4 B** and **O5 A**. On O4 the owner accepts the identity header as meeting "trusts sluis directly": the app verifies session's `/_session/jwks`, and the header states the person of a sluis sign-in. The first sluis v1 site's app routes use the mode `identity-header`.

## Consequences

- A sluis v1 site keeps every rule of the browser session contract ([0004](0004-browser-session-contract.md)), its keys on KMS and its audit as any site; the one weaker mode is G2's, named in its site file.
- session's site file gains `client.par`; nothing else in its configuration changes. No `client_secret` mode is built (O1 A); the first sluis v1 site waits for the sluis v1 release with `private_key_jwt`.
- sluis v1 gains `private_key_jwt` for confidential clients, which any other relying party may then use in place of a secret (sluis 0039 already prefers it).
- A sluis v1 site's product APIs, if it has any, get the identity header, as on a sluis v2 site ([0026](0026-exchange-targets-what-the-issuer-allows.md)).
- When the site moves to sluis v2, `client.par` goes back to `required` and the client is declared again at v2; the session store and the cookies do not change, but the people sign in again.

## Roads not taken

| Road | Why not |
| --- | --- |
| Keycloak as the issuer of this site | The app trusts sluis directly; a technical service never trusts a Keycloak realm |
| Wait for sluis v2 | Overruled by D92 A |
| Register session at sluis v1 as a `public` client | Rejected in [0005](0005-tokens-per-api-and-issuers.md): no client authentication, and with `sign_in_exchange` a token exchangeable by whoever holds it |
| `client_secret_post` rather than `client_secret_basic` under O1 B | Basic is the client method sluis declares for a confidential client; post puts the secret in the body beside the code |
| A `jwks_uri` pointing at session's `/_session/jwks` | That set also holds the `identity-header` key; an inline key of the `client-assertion` purpose alone needs no fetch from sluis and names exactly one key |
| A named issuer profile (`issuer_profile: sluis-v1`) that relaxes several rules at once | Each weaker mode should be named and refused where it is not needed; a profile hides what it turns off |
| Skip back-channel logout on sluis v1 | sluis v1 serves it, with `sid`, in the shape session checks |

## Open

- The sluis v1 release that carries `private_key_jwt`, and whether sluis's own checks at the token endpoint need more than the storage hook.
- Whether sluis v1's end-session page asks the person when session sends an `id_token_hint` for the person signed in in that browser (it should not, by `confirmedEndSession`); seen in the conformance run.
