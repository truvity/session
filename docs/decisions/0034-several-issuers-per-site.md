# 0034. Several issuers per site: the sign-in page, a flow per issuer, and the session's own issuer for everything after

Status: accepted, 2026-11-25 (owner decision D84 A)
Date: 2026-11-25

Lets one site sign people in at more than one issuer. The number 0033 is taken by the open pull request "sluis v1 as an issuer", so this record is 0034. It keeps every rule of [0004](0004-browser-session-contract.md) (S1 to S8), the sign-in of [0015](0015-envoy-http-mode-csrf-header-and-step-2-choices.md), the exchange of [0005](0005-tokens-per-api-and-issuers.md), [0016](0016-exchange-client-and-identity-header.md) and [0026](0026-exchange-targets-what-the-issuer-allows.md), and logout as [0031](0031-logout-across-hosts.md) decided it. What changes is that each of them is done at the issuer of the session, or of the sign-in, instead of the site's one issuer. It changes the site file's schema (breaking).

## Context

Until now a site file named one issuer (`issuer`, `client`, `scopes` at the top), and everything went there: the sign-in, the exchange, the refresh, the end-session, back-channel logout. [0026](0026-exchange-targets-what-the-issuer-allows.md) rejected "a second issuer per site" as a way round sluis's exchange targets; that road is still not taken here, because this record is about where people sign in, not about mixing issuers within one session.

The first site that needs several issuers is one internal tool (owner decision D83): a URL shortener for staff, which every vendor's staff may use. Each vendor's staff signs in at its own staff realm, and each realm is an issuer of its own: its own keys, its own sessions, its own logout. One site, several issuers, a person signing in at exactly one of them.

Nothing is deployed, so the schema may change without a migration ([0025](0025-first-version-for-the-first-sites.md) names the first sites; none runs yet). No record asks for the old schema to stay readable.

## Decision

### The site file: a list of issuers

```yaml
issuers:
  - id: corp                      # ?issuer=corp; 1 to 32 lower-case letters, digits and '-'
    label: Example Corp           # the sign-in page shows "Sign in with Example Corp"
    issuer: https://issuer.example.com/realms/corp-staff
    client:
      id: session-tools
      auth: private_key_jwt
    scopes: [openid, profile, email]
  - id: partner
    label: Example Partner
    issuer: https://issuer.example.com/realms/partner-staff
    client: { id: session-tools, auth: private_key_jwt }
    scopes: [openid, profile, email]
signin:
  remember_choice: 720h           # optional; unset remembers nothing
```

- `issuers` holds one entry or more. Each has an `id` (unique), a `label`, the issuer identifier `issuer` (unique; its discovery is `<issuer>/.well-known/openid-configuration`, read at start, PAR required as before), its `client` (`id` and `auth: private_key_jwt`) and its `scopes` (with `openid`).
- **Breaking.** The top-level `issuer`, `client` and `scopes` are gone. A file that still has them is refused with a message that names this record, so an old file never starts with a silent default.
- **Every client setting is the issuer's.** `client` and `scopes` sit in the issuer's entry, so a property of one issuer is set on that issuer only. The proposed record 0033 (sluis v1 as an issuer, an open pull request) names such properties: `private_key_jwt` at the issuer, a `client.par: required|unavailable` setting, no exchange routes, and the `offline_access` scope. If it is accepted, `par` goes into the entry's `client` and `offline_access` into its `scopes`, per issuer; this record builds neither.
- **The client key is one for every issuer**: the key port's purpose `client-assertion`, as today, published at `/_session/jwks`. Each issuer registers the same key (or the JWKS URL) for the site's client there. The assertion's audience is the issuer it is sent to, so an assertion made for one issuer is no good at another.
- With one entry, behaviour is exactly as before: there is no sign-in page, `/_session/login` goes to the issuer at once, and logout and the exchange are unchanged.

### The sign-in page

| Request | Answer |
| --- | --- |
| `GET /_session/login?issuer=<id>&return_to=...` | The sign-in at that issuer: PAR, PKCE, `private_key_jwt`, as before. An id the site does not have is a 400 |
| `GET /_session/login?return_to=...`, one issuer | The sign-in at that issuer, as before |
| `GET /_session/login?return_to=...`, several issuers | The remembered choice's sign-in when the site remembers one and the cookie names one of its issuers; else a `302` to `/_session/signin?return_to=...` |
| `GET /_session/signin?return_to=...`, several issuers | The page: one link for each issuer, in the site file's order, "Sign in with \<label\>", each to `/_session/login?issuer=<id>&return_to=...` |
| `GET /_session/signin?issuer=<id>&return_to=...` | A `302` to that issuer's login: the page is skipped. CI and the remote runner use it |
| `GET /_session/signin?...`, one issuer | A `302` to that issuer's login |

- The check's redirect and its 401's `login_url` stay `/_session/login?return_to=...`: no host adapter changes, and the page is reached through the login path.
- The page is session's own small neutral template (`internal/signin/page.go`, `html/template`): plain links, no script, no form, nothing loaded from elsewhere, served `no-store` with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. Each label and address is escaped. A site's own template, a document of the source port like `error_page`, is a later step; it will get the same data (the issuers' labels and addresses).
- `return_to` is checked on the page as on the login (a path of the site, never one of session's), and again at the callback.
- **The remembered choice** is a site-file setting, `signin.remember_choice`, a duration, off by default. When it is set and the site has several issuers, a completed sign-in sets `__Host-<site>-issuer` (the issuer's id, no secret; `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` the setting), and a later login that names no issuer goes to that issuer without the page. The page itself always shows every issuer, so a person can pick another. The cookie is session's own: the check strips it from the `Cookie` the site gets, as it strips the session and binding cookies. A logout leaves it, because it is a preference, not a session.

### A flow per issuer, and the mix-up defence

- The sign-in transaction (by state, sealed, used once) records the id of the issuer the person chose. The PAR, the authorisation request, the code's redemption and the ID token's verification (signature, `iss`, `aud`, `azp`, `exp`, `nonce`) are all that issuer's, with the site's client and scopes there.
- **The callback answers only to the issuer chosen.** Where the issuer sends RFC 9207's `iss` (or says in discovery that it does), `iss` must be that issuer's identifier; a callback that names another issuer is refused (`400`, the audit reason `iss`), and the state is used up. Where the issuer sends no `iss`, the state binds the response to the chosen issuer: the code is redeemed only at that issuer's token endpoint, with an assertion for that issuer, and the ID token must be that issuer's. A transaction whose issuer the site no longer names is refused (`issuer`).

### The session records its issuer, and policy and audit read it

- The session record keeps the issuer identifier (the ID token's `iss`), as it did. A session whose issuer is not one of the site file's issuers is no session: an issuer taken out of the site file ends its people's sessions at the next start.
- **Policy:** the principal's `issuer` attribute (already in session's Cedar schema, [policy.md](../policy.md)) is that identifier, so a bundle keeps a route to one issuer's people with `principal.issuer == "<issuer>"`. The entity id stays `User::"<subject>"`: a subject is unique only within its issuer, so a policy that names one person tests `principal.issuer` too.
- **Audit:** every record of a sign-in, a failed sign-in, a logout, a back-channel logout, a denial, an exchange and a refresh carries the issuer in `unmapped.session.issuer`, as [0023](0023-audit-emitter.md) defined; a failed sign-in now names the issuer chosen. A back-channel logout token of an issuer the site does not have is refused with the reason `issuer` and no issuer named, because its `iss` is not trusted.

### Logout per issuer

- **The person's logout** ([0031](0031-logout-across-hosts.md)) revokes the refresh token at the session's issuer and sends the browser to that issuer's end-session, with that issuer's client id and the `id_token_hint`.
- **Without a live session**, 0031 sends the browser to the issuer's end-session. With one issuer that is unchanged. With several, session cannot tell whose end-session it is: it uses the remembered choice when the site remembers one, and otherwise sends the browser back to the site's `/` (which shows the sign-in page).
- **Back-channel logout** stays one path, `/_session/backchannel-logout`, for every issuer. The token is verified by the issuer its `iss` names, among the site's only: that issuer's keys, the site's client at it as `aud`, the rest of 0031's checks. Its `sid` or subject then ends only that issuer's sessions, because the index entries, the tombstones and the claimed `jti` are keyed by issuer and value. A token from one issuer can never end another issuer's session, even for an equal subject.

### Exchange per issuer

- The exchange and the refresh of a route of mode `exchange` go to the session's issuer, with the site's client and an assertion for that issuer ([0026](0026-exchange-targets-what-the-issuer-allows.md) applies per issuer). The start needs an exchange client for every issuer of a site that has such a route.
- **A route whose audience only one issuer allows**: a session of another issuer asks its own issuer, which refuses, and the route answers `403` as for any refused exchange; the session stays. A site that wants a clean denial instead of the issuer's refusal writes a policy on `principal.issuer` for that route; the policy runs before the exchange. The route table names no issuer: it does not say which issuer allows which audience, and session would have to keep a second copy of each issuer's client registry.

### Conformance

The suite gets a stand of two issuers (two realms of the test Keycloak, each with its own person, the same client id and key), run through Envoy over gRPC (`TestConformanceTwoIssuers`): the page with one link for each issuer and no script; a sign-in through each, one by its link and one by `?issuer=`; a callback whose `iss` names the other issuer refused, and the same callback untampered accepted; a policy that keeps a route to each issuer's people; the exchange at the session's issuer (the token verifies at that issuer and not at the other); logout through the session's issuer, and back to the site without a live session; and a back-channel logout from one issuer that ends only that issuer's session. The sign-in paths do not differ by host, so the two-issuer scenarios run through one host; the suite of one issuer still runs through every host. The remote runner's `ISSUER=` names the issuer by its id in the site file (needed when the file has several), and the runner adds `?issuer=<id>` to the browser's requests for the sign-in page.

## Consequences

- A breaking change of the site file, and of the remote runner's `ISSUER=` (an id now, not a URL). No migration: nothing is deployed.
- `core.Options.Issuer` becomes `Issuers`, a map by issuer identifier, and `core.Rules` gains `Issuers`, the site's issuer identifiers. `signin.Options` takes a list of issuers and `Remember`.
- One more path under `/_session/` (`signin`); the hosts route the whole prefix to the service already, so no example changes.
- Every issuer is discovered at start: an issuer that is down at start fails the start, as one issuer did before.
- An app behind the identity header gets `sub` without the issuer, as before; on a site of several issuers two people of different issuers could in principle have the same `sub`. See Open.

## Roads not taken

| Road | Why not |
| --- | --- |
| Keep the old top-level `issuer`, `client`, `scopes` beside `issuers` | Two ways to say one thing, and a default to pick between them; nothing is deployed, so the clean break costs nothing |
| A site per issuer (one host each) | The tool is one site with one address; a host per vendor splits its links and its cookies |
| One issuer that brokers every vendor's realm | The owner chose each realm as an issuer of its own (D83, D84): their keys, sessions and logout stay apart, and session needs no broker in front |
| Script on the sign-in page (a picker, a remembered choice in local storage) | The page must work without script, and the remembered choice is a server-set cookie the check can strip |
| A back-channel path per issuer (`/_session/backchannel-logout/<id>`) | The token's `iss`, verified with that issuer's keys and matched against the site's issuers, already says which issuer sent it; one path keeps every host's routing as it is |
| A route that lists the issuers its exchange may use | It would copy the issuers' client registries into the site file; the issuer refuses, and a policy on `principal.issuer` gives a clean denial where wanted |
| `User::"<issuer>/<subject>"` as the Cedar entity id | Every bundle that names a user would break; the `issuer` attribute already tells people apart |
| A client key per issuer | One key, registered at each issuer, is what the key port and the JWKS hold today; a key per issuer needs a purpose per issuer and changes nothing at the issuers |

## Open

- Decided by [0035](0035-the-idp-claim.md): the claim `idp`. Whether the identity header and `/_session/whoami` should name the issuer (an `idp` claim, the issuer's id or identifier), so that an app tells people of different issuers apart without trusting `sub` alone. Not built: it adds a claim apps would rely on, and needs an owner decision.
- A site's own sign-in template, a document of the source port beside `error_page`: when a site asks for one.
