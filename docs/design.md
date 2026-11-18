# Design of truvity/session

Status: design, 2026-11-18. No code yet.

Decisions are recorded one by one in [docs/decisions](decisions/). This document puts them together and shows how the parts work.

## 1. Purpose

`session` is a relying-party component. After an issuer has signed a person in, `session` keeps the website's browser session on the server.

- The browser holds one opaque cookie. Tokens never reach the browser.
- The proxy in front of the site asks `session` before each request: may this pass, and with which headers?
- The issuer is sluis. Keycloak is used to build and test first.

What it replaces: the OIDC filter of Envoy Gateway, which keeps tokens in browser cookies.

What it does not replace: any part of the sluis issuer core. `session` is a client of the issuer, not a second issuer.

## 2. Goals and non-goals

| Goals | Non-goals |
| --- | --- |
| Server-side browser session for a website | Being an identity provider |
| One check core for every proxy | Authenticating API callers without a browser (the per-API door of sluis) |
| Per-API tokens, never one token valid everywhere | Authorisation policy beyond the route table (the API decides what the user may do) |
| Works behind Envoy Gateway, nginx and AWS API Gateway | Reading request bodies |
| Small, auditable, written in Go | Managing issuer clients or Keycloak realms |

## 3. Overview

```text
 browser  ->  host proxy  ->  site
                 |
                 +--  "may this pass?"  -->  session check  -->  session store
                                                  |
                                                  +--  sign-in, token exchange, logout  -->  issuer
```

One check core does the work. Adapters only translate between a proxy's protocol and the core.

| Piece | Job |
| --- | --- |
| Check core | Reads the cookie, loads the session, decides allow, redirect or 401, builds the headers |
| Adapters | Envoy external authorisation (HTTP and gRPC), nginx `auth_request`, AWS API Gateway Lambda authorizer |
| Sign-in handler | Login, callback, logout, back-channel logout, whoami |
| Exchange client | Gets and caches a token for each API audience (RFC 8693) |
| Ports | Go interfaces for the session store, keys and policy (section 9). First implementations: DynamoDB, key file and AWS KMS, the site file |
| In-path mode | The same service as a reverse proxy, for sites where one more hop is fine |

Libraries: `coreos/go-oidc`, `golang.org/x/oauth2`, `go-jose`. We write the glue, not the cryptography.

## 4. Deployment: external authorisation

The host proxy asks `session` before each request. `session` is not in the data path.

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant P as Host proxy
    participant S as Session check
    participant A as Site or API

    B->>P: GET /app with cookie
    P->>S: check request, method, path, headers
    S->>S: read cookie, load session, apply route rule
    alt valid session
        S-->>P: allow, set Authorization or identity headers
        P->>A: request with headers set by the check
        A-->>P: response
        P-->>B: response
    else no session, top-level page
        S-->>P: deny, 302 to /_session/login with return_to
        P-->>B: 302 to sign-in
    else no session, API call
        S-->>P: deny, 401 with JSON body
        P-->>B: 401 JSON
    end
```

Rules of this mode:

- The proxy sends only headers. The check never sees the body.
- The proxy strips `Authorization`, `Cookie` and identity headers that came from the browser. The allow answer sets the real ones. The example configs ship this.
- The sign-in paths (`/_session/*`) are routed to the service without a check, because they run before a session exists.
- The check fails closed. If the store is down, the answer is 503, never allow.

Hosts:

| Host | How it asks | Notes |
| --- | --- | --- |
| Envoy Gateway | `SecurityPolicy` with external authorisation, HTTP and gRPC adapters from the start | Allow headers set on the upstream request, deny answer passed to the browser |
| nginx | `auth_request` with `auth_request_set` | Self-hosted installs |
| AWS API Gateway | Lambda authorizer | Cannot redirect. It returns 401 and the browser helper starts sign-in. The authorizer does not cache its answers by default. The sign-in paths go to the service over an HTTP integration, or to the same binary as a second Lambda handler, for each install. Where there is no cluster, the Lambda handler is the default |

The in-path mode is a plain reverse proxy that runs the same check, then forwards the request. It costs a hop, so it is for sites where that is fine.

## 5. Behaviour contract

These are the rules every host gets. They do not depend on the proxy.

| Id | Rule |
| --- | --- |
| S1 | Cookie `__Host-<site>`: opaque id, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` |
| S2 | Sessions live on the server, encrypted, in DynamoDB on every shape. Each site has an idle and a maximum lifetime |
| S3 | Sign-in uses authorisation code with PKCE, always. PAR and `private_key_jwt` are used (issuers have them) |
| S4 | Page without session: redirect to sign-in. API call: JSON 401. The API Gateway authorizer cannot redirect, so it returns 401 and the browser helper starts sign-in |
| S5 | State-changing requests need CSRF protection: a custom header plus `Origin` and `Sec-Fetch-Site` checks. Headers only |
| S6 | Logout is a POST with CSRF, then the issuer's end-session. Back-channel logout deletes the session on all replicas |
| S8 | The browser's `Authorization`, cookies and identity headers are stripped. In external authorisation the host strips and the allow answer sets them |

(There is no S7. The ids follow the maintainers' list of decisions.)

### 5.1 Session record

| Field | Content |
| --- | --- |
| id | 256 random bits, only in the cookie. The store key is a keyed hash of it, so a store leak gives no usable cookie |
| subject, issuer, `sid` | From the ID token. Indexed for back-channel logout |
| tokens | The sign-in access token and refresh token |
| exchanged tokens | One entry per audience, see section 7 |
| created, last seen, expires | Idle and maximum lifetime |

The record is encrypted with AES-256-GCM. The session id is the associated data. The data keys come from the key port, so they can be rotated.

A new id is issued at sign-in, so a session id set before sign-in is never reused (no fixation).

Idle time is refreshed at most once a minute, to keep writes down. The default lifetimes are suggestions: 30 minutes idle, 8 hours maximum. Each site sets its own. These defaults were accepted on 2026-11-18 (decision 0011).

### 5.2 Paths

`session` owns one prefix on every site, `/_session/` by default.

| Path | Method | Purpose |
| --- | --- | --- |
| `/_session/login` | GET | Start sign-in. `return_to` must be a relative path of the same site |
| `/_session/callback` | GET | Receive the code from the issuer |
| `/_session/logout` | POST | End the session. Needs CSRF headers |
| `/_session/backchannel-logout` | POST | Called by the issuer |
| `/_session/whoami` | GET | JSON: subject, name, groups, session expiry |
| `/_session/jwks` | GET | Public keys of the service, for apps that verify the signed identity header |

### 5.3 Unauthenticated requests

A route says what to do without a session: `redirect` or `401`. The default is `redirect` for a top-level navigation (`GET`, `Sec-Fetch-Mode: navigate`, `Accept` includes `text/html`) and `401` for everything else. The 401 body is JSON with `error: login_required` and a `login_url`.

## 6. Sign-in

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant S as Session service
    participant V as Session store
    participant I as Issuer

    B->>S: GET /_session/login?return_to=/app
    S->>S: make state, nonce, PKCE verifier
    S->>V: save sign-in transaction by state
    S->>I: POST PAR with client_assertion private_key_jwt, challenge, nonce, state
    I-->>S: request_uri
    S-->>B: 302 to issuer authorize with client_id and request_uri, Set-Cookie sign-in binding
    B->>I: GET authorize, person signs in
    I-->>B: 302 to /_session/callback with code, state, iss
    B->>S: GET /_session/callback with binding cookie
    S->>V: load and delete transaction by state
    S->>S: check binding cookie, state, iss
    S->>I: POST token with code, verifier, client_assertion
    I-->>S: ID token, access token, refresh token
    S->>S: validate ID token: signature, iss, aud, azp, exp, nonce
    S->>V: create session under a new id
    S-->>B: 302 to return_to, Set-Cookie __Host-site
```

Notes:

- The sign-in transaction is short-lived (a few minutes) and used once.
- A short-lived binding cookie ties the transaction to the browser that started it.
- The callback checks the `iss` parameter (RFC 9207) against the configured issuer.
- `return_to` is stored in the transaction, never taken from the callback URL.
- PAR keeps the request parameters off the browser's URL bar. `private_key_jwt` means the service holds no shared secret.

## 7. Per-API tokens (RFC 8693)

A route can name an API audience. The check exchanges the session's token for a token that is valid only for that API, and puts it in the allow answer.

```mermaid
sequenceDiagram
    autonumber
    participant P as Host proxy
    participant S as Session check
    participant V as Session store
    participant I as Issuer

    P->>S: check GET /api/billing/x
    S->>V: load session
    S->>S: route rule says audience billing
    S->>V: get cached token for session and audience
    alt cache hit, not near expiry
        V-->>S: token
    else cache miss
        S->>V: take short lock for session and audience
        S->>S: if session access token is old, refresh it first
        S->>I: POST token, grant_type token-exchange, subject_token, audience, client_assertion
        I-->>S: access token for billing
        S->>V: store encrypted, expiry = token expiry minus skew
        S->>V: release lock
    end
    S-->>P: allow, Authorization Bearer token for billing
```

Rules:

- The cache key is session id, audience and scope. Entries expire with the token, minus a skew.
- A lock (single flight) stops many parallel requests from exchanging at once.
- Cache entries are deleted with the session, at logout and at back-channel logout.
- If the exchange is refused, the answer is 403 for that route. The session stays.
- Option C is an opt-in per route: a signed identity header with user and groups, for apps that cannot handle tokens. The service signs it through the key port and publishes the public keys at `/_session/jwks`. It is short-lived, about a minute.
- Forwarding the session token itself (option B) is rejected, because one token would be valid on every API.

## 8. Logout

The person's own logout is simple: a POST with CSRF headers deletes the session, clears the cookie and redirects to the issuer's end-session.

Logout started at the issuer arrives by back-channel logout. The issuer posts to any replica. All replicas share the store, so deleting there is enough.

```mermaid
sequenceDiagram
    autonumber
    participant I as Issuer
    participant LB as Load balancer
    participant R2 as Replica 2
    participant V as Session store
    participant R1 as Replica 1
    participant B as Browser

    I->>LB: POST /_session/backchannel-logout, logout_token
    LB->>R2: forward
    R2->>R2: validate JWT: signature, iss, aud, events claim, no nonce
    R2->>V: set jti if absent, reject replay
    R2->>V: find sessions by sid, or by sub if no sid
    R2->>V: delete sessions and their exchanged tokens
    R2-->>I: 200
    B->>R1: next request through host proxy
    R1->>V: load session
    V-->>R1: not found
    R1-->>B: redirect to sign-in or 401
```

Design consequences:

- Replicas keep no session state. The next check on any replica sees the deletion at once.
- For this reason the first version has no local session cache (decision 0012). The spike measures DynamoDB latency.
- The `sid` and `sub` lookups use a secondary index on the session table.

## 9. Ports: store, keys, policy

The core talks to three Go interfaces (ports). They are shaped like the building blocks of sluis v2, so that `session` can switch to them once the sluis core is done (alpha.2). Decision 0009.

| Port | Shaped like | Job | First implementation |
| --- | --- | --- | --- |
| Session store | sluis `store` | get, put, delete, conditional update, expiry | DynamoDB |
| Key | sluis `key` | sign, public keys (JWKS), data keys for record encryption | A key file, and AWS KMS |
| Policy | sluis `policy` | per-route decisions: which API token a route needs, who may reach it | The site file |

### Session store on DynamoDB

Sessions live in DynamoDB on every shape: Kubernetes, nginx and API Gateway installs alike (decision 0010).

| Need | How |
| --- | --- |
| Expiry | A TTL attribute, plus an explicit expiry check on read, because TTL deletion is lazy |
| Idle refresh | A conditional update, at most once a minute for each session |
| Exchange lock | A conditional write with a short expiry, one item for each session and audience |
| Back-channel logout | A secondary index on `sid` and `sub` |
| Token cache | Items under the session, deleted with it |

Rules:

- The check reads the session item for each request. The spike measures the latency and the cost.
- Reads of the session item are strongly consistent, so a logout is seen at once.
- A memory store exists for tests only and refuses to start in production mode.
- The Helm chart takes a table name and a cloud identity (a service account role). It does not run a store.

### Keys

The key port covers three jobs: the `private_key_jwt` assertions, the signed identity header, and the data keys that encrypt session records. The key file is the simple start and works with Keycloak. AWS KMS keeps the key from ever leaving it. The JWKS of the service is published at `/_session/jwks`.

### Policy

The policy port answers, for a request on a route: is a session needed, which API audience's token does the route need, and may this person reach it. At first the answer comes from the route table of the site file (section 10).

## 10. Site configuration

One file per site. The schema is part of the repo, and `session check` validates it (the generator turns it into proxy config).

```yaml
site: docs
host: docs.example.com
issuer: https://issuer.example.com
client:
  id: session-docs
  auth: private_key_jwt
  key_file: /run/secrets/docs-client-key.pem
scopes: [openid, profile, groups]
session:
  idle: 30m
  max: 8h
routes:
  - match: { prefix: /assets/ }
    mode: public
  - match: { prefix: /api/billing/ }
    mode: exchange
    audience: https://billing.example.com
  - match: { prefix: /api/ }
    mode: identity-header
  - match: { prefix: / }
    mode: session
```

| Route mode | Allow answer carries |
| --- | --- |
| `public` | Nothing. No session needed |
| `session` | Only that the session is valid, plus the cookie-stripped `Cookie` header |
| `exchange` | `Authorization: Bearer` with the token for the audience |
| `identity-header` | A signed identity header (option C) |

Routes are matched in order. The first match wins. The check matches on the normalised path, and the host proxy must route on the same normalised path (see the threat model).

## 11. Repository contents

| In the repo | Path (planned) |
| --- | --- |
| Check service, image and Helm chart: 2 replicas, Service, NetworkPolicy, DynamoDB table name and cloud identity | `cmd/session`, `charts/session` |
| Lambda authorizer package, and the same binary as a second Lambda handler for the sign-in paths | `cmd/authorizer-lambda` |
| Example host configs: Envoy `SecurityPolicy`, nginx, API Gateway | `examples/` |
| Site config schema, `session check` validator and generator | `schema/`, `cmd/session` |
| Browser helper in TypeScript: `apiFetch` (401 gives a re-login hint), `whoami`, `signOut` as POST with CSRF | `web/` |
| Conformance suite: headless browser, run in CI against a test sluis and a test Keycloak | `conformance/` |
| Docs: site file reference, "put a site behind it" guide, threat model | `docs/` |

Not in the repo:

- The per-API door for API callers. That is the sluis resource-proxy sidecar.
- Keycloak realm configuration.
- Envoy routing and cluster configuration. Those live in the platform's own repositories.

## 12. Issuers and the first checks

| Issuer | Role |
| --- | --- |
| sluis v2 | The target, once its FAPI work lands (PAR, `private_key_jwt`) |
| Keycloak | Has PAR and `private_key_jwt` now. Used to build and test first |

Check E8, in the first spike: does the token exchange of sluis v1 accept the proxy's sign-in token? If yes, sites on v1 can use `session` before the switch. If no, they wait.

## 13. Threat model (summary)

The full model goes into `docs/threat-model.md` with the first code.

| Threat | Answer |
| --- | --- |
| Token theft from the browser | Tokens never leave the server. The cookie is `HttpOnly` and `__Host-` |
| Stolen store contents | Session records are encrypted. The store key is a keyed hash of the id |
| CSRF | `SameSite=Lax`, a custom header, `Origin` and `Sec-Fetch-Site` checks (S5) |
| Session fixation | New id at sign-in |
| Open redirect | `return_to` must be a relative path, kept server-side |
| Login CSRF and code injection | State plus binding cookie, PKCE, `iss` check |
| Header spoofing | The host strips browser headers, the allow answer sets them (S8). The examples ship this |
| Path confusion between proxy and check | Both use the normalised path. A conformance test sends encoded and dot-segment paths |
| Replay of logout tokens | `jti` stored until the token expires |
| Store outage | Fail closed |
| Token blast radius | One token per API audience. No token valid everywhere |
| Cross-site embedding | `SameSite=Lax` and no `Domain`. Sites are separate hosts |

## 14. Testing

The conformance suite drives a headless browser through the real flows: sign-in, an API call with a 401 and re-login, CSRF refusal, logout, back-channel logout across two replicas, session expiry, and header stripping. It runs in CI against a test sluis and a test Keycloak, with each host adapter in turn.

## 15. Decisions after review

On 2026-11-18 the maintainers accepted the defaults of this document and answered the questions that came with it. They are recorded in decisions 0009 to 0012. In short:

| Topic | Decided | Record |
| --- | --- | --- |
| Ports shaped like sluis v2 building blocks | Yes, own interfaces now, switch to the sluis blocks at alpha.2 | 0009 |
| Session store | DynamoDB on every shape. Valkey is dropped | 0010 |
| Defaults: `/_session/` paths, keyed-hash store key, AES-256-GCM, 30 min idle and 8 h maximum, YAML site file, fail closed with 503, redirect for top-level navigations and 401 otherwise | Accepted as written | 0011 |
| API Gateway sign-in handlers | HTTP integration or a second Lambda handler for each install, default Lambda where there is no cluster | 0012 |
| Local session cache | None at first | 0012 |
| `private_key_jwt` key and identity header key | Through the key port: key file and AWS KMS. JWKS published | 0012 |
| Sites and hosts | One site per host | 0012 |
| Authorizer caching | Off by default | 0012 |
| Subject token freshness | Refresh token stored, refreshed under a lock | 0012 |
| Envoy adapters | HTTP and gRPC from the start | 0012 |
| Refused exchange | JSON 403 for API routes, error page for page routes | 0012 |

## 16. Next steps

1. Spike, about a week:
   - Envoy and nginx check paths, HTTP and gRPC: headers set, `Cookie` rewrite, deny answers, `Set-Cookie` on refresh.
   - The Lambda authorizer: response shape, how identity reaches the integration, the second Lambda handler for the sign-in paths.
   - DynamoDB: latency and cost of a read for each request, strongly consistent reads, the conditional update for idle time, the secondary index for logout.
   - The E8 check: sluis v1 token exchange with the proxy's sign-in token.
2. Build the check core, the three ports with their first implementations (DynamoDB, key file, site-file policy), the sign-in handler and the Envoy adapters against Keycloak.
3. Add the nginx adapter, the AWS KMS key, the exchange client and the conformance suite.
4. First version for the first internal sites.
5. Lambda authorizer and the Lambda sign-in handler.
6. Move to sluis v2 when PAR and `private_key_jwt` land, and to its building blocks once its core is done (alpha.2).

### Open questions

The questions of the first draft are decided (section 15). Two new ones came from dropping Valkey. Each has options and a recommendation.

**Q1. What do installs without AWS use for sessions?** A self-hosted nginx site may have no AWS account to hold a DynamoDB table.

| Option | Meaning |
| --- | --- |
| A | Every install uses a DynamoDB table it can reach. No second store |
| B | Add a store implementation for a DynamoDB-compatible local service |
| C | Add another store (for example a relational database) behind the store port |

Recommendation: A for now. The store port lets us add B or C when a real site needs it. Do not write a second store before then.

**Q2. How do we keep logout correct with a secondary index?** Secondary indexes are eventually consistent. A logout token that arrives just after sign-in could miss the new session.

| Option | Meaning |
| --- | --- |
| A | Accept it. The session still ends by idle or maximum time |
| B | Also store the logout as a tombstone for each `sid` and `sub` for a short time. The check refuses sessions older than a tombstone |
| C | Look up sessions by a base-table key built from `sid`, so no index is needed |

Recommendation: B. It is small, and it closes the gap that A leaves. Check it in the spike.
