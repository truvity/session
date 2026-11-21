# 0001. Purpose, scope and name

Status: accepted
Date: 2026-11-18

## Context

Envoy Gateway's OIDC filter keeps the tokens in browser cookies. Any script that runs on the page can steal a token from the browser, and one token works for every API behind the site. We want the browser to hold nothing but a session id.

sluis is our issuer. It signs people in. It does not keep a website's browser session.

The repository also needs a short, public name.

## Decision

`session` is a relying-party component. After an issuer has signed a person in, it keeps the website's browser session on the server.

- It replaces Envoy Gateway's OIDC filter.
- It replaces no part of the sluis issuer core. sluis is its issuer, and `session` is a client of it, not a second issuer.
- It is the group's browser-session proxy for product fronts.
- It never emits usage or billing records. A product behind `session` meters its own usage.
- Its sign-in flow works with any OIDC issuer that has PAR and `private_key_jwt`. Keycloak is the issuer it is built and tested against first.
- The repository is `truvity/session`. The binary, the image and the Helm chart use the same name.

Out of scope: being an identity provider; authenticating API callers that have no browser (that is the per-API door of sluis, its resource-proxy sidecar); reading request bodies; managing issuer clients or Keycloak realms.

## Consequences

- Tokens stay on the server. The browser holds an opaque cookie.
- The issuer stays small. Website sessions are a client concern.
- We own one more service to run and secure.
- Sites that use the Envoy filter today move to the check described in [0002](0002-own-go-service-and-external-authorisation.md).
- The name says what the component keeps and ties it to no protocol and no proxy.

## Roads not taken

| Road | Why not |
| --- | --- |
| Keep Envoy Gateway's OIDC filter | Tokens stay in browser cookies, and one token is valid for every API |
| Add website sessions to the sluis issuer core | Website sessions are a client concern; the issuer should stay small |
| A name that mentions OIDC or the proxy | Ties the name to one protocol or one proxy |
| A product-style name | The plain name says what the component keeps |
