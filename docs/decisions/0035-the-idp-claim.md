# 0035. The issuer's id in the identity header and in whoami: the claim `idp`

Status: accepted, 2026-11-25 (owner decision D115 A)
Date: 2026-11-25

Adds one claim to the identity header of [0005](0005-tokens-per-api-and-issuers.md) and [0016](0016-exchange-client-and-identity-header.md), and one field to `/_session/whoami`. It settles the first open question of [0034](0034-several-issuers-per-site.md). Nothing else in those records changes. The number 0033 is taken by an open pull request, so this record follows 0034.

## Context

A site may have several issuers ([0034](0034-several-issuers-per-site.md)). A subject is unique only within its issuer, so two people of different issuers can have the same `sub`. An app behind the identity header saw only `sub` (with `name`, `email` and `groups`), and could not key its data by person without trusting `sub` alone. 0034 left open whether the header and whoami should name the issuer.

## Decision

- **The identity header** (`X-Session-Identity`, a JWS of `typ` `session-identity+jwt`) carries `idp`: the id of the session's issuer in the site file (`issuers[].id`, such as `corp`). The other claims are unchanged: `iss` the site's origin, `aud`, `sub`, `name`, `email`, `groups`, `iat`, `exp`.
- **`/_session/whoami`** answers `idp` beside `sub`, `name`, `email`, `groups` and `expires_at`.
- **Every header and every whoami has it, with one issuer too,** so the shape is the same on every site and an app does not change when a site adds an issuer.
- **An app that keys data by person uses `idp` and `sub` together.**
- The value is the site's id, not the issuer identifier (the URL): it is short, it is what the site file and `?issuer=` name, and it does not change when an issuer moves its URL. The id is read from the site file at each check, so it is the id the site names now. The issuer identifier stays in the session and in the audit records (`unmapped.session.issuer`), and policy keeps `principal.issuer`.

## Consequences

- An addition: an app that ignores unknown claims sees no change. Not breaking.
- Renaming an issuer's `id` in the site file changes the `idp` that apps see for its people; an app that keys by `idp` treats an id as stable, as the site file does.
- `core.Rules.Issuers` holds each issuer's id beside its identifier (`core.SiteIssuer`), so the check can name the id without the sign-in handler.

## Roads not taken

| Road | Why not |
| --- | --- |
| The issuer identifier (the URL) as `idp` | Long, and it changes when an issuer moves; the site's id is what the site names |
| The claim only on sites of several issuers | Apps would need two shapes, and would change when a site adds its second issuer |
| A combined subject, `sub` = `<idp>/<subject>` | Changes the meaning of `sub` for every app, and breaks the match with the issuer's own `sub` |
