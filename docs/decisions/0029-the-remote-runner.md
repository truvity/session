# 0029. The remote runner: the conformance scenarios against a deployed site

Status: accepted, 2026-11-25 (owner decision)
Date: 2026-11-25

Answers the first two lines of "Not in this record" of [0028](0028-the-image.md): how the scenarios of [0020](0020-conformance-suite.md) run against a deployed site, and the test backend that site routes to. Step 4 is done when they pass there ([0025](0025-first-version-for-the-first-sites.md)).

## Context

The suite of 0020 builds its own stand for each host: the in-process store double, a clock it moves, a realm it makes through Keycloak's admin API with a password person, a TLS front with a test certificate, and the audit records of a JSON-lines driver it reads in the process. A deployed first site has none of these: its store is DynamoDB, its clock is the wall clock, its realm is the deployment's and signs people in through a brokered upstream, and its audit records go to the spool sidecar's socket. On development that upstream is mimic, a test identity provider of fixed identities: it signs in the identity a `login_hint` names, shows a chooser of identities when none is named, and takes a session from a CI job's token at `POST /session`.

## Decision

| Subject | Choice |
| --- | --- |
| Where it lives | `conformance/remote_test.go`, `TestRemote`, in the same package as the local suite, so both run the one list of scenarios; `conformance/remote/` holds the site file and the README |
| How it runs | `just test-remote HOST=<host> [KEY=VALUE ...]`, each setting becoming `SESSION_REMOTE_<KEY>`: the host, the issuer, the test identity (`HINT`), the brokered provider's alias (`IDP`), an optional CA, mimic's URL and token. Without `HOST` the test skips, so `just test` and `just test-conformance` do not change |
| Which scenarios | Each scenario carries where it runs: anywhere, local only or remote only. Remotely: no session, sign-in, protected route (S8), the sign-in prefix, CSRF (S5), exchange and identity header with a refused exchange, the bad paths, logout (S6), and two that only the remote site file makes short enough to wait out in real time: the idle lifetime and the absolute lifetime |
| What stays local | The store outage (a deployed store cannot be taken down from the test), back-channel logout and the refused refresh (both end the person's Keycloak session through the realm's admin API; the refresh also needs the clock six minutes ahead) |
| The sign-in | The runner pauses each request of the browser to the issuer's authorization endpoint (the DevTools protocol's Fetch domain) and adds `kc_idp_hint` and `login_hint`, so Keycloak sends the browser to the brokered provider and names the identity there; session's own request is otherwise unchanged and session learns nothing of the hints. mimic's session is handed over with a token, as a CI job does; mimic's chooser, Keycloak's provider button and, for a realm with its own person, Keycloak's password form are answered when they show |
| The site | `conformance/remote/site.yaml`: the suite's route table (a test checks it is the same), `session.idle` 90 s (longer than the one-minute touch interval) and `session.max` 3 min (shorter than Keycloak's access tokens, so a run never refreshes). Every route sends to the test backend |
| The test backend | `conformance/echo`: answers every request with its method, path and headers as JSON, the answer the local stand's site already gave, now the same code in both. The image `ghcr.io/truvity/session-echo`, distroless, built in the same jobs of `image.yaml` from the same commit and with the same tag as `ghcr.io/truvity/session` (0028) |
| Bad paths | Sent outside the browser over TLS to the site, with the host's expected answers (`PROXY=envoy`, the default, or `nginx`). Anything in front of the proxy that answers a bad path itself fails the scenario, which is the finding |
| Audit | Not checked by default: the records go to the site's spool, not to the runner. With `AUDIT=<command>` the runner runs the command after the scenarios, with `SESSION_REMOTE_SINCE`, reads the records it prints one a line, and checks as the local suite does that each is JSON, none names the test identity in clear, and sign-in, denied, token exchange and logout are there |
| Who runs it | An agent from a workstation first, against the development site, with the browser in a container on the host network. CI later, when a job can reach the site and get mimic's token by workload identity |

## Consequences

- Step 4's done-line is a command: `just test-remote` against the deployed site, green.
- The deployment of a conformance site carries the remote site file, the echo image and a realm with the clients `session-docs` and `billing`, no client `no-such-client`, and a brokered provider whose first sign-in asks nothing.
- The echo backend echoes every header, the exchanged token and the identity header included: it must stand only behind a test site.
- A scenario added to the suite states where it runs; the local run reports the remote-only ones as skipped, with the reason.

## Roads not taken

| Road | Why not |
| --- | --- |
| A second package `conformance/remote` with its own copy of the scenarios | Two copies drift; Go test files of one package cannot be imported by another |
| A movable clock on the deployed site (a debug flag of `session serve`) | A flag that moves a deployed site's clock is a way round its lifetimes; the short site file tests the same rules with the real clock |
| `login_hint` and `kc_idp_hint` forwarded by session from the request | A request parameter that picks the person's identity provider is a site's design choice, not the runner's; the runner adds them to its own browser's requests only |
| The headless browser signing in at the issuer behind mimic | That sign-in is a person's multi-factor sign-in; a token handed to mimic is what CI does, and it names who ran the test |
| The echo as a subcommand of the session image | The test backend would ship in every production image |
| Reading the audit spool directly | The spool is the deployment's; a command the person gives reads it wherever it lives |
