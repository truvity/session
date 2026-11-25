# The remote runner

The conformance scenarios of `conformance/` against a deployed site ([decision 0029](../../docs/decisions/0029-the-remote-runner.md)). The local suite (`just test-conformance`, [0020](../../docs/decisions/0020-conformance-suite.md)) builds its own stand; this runner points the scenarios that need none of the stand's tricks at `https://<host>`.

```sh
export SESSION_REMOTE_MIMIC_TOKEN=...     # a token for mimic's POST /session, never on the command line
just test-remote HOST=docs.devel.example.com ISSUER=https://idp.devel.example.com/realms/session-conformance \
  IDP=mimic HINT=alice EMAIL=alice@example-a.test MIMIC=https://mimic.devel.example.com
```

## Which scenarios run where

| Scenario | Local | Remote | Why not the other |
| --- | --- | --- | --- |
| No session: a public route passes, an API call gets the JSON 401 | yes | yes | |
| Sign-in: to Keycloak and back with the S1 cookie | yes | yes | |
| Protected route: no session cookie, no owned headers at the site (S8) | yes | yes | |
| The sign-in prefix `/_session/` without a check | yes | yes | |
| CSRF with and without the header (S5) | yes | yes | |
| Exchange, identity header, a refused exchange | yes | yes | |
| Store outage: 503, never an allow | yes | no | A deployed site's store cannot be taken down from the test |
| Bad paths | yes | yes | |
| Logout and Keycloak's end-session (S6) | yes | yes | |
| Back-channel logout | yes | no | Ending the person's Keycloak session from outside the browser takes the realm's admin API |
| Refresh refused | yes | no | The admin API again, and a clock six minutes ahead (Keycloak's access tokens live five) |
| Idle lifetime | no | yes | It waits out `session.idle` of the remote site file (90 s) in real time; the local stand keeps the defaults |
| Absolute lifetime | no | yes | It waits out `session.max` (3 min) in real time, with a request every 20 s |

A run takes about seven minutes, most of it the two lifetimes. The scenarios run in order and a failing one stops the run, because the later ones build on its session. `SKIP=<pattern>` (go test's `-skip`) leaves one out, for example `SKIP='TestRemote/bad_paths'` when an edge in front of the proxy answers the bad paths itself.

## What the site needs

- The site file [`site.yaml`](site.yaml), with `host` and `issuer` set to the deployment's: the suite's routes, and the short lifetimes. Every route sends to the test backend `ghcr.io/truvity/session-echo` (port 8080), which echoes each request's method, path and headers as JSON. It echoes the exchanged token and the identity header too, so it stands only behind a test site.
- A realm with the client `session-docs` (`private_key_jwt`, redirect `https://<host>/_session/callback`, post-logout redirect `https://<host>/`), a client `billing` that `session-docs` may exchange to, no client `no-such-client`, and a brokered provider whose first sign-in asks nothing.

## Settings

Each `KEY=VALUE` argument becomes `SESSION_REMOTE_<KEY>`; the variables may be set directly too.

| Key | Meaning |
| --- | --- |
| `HOST` | The site's host (required), with a port when it is not 443 |
| `ISSUER` | The realm's issuer; the site file's when not given |
| `SITE_FILE` | The site file the site runs, for its name and lifetimes; `conformance/remote/site.yaml` when not given |
| `IDP` | The alias of the brokered provider at Keycloak, added to the sign-in as `kc_idp_hint` |
| `HINT` | The test identity, added as `login_hint` and picked at mimic's chooser |
| `EMAIL` | The e-mail address `whoami` must name; any when not given |
| `MIMIC`, `MIMIC_TOKEN_FILE` | mimic's public URL, and a file holding the token for its `POST /session` (or `SESSION_REMOTE_MIMIC_TOKEN`) |
| `USERNAME` | A person of the realm itself, signed in at Keycloak's form, with `SESSION_REMOTE_PASSWORD` |
| `CA` | A PEM file of the CA of the site's or the issuer's certificate, trusted by the runner and the browser |
| `RESOLVE` | An address to send the host to instead of its DNS answer |
| `PROXY` | `envoy` (the default) or `nginx`: whose answers to the bad paths are expected |
| `AUDIT` | A command that prints the site's audit records since `$SESSION_REMOTE_SINCE`, one JSON record a line |
| `SKIP` | go test's `-skip` pattern |

The runner adds `kc_idp_hint` and `login_hint` to the browser's requests to the issuer's authorization endpoint, so session's own sign-in request is unchanged. mimic signs in the identity of the hint at once when the browser has a session there, which the token hands over as a CI job does.

## Audit

The records of a deployed site go to its spool, not to the runner, so the remote run does not check them unless `AUDIT` names a reader. With one, it checks what the local suite checks of the actions it reaches: every line is a record, none names the test identity in clear, and sign-in, denied, token exchange and logout are there. Back-channel logout and refresh are not reached remotely.
