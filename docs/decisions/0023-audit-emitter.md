# 0023. The emitter of truvity/audit: the choices of the switch from the stand-in

Status: accepted, 2026-11-25 (owner decision on the pull request of the move to the emitter of truvity/audit); partly superseded by [0024](0024-audit-transport-is-an-explicit-switch.md) (the rows "Local development only" and "Every named environment" of the transport, and the scope `local` for `--environment local`: the transport is the switch `--audit-stdout` or `--audit-socket`, never a value of `--environment`)
Date: 2026-11-25

Carries out what [0008](0008-audit.md) decided (security-audit events through the emitter of `truvity/audit`, over atoom's `transport` port, to the audit writer of the environment), now that `truvity/audit` 0.19.0 has the emitter in Go. It keeps every rule of 0008 and the fail-closed sign-in of [0015](0015-envoy-http-mode-csrf-header-and-step-2-choices.md).

## Context

Until now `internal/audit` was a stand-in: each `core.Event` as one JSON line of session's own shape on stdout, with the subject in clear. `truvity/audit` 0.19.0 has the emitter in Go, the module `github.com/truvity/audit/emitter`:

- From one call it builds one record, an OCSF 1.9.0 security record as RFC 8785 canonical JSON, checks it against the product's action table and the JSON Schema of its row, and hands it to the transport port's `Emit`.
- A person is never named: the subject becomes a pseudonym `p1.<YYYYMM>.<value>`, the keyed hash that the host of a `Mac` makes under the pseudonym key of the epoch, with a domain label that is the product's (audit records 0011 and 0018).
- Three calls: best effort (a failure is counted and the next record of the tenant carries the total), required, and blocking.
- The product brings its own action table and schemas; the generator of audit's table format has not moved to `truvity/audit` yet.

atoom 0.6.0 has the port (`transport`, `atoom.transport.v1alpha1.TransportService`) and one driver, `transport-spool`, in Rust, a sidecar that serves the emit side on a UNIX socket (`DIR/emit.sock`). There is no Go driver. The emitter 0.19.0 pins atoom 0.5.0; Go's minimum version selection takes session's 0.6.0, and the emitter builds on it and passes its own tests on it, so one atoom version stays in `go.mod`.

The records say what to use. Where they are silent, the choices below were made on 2026-11-25, by the owner (the transport outside local development, where the transport is set, the scope of the pseudonym key, the sign-in's call) and in the build; the record is accepted on its pull request.

## Decision

### The emitter

| Subject | Choice |
| --- | --- |
| The module | `github.com/truvity/audit/emitter` v0.19.0, with `transport` and `socket` of atoom 0.6.0: every atoom module stays at 0.6.0 |
| Product, component, scope | Product `session` (`metadata.product.name` and the product object `unmapped.session`); component `session` (`actor.user.uid` is `session@<scope>`); scope the `--environment` of the process, `local` for local development (`metadata.log_name`) |
| Release | session's version, which must be a semantic version: the default build's is now `0.0.0-dev` (it was `dev`, and `session version` prints the new value), as the writer refuses a record whose release is not a version |
| Tenant | None: the operator's own tenant, which the writer fills. session has no tenants; the site is a field of the product object |
| The stand-in's format | Dropped: no record of session's own shape is written any more |
| The time of a record | The emitter's clock at the emit, not `core.Event.Time`; both are the process's clock |
| Where it runs | In session's process, as a library, behind `core.Auditor` (`internal/audit.Auditor`); the core is unchanged |

### The table

session's action table is code in `internal/audit` (`Table`, `Schemas`): one row for each kind of `core.Event`, a kind and its failure folded into one action, because OCSF says the outcome in `status_id`. The classes follow audit's class mapping.

| `core.Event` kind | Action (`event_code`) | OCSF class, activity | Outcome |
| --- | --- | --- | --- |
| `sign-in` | `sign-in` | 3002 Authentication, 1 Logon | success |
| `sign-in-failed` | `sign-in` | 3002, 1 Logon | failure |
| `logout` | `logout` | 3002, 2 Logoff | success |
| `back-channel-logout` | `back-channel-logout` | 3002, 2 Logoff | success; failure when it has a reason (a refused logout token) |
| `denied` | `denied` | 6003 API Activity, 99 `Check`; with the policy decision in the `security_control` profile | failure |
| `token-exchange` | `token-exchange` | 3002, 99 `Token Exchange` | success; failure when it has a reason |
| `refresh-failed` | `refresh` | 3002, 99 `Refresh` | failure |

| Field of `core.Event` | In the record |
| --- | --- |
| `Kind` | `metadata.event_code`, `class_uid`, `activity_id` and `status_id`, as above |
| `Reason` | `status_code` of a failure, when it is a closed word (a letter, then letters, digits and `_ . : -`, at most 64); otherwise `unrecognised`. An issuer's error code is the issuer's text, and a record never carries text a request brought |
| `Subject` | The pseudonym: `user.uid` of an Authentication (`type_id` 1, User), the resource (`type` `person`) of an API Activity. The subject's kind is `person`, its value the issuer's subject |
| `Site`, `Issuer`, `Route`, `Audience` | Members of the product object `unmapped.session`: `site` (every record), `issuer`, `route` (a denial) and `audience` (a token exchange, every record) |
| `PolicyDigest` | `policy.version` of a policy denial; `policy.uid` is the name of the site's bundle (`policy.bundle`, `policy-bundle` in the example); `action_id` 2, Denied |
| `Time` | Not used: the emitter's clock |

- A denial's `api.operation` is `check`, or `logout` for the CSRF refusal of the logout path; its `src_endpoint.name` is `unknown`, because the transport of the check names no peer: session is not told which proxy asked.
- The schema of each action is closed where session writes: the product object has only its members (and `lost`, which only the emitter writes), the outcomes and activities are the row's, the subject is a pseudonym or `unknown`, the digest is 96 hex digits. The members the emitter fills from its configuration and the class are left to it.
- A record carries no header value, cookie, token or body, as before; it now carries no subject in clear either.

### The pseudonyms

| Subject | Choice |
| --- | --- |
| The `Mac` | The seal block session already runs ([0021](0021-atoom-policy-loader-and-seal-block.md)): a new keyed-hash purpose `pseudonym`, declared with `CallerGeneration`, whose generation is the epoch `YYYYMM` the emitter names. A new month makes a new data key, wrapped and kept like the others under `seal/`; HMAC-SHA384 with the label bound in, of which the emitter keeps 128 bits |
| The label | `session-pseudonym-v1`. A changed label changes every pseudonym |
| The scope | The installation's own (`session/<site>`): the same person has another pseudonym at another site, and in another scope of the log |
| When it cannot be made | A refusal (every failure above) is written without its subject (`user.uid` `unknown`) and one warning says so, at most once a minute; a success fails, and a sign-in with it |
| The seal block's rules | Unchanged: `Mac` in the installation's own scope, making a missing key, as for session's other hashes |

### The calls

| Event | Call | When the transport is down |
| --- | --- | --- |
| `sign-in` | Blocking (`EmitBlocking`): the answer comes when the transport says the record is durable | The sign-in fails closed with 503, as 0015 decided; the event is not lost, because the sign-in did not happen |
| Every other | Best effort (`Emit`), bounded by one second, a constant in code | The check is answered as before; the event is counted in `session_audit_dropped_total` and by the emitter, whose next record carries the total of lost facts |

### The transport

| Subject | Choice |
| --- | --- |
| Where it is set | A start-up setting, as the store and key drivers are: not the site file, whose planned `audit` section is dropped |
| To the audit writer of the environment | `session serve --audit-socket PATH`: a client of the port over the UNIX socket of the environment's transport driver, the emit socket of `transport-spool` (`DIR/emit.sock`), which names session from the peer credentials and whose consumer is the writer |
| Local development only | No `--audit-socket` with `--environment` unset or `local`: `internal/audit.Lines`, a driver of the port mounted in session's process, writes each record, the canonical JSON, as one line to stdout, as the stand-in did. It serves no consumer and keeps nothing. The drivers are told no environment, and the scope of the log is `local` |
| Every named environment | Any other value of `--environment` (`devel`, `stage`, `production`, `development`, or any other) refuses to start without `--audit-socket`: the records of an environment go to its writer |
| The tests | `Lines` over a buffer, and the seal block of `sealertest`: no socket, no container and no AWS. The conformance suite runs the emitter in its stand the same way, and checks after each host that every action its scenarios reach was recorded and that no record names the person |

## Consequences

- Each record is an OCSF record that the environment's writer can validate and seal; the stand-in's shape is gone, and with it the subject in clear.
- An install in any named environment runs a transport driver beside session, today the `transport-spool` sidecar, and the writer consumes it.
- session's records pass the emitter's checks before they leave: an event that does not fit the table is refused in the process, counted, and never reaches the writer.
- One more data key a month in the store, for the pseudonyms; the pseudonyms of a month can be destroyed with its key once the seal block's `Erase` is reachable.
- The operational log on stderr and the records on stdout stay apart in a run without a writer.

## Roads not taken

| Road | Why not |
| --- | --- |
| Keep the stand-in as a driver | Its shape is session's own and names the subject in clear; `Lines` writes the real records with the same ease |
| A Go driver of the spool in session's process | atoom has the spool in Rust only; a second implementation of a durable queue is atoom's to write, not session's |
| The transport in the site file (`audit.transport`, the planned shape of design section 10) | The site file says what a site is; which drivers run beside the process is the deployment's, as for the store and the keys |
| `Lines` in every environment but production when no socket is given | A record on stdout is not in the writer's log, and 0008 sends the events of an environment to its writer; only a run on a developer's machine has none |
| Always require a socket, even locally | Every local run and example would need a spool sidecar, for records nobody reads |
| `--environment` defaulting to `development` as before | An install that forgot the flag would then be an environment of its own name with nowhere to send its records; unset now means local development |
| A tenant for each site | session has no tenants, and a pseudonym key of the tenant would need a scope of the seal block for each site; the site is in the product object |
| A pseudonym key of the environment, shared by every site | Needs a host of the seal block beside the sites; within one installation, pseudonyms are stable |
| The issuer in the pseudonym's value | A site has one issuer; the issuer is in the product object |
| A YAML table and a generator, as sluis has | audit's generator has not moved to `truvity/audit`; six rows in code, with a test that the schemas pass audit's policy, are less to keep until it does |
| `sign-in-failed` and `refresh-failed` as actions of their own | OCSF says the outcome in `status_id`; two actions for one act would split what a reader looks for |
| A denial as Authorize Session (3003) or as Authentication | 3003 is a grant of privileges and Authentication a logon; a refused request at the edge is API Activity in audit's mapping |
| The activity of a denial by the HTTP method (2 Read, 1 Create) | `core.Event` has no method, and the event carries what it carried |
| A decision id of its own for each denial as `policy.uid` | A random id names nothing a reader can look up; the bundle's name and its digest name the policy that decided |
| A best-effort sign-in | 0008 and 0015: a sign-in completes only after its event is accepted |
| The required call (`EmitRequired`) for a sign-in | It waits only for the transport's answer, not for durability; the same on the spool, weaker on a driver that answers before it writes |
| A flag for the best-effort timeout | One second is well under a proxy's timeout for the check; a knob nobody needs yet |
| Keep the version `dev` and map it to a semantic version inside `internal/audit` | Two names for one build: what `session version` prints and what the records say would differ |

## Open

- Publishing session's catalogue (the table and its schemas, `internal/audit.Schemas`) to the writer of an environment: with the move of audit's generator and the `AuditCatalogue` kind.
- The Lambda shape: the transport driver of Lambda is atoom's planned `transport/sqs`.
- The seal block's `Erase` of a month's pseudonym key, with its rotation and rewrap (0021).
- A denial's gaps: its `src_endpoint.name` is `unknown`, because the check is not told which proxy asked, and its activity is always 99 `Check`, because `core.Event` has no HTTP method. Each needs a field of `core.Event`: the adapter that answered, and the method.
