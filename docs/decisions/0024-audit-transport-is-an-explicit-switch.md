# 0024. The audit transport is an explicit switch, not a value of `--environment`

Status: proposed; if accepted, partly supersedes [0023](0023-audit-emitter.md)
Date: 2026-11-25

## Context

[0023](0023-audit-emitter.md) chose where the security-audit records go by the value of `--environment`: unset or `local` wrote them to stdout, and any other value refused to start without `--audit-socket`. That puts knowledge of deployment shapes in reusable code: session decided a policy from the name of an environment. The principle session follows is that reusable code names no environment, region, account, host, organisation, cluster or namespace, and never says "if the environment is X then do Y"; a deployment chooses behaviour with explicit, neutral start-up switches or configuration it supplies.

## Decision

| Subject | Choice |
| --- | --- |
| The transport | Exactly one of two start-up switches. `--audit-socket PATH`: the emit socket of a transport driver (`transport-spool`, whose consumer is the audit writer), as in 0023. `--audit-stdout`: `internal/audit.Lines`, a driver in the process that writes each record as one JSON line to stdout, for local development |
| Neither | session refuses to start: `--audit-socket is required`, and the message names `--audit-stdout` |
| Both | session refuses to start: the place of the records is ambiguous |
| `--environment` | A label only. It is the scope of the log (`metadata.log_name`, `actor.user.uid` `session@<scope>`), `local` when unset, and, until atoom 0.7.0, the environment the software key driver is told, verbatim. Nothing in session decides by its value; `local` is no longer special |

## Consequences

- A local run says so with `--audit-stdout`; a deployment that forgot `--audit-socket` fails at start whatever it calls itself, as 0023 meant.
- `--environment local` now reaches atoom 0.6.0's software key driver as `local`, which that driver refuses when a purpose is on it; unset still works. This goes away with atoom 0.7.0, which drops the environment from `key/software` and `key/yubikeypiv`.
- The one place session still hands an environment to a driver is `atoomx.OpenKeys` (`KeyOptions.Environment`, from `cmd/session/main.go`, and `Environment: "development"` in three tests). It is removed when session moves to atoom 0.7.0, not here.

## Roads not taken

| Road | Why not |
| --- | --- |
| Keep 0023's rule with a longer list of local names | Still a policy chosen by an environment's name |
| `--audit-transport` (`socket` or `stdout`) with `--audit-socket` for the path | Two flags to say one thing; a path or a yes is enough |
| Default to stdout, `--audit-socket` to leave it | An install that forgot the flag would run without a writer and nobody would notice |
| `--audit-stdout` silently ignored beside `--audit-socket` | Either choice of which wins hides a mistake in the deployment |

## Open

- Whether `--environment` keeps its name once it is only the scope of the log (atoom 0.7.0), or becomes `--audit-scope`.
