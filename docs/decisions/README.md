# Decision records of session

Each record stands alone: status and date, context, decision, consequences and roads not taken. The [design](../design.md) puts them together and shows how the parts work.

## The records

| Record | Subject |
| --- | --- |
| [0001](0001-purpose-scope-and-name.md) | Purpose, scope and name |
| [0002](0002-own-go-service-and-external-authorisation.md) | Our own Go service, deployed as external authorisation |
| [0003](0003-repository-contents.md) | Repository contents |
| [0004](0004-browser-session-contract.md) | The browser session contract (S1 to S8, defaults) |
| [0005](0005-tokens-per-api-and-issuers.md) | Per-API tokens by token exchange, and the issuers |
| [0006](0006-built-on-atoom.md) | Built on atoom: ports, drivers, stores and sealing |
| [0007](0007-policy.md) | Policy: Cedar as a library, with a shared bundle |
| [0008](0008-audit.md) | Audit: the security class only, never usage |
| [0009](0009-session-core-block.md) | The session core is a block, built inside session first |
| [0010](0010-logout-pointer-items.md) | Logout without a secondary index: pointer items and one tombstone read (pointer items superseded by 0031) |
| [0011](0011-host-adapter-rules.md) | Host adapter rules: Envoy, nginx, API Gateway, the store timeout |
| [0012](0012-lambda.md) | Lambda: every function behind the Web Adapter |
| [0013](0013-reference-stand.md) | Reuse of the group SSO reference stand |
| [0014](0014-authorizer-native-go-handler.md) | The authorizer is a native Go handler |
| [0015](0015-envoy-http-mode-csrf-header-and-step-2-choices.md) | Envoy HTTP mode and the CSRF header; the choices of step 2 (partly supersedes 0011) |
| [0016](0016-exchange-client-and-identity-header.md) | The exchange client and the identity header: the choices of step 3.1 |
| [0018](0018-nginx-adapter.md) | The nginx adapter: the choices of step 3.2 (partly supersedes 0011) |
| [0019](0019-signing-keys-on-aws-kms.md) | Signing keys on AWS KMS: the choices of step 3.3 |
| [0020](0020-conformance-suite.md) | The conformance suite: the choices of step 3.4 |
| [0021](0021-atoom-policy-loader-and-seal-block.md) | atoom's policy loader and seal block: the choices of the move to atoom 0.5.0 |
| [0022](0022-atoom-token-block.md) | atoom's token block: the choices of the move to atoom 0.6.0 |
| [0023](0023-audit-emitter.md) | The emitter of truvity/audit: the choices of the switch from the stand-in |
| [0024](0024-audit-transport-is-an-explicit-switch.md) | The audit transport is an explicit switch, not a value of `--environment` (partly supersedes 0023) |
| [0025](0025-first-version-for-the-first-sites.md) | The first version for the first sites: step 4, and what step 5 waits for |
| [0026](0026-exchange-targets-what-the-issuer-allows.md) | The route mode `exchange` targets what the site's issuer allows: with sluis v2, resource clients only |
| [0027](0027-atoom-0.7.0-and-the-audit-scope-flag.md) | atoom 0.7.0 and `--audit-scope`: the key drivers are told no installation (partly supersedes 0024) |
| [0028](0028-the-image.md) | The image of session, and what else a deployed first site needs from this repository |
| [0029](0029-the-remote-runner.md) | The remote runner: the conformance scenarios against a deployed site, and the echo test backend |
| [0030](0030-lambda-handlers-step-5-choices.md) | The Lambda handlers: the choices of step 5 before atoom's B9 |
| [0031](0031-logout-across-hosts.md) | Logout across hosts: end-session, back-channel logout, the lookup, cookies and audit (partly supersedes 0010) |
| [0032](0032-atoom-0.8.0-transports-and-the-appconfig-source.md) | atoom 0.8.0: the audit transports NATS and SQS, and the AppConfig source |

## How the records are kept

- On 2026-11-21 the records were rewritten once, cleanly, to state the current design and to fold in every amendment. History before that is in git.
- **From this rewrite on, the records are append-only.** A change to a decision is a new record that supersedes the old one. The old record moves to [archive/](archive/) and keeps its number, with a "superseded by" note. Typos and links may be fixed in place.
- A record that is accepted but not yet built says what is built and what is planned. "Open:" marks a question nobody has decided.

## Renumbering in the clean rewrite

The records have new numbers. The old numbers appear in the archive, in the [archived spike findings](../archive/spike-2026-11-18.md), and in git history. The archived records `0009`, `0010` and `0014` keep their old numbers and are not the records with the same numbers above.

| Old record | Subject | Now |
| --- | --- | --- |
| 0001 | Purpose and scope | 0001 |
| 0008 | Name | 0001 |
| 0002 | Our own Go service | 0002 |
| 0003 | Deployment is external authorisation | 0002 |
| 0004 | Repository contents | 0003 |
| 0005 | Browser session behaviour contract | 0004 |
| 0011 | Defaults accepted | 0004 |
| 0012 | Answers to the first open questions | 0004 (Q5), 0005 (Q4, Q7, Q9), 0006 (Q2, Q3), 0011 (Q1, Q6, Q8) |
| 0006 | Per-API tokens by token exchange | 0005 |
| 0007 | Issuers, and the sluis v1 check | 0005 |
| 0017 | session is built on atoom | 0006 (ports, stores, sealing), 0007 (policy), 0008 (audit), 0009 (block), 0012 (Lambda), 0013 (reference stand) |
| 0013 | Logout without a secondary index | 0010 |
| 0015 | API Gateway handlers and caching | 0011, 0012 |
| 0016 | Host adapter rules | 0011 |
| 0009 | Ports shaped like the sluis v2 building blocks | [archived](archive/0009-ports.md), superseded by 0006 |
| 0010 | Sessions in DynamoDB on every shape | [archived](archive/0010-dynamodb-sessions-everywhere.md), superseded by 0006 |
| 0014 | Installs without AWS | [archived](archive/0014-installs-without-aws.md), superseded by 0006 |

## Archive

- [0009 Ports shaped like the sluis v2 building blocks](archive/0009-ports.md)
- [0010 Sessions in DynamoDB on every shape](archive/0010-dynamodb-sessions-everywhere.md)
- [0014 Installs without AWS](archive/0014-installs-without-aws.md)
- [Findings of the first spike](../archive/spike-2026-11-18.md) and its [run notes](../archive/spike-2026-11-18-run.md)
