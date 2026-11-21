# 0017. session is built on atoom: its ports, blocks, sealing, policy, audit and Lambda packaging

Status: accepted, 2026-11-20 (maintainer decisions S1 A, S2 B, S3, S4' B, S5 A, U1 A, Q3a A, Q3b A, 3' A, B1 A, R A). Supersedes 0009 and 0014. Amends 0002, 0010, 0012 (Q3, Q4), 0015 and section 9 of the design.

## Context

0009 gave `session` three Go interfaces of its own (store, key, policy), shaped like the sluis v2 building blocks, to be swapped for the blocks once the sluis core was done. Since then the shared parts of sluis moved into [truvity/atoom](https://github.com/truvity/atoom), and atoom 0.2.0 was released on 2026-11-20. It has the `store` port with the `dynamodb`, `rqlite` and `memory` drivers, the `key` port with the `awskms`, `software` and `yubikeypiv` drivers, and the `source` port, with Go and Rust code and a conformance kit for each port. The maintainers then decided how session uses atoom, and how atoom grows a layer of blocks above its ports.

## Decision

### Ports and drivers (S1 A)

`session` uses atoom's ports and drivers directly, pinned to a release (0.2.0 first). It has no store, key or source interface of its own.

| Need | atoom | First drivers |
| --- | --- | --- |
| Sessions, pointer items, tombstones, exchange locks, token cache | `store` port (`Get`, `Query`, `Transact`; items with an expiry; index entries written in the item's transaction) | `store/dynamodb` |
| `private_key_jwt` assertions, the signed identity header, the JWKS, record sealing | `key` port (`Sign`, `PublicKey`, `Ecdh`) | `key/awskms`, `key/software` (a key file) |
| The site file and the policy bundle | `source` port (`Read`, `Watch`) | `source/file` in Go (a new atoom driver, decision 4 A) |

- **Always the ConnectRPC contract.** session calls every port through its generated client, also when the driver runs in the same process: the driver's handler is mounted on an in-memory transport (atoom's in-process mode). A driver can then move to a socket or a Lambda extension by configuration alone. The deadline and the correlation id travel with every call (`call.Inherit` in Go).
- **Drivers run in-process on every shape.** session is Go and atoom's AWS drivers are Go, so no sidecar and no Lambda extension is needed. A driver in another language (the Rust `store/rqlite`) is reached over a socket where an install wants it.

### Stores (S5 A, supersedes 0014, amends 0010)

- session runs on **any atoom store driver that passes the store kit**: DynamoDB first, PostgreSQL and Valkey when atoom builds them. Valkey is no longer dropped (0010): it fits sessions, which are temporary data.
- Durable and temporary data use the same item interface. A store driver declares its durability ("strict", or "may lose acknowledged writes on failover"). sluis refuses a lossy driver for its lasting data. **session accepts either**, because a lost session only means a new sign-in.
- The rules of the session store do not change: one strongly consistent read per check; pointer items and a tombstone read at creation (0013); a timeout on every call (0016).

### Sealing (S3)

- Session records and cookies are sealed by atoom's **`keyring` block**, the core of sluis key@ moved into atoom. `keyring` holds data keys per purpose, wrapped through the key port's `Ecdh` (one KMS call per key, not per request), and offers `Seal`, `Open` and `Mac`.
- A sealed value is bound to its address (session id and purpose) as authenticated data, so a value copied to another session does not open.
- Keys follow the sluis model: **per purpose and installation, never per person.** The store never seals or opens. session calls `keyring` explicitly and decides which fields it seals; fields that index entries or conditions use stay readable.
- Who may use which purpose is a rule that session hands to `keyring` (its rules hook); session needs no grants.

### Policy (S4' B)

- Cedar is used **as a library**: `cedar-go` in session, in-process. This is a named exception to "always the ConnectRPC contract", because Cedar is a library by design. Its own API keeps all of its types and features.
- What is shared with sluis and ritueel comes from atoom:
  - the **signed policy bundle**: schema, policies, templates and links in one signed document, read through `source`;
  - the **loading rules**: verify the signature before parsing; validate against the schema in strict mode; compile once and swap atomically; keep the last good set when a reload fails; refuse a cold start with no valid set; refresh on watch or by ETag with a minimum interval; no I/O during a decision; audit each decision with the digest of its policy set;
  - the **loader library** in Go;
  - a **decision test set** that runs against `cedar-go` and the Rust `cedar-policy` in CI.
- In Envoy's `ext_authz` and in the Lambda authorizer, the decision runs **in-process on every request**. The entities come from the session item the check already read (the person's claims, cached at sign-in) and from the route in the site file. There is **no extra read and no call to sluis's policy actor** on the request path.
- The site file's route table keeps what is structure (does a route need a session, which audience's token does it need). Cedar decides who may reach a route.

### Audit (Q3a A, Q3b A, U1 A)

- session emits **security audit** events through the emitter of `truvity/audit` over atoom's `transport` port, and never waits on them for a decision: sign-in, logout (local and back-channel), refresh failures, token exchanges, denials. A sign-in completes only after its event is accepted by the transport.
- Allowed requests are **counted as metrics**, not logged one by one.
- The events go to the **audit writer of the sluis installation** of the environment (the new `truvity/audit` product).
- When the transport is down, checks keep being answered; dropped events are counted and raise an alert.
- **session never emits usage or billing records.** A product behind session meters its own usage.

### Blocks (B1 A)

atoom gains a layer of blocks above its ports. A block has a contract like a port's, is built from other ports and blocks, declares its dependencies, which are passed in, has no backend code and no cycles, and takes its rules from its host. One implementation per block, in the language of its main host; another language calls it as a process. session's own core is a block: session records, the sealed cookie, idle and absolute expiry, logout pointers, the exchange cache. **It is built inside `truvity/session`** and moves into atoom when sluis's `session` actor adopts it. That is the general rule: a block moves into atoom at its second consumer.

### Lambda packaging (3' A, amends 0015)

- Every Lambda function of session runs behind the **Lambda Web Adapter**, vendored and pinned in session's own layer. The binary is the same HTTP server on every shape.
- The authorizer is the open case. The adapter does not list API Gateway authorizer events among the events it supports. The fit spike tests it. If authorizer events do not arrive correctly, the authorizer alone keeps a native Go handler, in the same binary.
- A function is the app zip, the adapter's layer and one configuration layer (site file, policy bundle). Drivers are in-process, so there is no drivers layer.

### The reference stand of the group SSO design (R A, amends 0002)

`session` stays our own Go service (0002 B). The reference stand of the group's SSO design (Apache with `mod_auth_openidc` and the Go audience broker) is not the implementation. Its code may be reused where it fits:

- the broker's rules (the forgery check, the route allowlist, the exchange per audience and its cache keys, step-up), from `drafts/kit/io-gate`;
- the browser library `@stand/proxy-client`;
- the conformance suites and the browser scenarios.

Its Keycloak findings go into the conformance suite:

- redirect to sign-in only on a navigation;
- `passMaxAge` for step-up through a broker;
- the client assertion's audience is the token endpoint;
- `id_token_hint` at logout;
- the reuse of a client assertion at logout.

`session` is the group's browser-session proxy for product fronts.

## Options considered

| Question | Decided | Roads not taken |
| --- | --- | --- |
| Interfaces | atoom's ports and drivers now | Our own interfaces (0009, duplicates atoom); atoom's store only (half-shared) |
| Driver placement | In-process, through the ConnectRPC contract on an in-memory transport | Direct handler calls (skip interceptors, share messages); sidecars on every shape (no fit for Lambda) |
| Stores | Any driver that passes the kit, durability declared | DynamoDB only (0010, 0014) |
| Sealing | atoom's `keyring` block | Our own sealing over `Ecdh` (a second copy of crypto code); a data-key call added to the key port (a contract change in every driver); no sealing |
| Policy | Cedar libraries, with a shared bundle, loading rules, loaders and a test set | A ConnectRPC policy-engine port (re-describes Cedar's API, loses features as Cedar grows); only the Rust engine over a socket (a hop on every request); a plain route table only |
| Audit writer | sluis's writer of the environment | A writer for each session installation |
| Allowed requests | Counted | Logged one by one (volume follows traffic) |
| Usage | None | Every allowed request as a usage record (a durable write on every request) |
| Lambda | The Web Adapter on every function; the authorizer after a spike | A native handler for the authorizer from the start |
| The reference stand | Our Go service, reusing the stand's code where it fits | The Apache shape packaged for atoom (no authorizer, a C fork for the store and KMS); both behind one contract |

## Consequences

- session has no port interfaces of its own. Its core depends on atoom's generated clients, the `keyring` block and `cedar-go`.
- atoom must ship, for session's first version: the `keyring` block, the Go `source/file` driver, the Cedar loader in Go with the decision test set, the audit emitter in Go, and the durability field of the store contract.
- The fit spike (next steps) runs the check core on atoom 0.2.0 drivers. It also tests authorizer events through the Lambda Web Adapter.
- An upgrade of atoom is a pinned bump. While atoom's contracts are `v1alpha1`, a breaking change raises atoom's minor version, and session follows it on purpose.
