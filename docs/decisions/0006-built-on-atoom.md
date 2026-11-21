# 0006. Built on atoom: ports, drivers, stores and sealing

Status: accepted
Date: 2026-11-20

## Context

`session` needs a place for sessions, keys to sign and seal with, and a place to read its site file and policy from. These are the ports of [atoom](https://github.com/truvity/atoom): `store`, `key` and `source`, with Go and Rust code, drivers and a conformance kit for each. atoom also has a layer of blocks above its ports: contracts built from other ports, such as `seal` (see the [atoom records](https://github.com/truvity/atoom/tree/master/docs/decisions)).

## Decision

### Ports and drivers

`session` uses atoom's ports and drivers directly, pinned to a release (0.2.0 first). It has no store, key or source interface of its own.

| Need | atoom | First drivers |
| --- | --- | --- |
| Sessions, pointer items, tombstones, exchange locks, the token cache | `store` port (`Get`, `Query`, `Transact`; items with an expiry; index entries written in the item's transaction) | `store/dynamodb` |
| `private_key_jwt` assertions, the signed identity header, the JWKS, record sealing | `key` port (`Sign`, `PublicKey`, `Ecdh`) | `key/awskms`, `key/software` (a key file) |
| The site file and the policy bundle | `source` port (`Read`, `Watch`) | `source/file` in Go |

- **Always the ConnectRPC contract.** `session` calls every port through its generated client, also when the driver runs in the same process: the driver's handler is mounted on an in-memory transport. A driver can then move to a socket or a Lambda extension by configuration alone. The deadline and the correlation id travel with every call. The correlation id header is `Atoom-Correlation-Id`, and the old `Sluis-Correlation-Id` is accepted for one release.
- **Drivers run in-process on every shape.** `session` is Go and atoom's AWS drivers are Go, so no sidecar and no Lambda extension is needed. A driver in another language is reached over a socket where an install wants it.

### Stores

- `session` runs on **any atoom store driver that passes the store kit**: DynamoDB first, PostgreSQL and Valkey when atoom builds them.
- Durable and temporary data use the same item interface. A store driver declares its durability: `strict`, or `lossy` (a failover can lose acknowledged writes). **`session` accepts either**, because a lost session only means a new sign-in.
- Rules of the session store:
  - one strongly consistent read per check, and nothing else on the request path;
  - pointer items and one tombstone read at creation for logout ([0010](0010-logout-pointer-items.md));
  - a timeout on every store call, shorter than the proxy's timeout for the check, so a slow store is a down store and the check answers 503 ([0011](0011-host-adapter-rules.md));
  - expiry is a TTL attribute plus an explicit expiry check on read, because TTL deletion is lazy;
  - idle refresh is a conditional update;
  - the exchange lock is a conditional write with a short expiry, one item for each session and audience.
- **No local session cache at first.** Replicas keep no session state, so a logout is seen at once. The first spike measured DynamoDB Local only. Open: the latency of real DynamoDB from the target region, which confirms or reverses "no local cache".
- A memory store exists for tests only and refuses to start in production mode.
- The Helm chart takes the store and key driver settings and a cloud identity. It does not run a store.

### Sealing

- Session records and cookies are sealed by atoom's **`seal` block**, the core of sluis key@ moved into atoom. `seal` holds data keys per purpose, wrapped through the key port's `Ecdh` (one KMS call per key, not per request), and offers `Seal`, `Open` and `Mac`.
- A sealed value is bound to its address (session id and purpose) as authenticated data, so a value copied to another session does not open.
- Keys are per purpose and installation, never per person. The store never seals or opens. `session` calls `seal` explicitly and decides which fields it seals. Fields that index entries or conditions use stay readable.
- Which purposes exist is `session`'s own declaration to `seal`. Who may use which purpose is a rule `session` hands to `seal` through its rules hook, so `session` needs no grants.

### What is built and what is planned

| Item | State |
| --- | --- |
| atoom 0.2.0: the `store` port with the `dynamodb`, `rqlite` and `memory` drivers, the `key` port with `awskms`, `software` and `yubikeypiv`, the `source` port, kits and distribution | Built |
| The `seal` block, with purposes declared by its host (the key port takes any purpose its host declares) | Planned in atoom |
| The Go `source/file` driver | Planned in atoom |
| The Cedar loader in Go with the decision test set ([0007](0007-policy.md)) | Planned in atoom |
| The `durability` field of the store contract | Planned in atoom |
| The audit emitter in Go ([0008](0008-audit.md)) | Planned in `truvity/audit` |
| `Atoom-Correlation-Id` | Planned in atoom |

## Consequences

- `session` has no port interfaces of its own. Its core depends on atoom's generated clients, the `seal` block and `cedar-go`.
- An upgrade of atoom is a pinned bump. While atoom's contracts are `v1alpha1`, a breaking change raises atoom's minor version, and `session` follows it on purpose.
- Sessions can move to another store by configuration, if it passes the kit.

## Roads not taken

| Road | Why not |
| --- | --- |
| Our own store, key and policy interfaces shaped like the sluis building blocks | They would duplicate atoom for ever |
| atoom's store only, with our own key handling | Half shared |
| Direct handler calls to drivers | They skip the interceptors and share messages |
| Sidecars on every shape | No fit for Lambda |
| DynamoDB only | One backend is simple, but a real site may need another store, and the kit keeps that open |
| Valkey for clusters and DynamoDB for API Gateway installs, both built first | Two backends to build, test and secure before a site needs the second |
| Our own sealing over `Ecdh` | A second copy of crypto code |
| A data-key call added to the key port | A contract change in every driver |
| No sealing | A store leak would expose the sessions |
| A local session cache | Needs invalidation across replicas, or logout lags |
