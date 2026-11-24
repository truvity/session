# 0021. atoom's policy loader and seal block: the choices of the move to atoom 0.5.0

Status: proposed
Date: 2026-11-24

Carries out what [0006](0006-built-on-atoom.md) (sealing) and [0007](0007-policy.md) (the shared bundle, the loading rules, the loader) decided, now that atoom has built them: the `seal` block (atoom 0.4.0) and the Cedar loader `policy` (atoom 0.5.0, atoom record 0019). It ends the interim of [0019](0019-signing-keys-on-aws-kms.md), whose sealing "stays on the local sealer".

## Context

Until now `session` had two stand-ins: `internal/localseal` (AES-256-GCM and HMAC-SHA256 under keys derived from one root key file) and a Cedar loader that read plain Cedar text through the source port, with no signature, no schema and a SHA-256 digest of the text. atoom 0.5.0 has both shared parts:

- `policy`: a signed document (a JWS in the general JSON serialisation, ES384, protected header `alg`, `kid`, `seq`, `kind`) of the kind `PolicyBundle`, read through the source port by the name `policy-bundle`; a payload of a schema and policies by id; strict validation against the schema; an atomic swap; the last good set kept; a cold start refused without a valid set; refresh by watch or poll; decisions with the SHA-384 digest of the payload. `cedar-go` has no templates; `session` uses none.
- `blocks/seal`: data keys per purpose and scope, wrapped through the key port by an ECDH-P384 wrapping key and kept in the store port; `Seal`, `Open`, `Mac`; the host declares the purposes and supplies the rules.

The records say what to use. Where they are silent, the build chose; those choices are below.

## Decision

### Policy

| Subject | Choice |
| --- | --- |
| The pinned key | The site file holds it: `policy.verify_key`, a `kid` and a P-384 public key as PEM (`PUBLIC KEY`), one key. `session check` refuses a missing or broken key. A key is pinned by configuration and never by a document |
| Rotating the publisher's key | A new site file with the new key and a restart, as the site file is read once at start; the bundle signed by the new key goes out with it |
| The schema | The bundle carries it, as atoom's format says. `session` gives every decision the same entities as before (`User`, `Group`, `Route`, an action per HTTP method, the context `path` and `method`) and ships their schema: `internal/policy.Schema`, the schema of `examples/policy-bundle.json`. Its actions are `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` and `OPTIONS`; a bundle that serves other methods declares them |
| A request that does not fit the schema | A denial (atoom's misfit): 403 `forbidden`, as any denial, and an audit event `denied` with the reason `misfit`, so a schema that does not match `session`'s entities is found in the audit log |
| The digest | atoom's value as it is: the SHA-384 of the payload in lower-case hex, 96 characters, in the audit field `policy_digest`. No prefix: it is what `sha384sum` of the payload and the loader's own outcome show |
| Refresh | The loader's `Run`: a watch of the file driver's `policy-bundle.jws`, reads at least a second apart. On Lambda the source never changes and `Run` returns |
| Outcomes of a reload | Logged in the operational log (applied, rejected, unavailable, with digest and seq). Not a security-audit event: [0008](0008-audit.md) lists the kinds, and a kind for a policy change would be a decision of its own |
| Signing a bundle | Not in `session`. A bundle is signed by its publisher's pipeline in atoom's format, the format of sluis's signed config; `internal/policy/policytest` signs bundles for the tests only |

### Sealing

| Subject | Choice |
| --- | --- |
| The block | `blocks/seal` mounted in process and called through its generated client (`internal/sealer`), as every port is ([0006](0006-built-on-atoom.md)). `core.Sealer` stays the core's interface |
| Purposes | Seal: `session-record` (code 1), `signin-record` (2), `exchanged` (3). Mac: `session-key`, `lookup-key`. A code is never given to another purpose |
| Address | One part: the store key the value is kept under, which is a keyed hash of the session id (or of the state, the audience) with its kind. The purpose is bound by the envelope's code |
| Mac | HMAC-SHA384 (48 bytes) labelled with the purpose's name. Store keys grow from 43 to 64 characters |
| Installation and scope | The installation is `session/<site>`; `session` uses the installation's own scope only |
| Rules | The core is the block's one caller: `Seal`, `Open` and `Mac` in the own scope, and `Seal` and `Mac` make a missing data key. `Rotate`, `Erase`, `Rewrap` and `MarkCompromised` are refused on the core's client |
| Where the wraps live | In `session`'s store, under the block's prefix `seal/`, beside the core's items (`s/`, `x/`, and so on): no second table. The block's seal counters are there too. The tests give the block a store double of its own, so that counts of the core's store stay the core's |
| The wrapping key | The key purpose `wrapping` (ECDH-P384), chosen with `--key` like the signing purposes: the key file by default, or AWS KMS with `--key wrapping=awskms[:KEY]`, an `ECC_NIST_P384` `KEY_AGREEMENT` key the deployment makes, and `kms:DeriveSharedSecret` for the role. A missing or wrong key fails the start |
| Replicas | Every replica of an installation uses the same wrapping key (the same KMS key, or the same key file). The block wraps each data key for this instance's wrapping key alone; a replica with another key cannot open the data keys of the others |
| The request path | The check still reads one item. The block keeps each data key and its current generation for 15 minutes (atoom's default): after a start, and then every 15 minutes for each purpose, the next `Mac` or `Open` reads the wraps (one query) and opens one with one ECDH (one KMS call on KMS). Seals take from reservations of 1024: one store write for each 1024 seals |
| The old format | Values sealed by the local sealer do not open under the block, and the store keys change with the MAC. Nothing is deployed ([design section 16](../design.md#16-status-and-next-steps)), so nothing is migrated. `--seal-root` and `session seal-root` are gone |

## Consequences

- A tampered, unsigned or older bundle is refused before it is parsed, and the last good set stays; a bundle that does not validate against its schema never replaces one that does.
- A site with a policy needs a publisher key pair and a pipeline that signs bundles; the example's public key is a placeholder to replace.
- A stolen store no longer holds anything that opens with a file next to it: the data keys are wrapped by a key on the key port, on KMS where it must not leave.
- The deployment makes one more KMS key when the wrapping key is on KMS.
- What sluis key@ and `session` seal now runs on the same code in atoom.

## Roads not taken

| Road | Why not |
| --- | --- |
| The verify key as a file path (the planned shape of design section 10) | A second file to ship beside the site file; on Lambda one more part of the configuration layer. Inline, `session check` sees it |
| The verify key as a document of the source port | The source that serves the bundle could then serve the key that verifies it |
| Several pinned keys, or a co-signer, now | One publisher is enough until a site needs rotation without a restart or a second signature; atoom's loader already takes a list |
| Keep the `sha256:` style prefix on the digest | It would differ from the value atoom and its other consumers show for the same set |
| A security-audit event for each reload | A new event kind, which 0008 does not have |
| A separate table, or a store namespace of its own, for the wraps | More to deploy for a few items; the prefix keeps them apart |
| A list of recipients for the data keys (each replica its own wrapping key) | Needs a signed list of recipients and a `Rewrap` job, as sluis's `KeyPlan` has; one shared key is enough for one installation |
| Keep the local sealer for a release | A second copy of crypto code, which 0006 rules out; nothing deployed needs it |

## Open

- How a site rotates the data keys and the wrapping key (the block's `Rotate` and `Rewrap`): not reachable from `session` yet, and needed before the first site that must rotate.
