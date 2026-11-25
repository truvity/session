# 0022. atoom's token block: the choices of the move to atoom 0.6.0

Status: proposed
Date: 2026-11-25

Carries out, for signing, what [0006](0006-built-on-atoom.md) decided (no crypto code of session's own where atoom has the part), now that atoom 0.6.0 has the `token` block (atoom record 0020) and `key/route`. It keeps every rule of [0016](0016-exchange-client-and-identity-header.md) and [0019](0019-signing-keys-on-aws-kms.md).

## Context

Until now `internal/signin` built its two compact JWS itself: the header, the SHA-256 of the signing input, the key port's `Sign` of the digest, the DER signature turned into `r||s`, and `/_session/jwks` from a `PublicKey` call of each purpose. atoom 0.6.0 has that part:

- `blocks/token`: `Sign(purpose, typ, claims_json)` through the seal block's `Sign`; `KeySet`, the JWK Set of the purposes' current keys and of keys the host hands in; `Verify`. The kid rule is per purpose, the key port's `key_id` (the default) or the RFC 7638 thumbprint. It is stateless; rotation is a later step (B8b).
- `key/route`: one key-port client in front of several drivers, each call sent to the driver of its purpose.

The seal block is already hosted by session ([0021](0021-atoom-policy-loader-and-seal-block.md)). Where atoom's records are silent, the build chose; those choices are below.

## Decision

| Subject | Choice |
| --- | --- |
| Where the block runs | In session's process, mounted on an in-memory transport and called through its generated client, over the seal block session already runs (`internal/sealer`, `Options.Tokens`). One seal block for sealing and signing |
| One key client | The seal block takes one client of the key port: `key/route` over the drivers session opened (`atoomx.KeySet.Route`), so each purpose stays on the driver `--key` chose for it, as 0019 says |
| The token purposes | `client-assertion` (type `JWT`) and `identity-header` (type `session-identity+jwt`), ES256, kid the key port's `key_id`. They are signing purposes of the seal block (`token.SealPurposes`), and their keys are declared to their drivers as before (`signin.Purposes`) |
| The seal block's rules | Now also allow `Sign` and `PublicKey`, under the two token purposes only. Every other purpose and operation is refused as before (`Rotate`, `Erase`, `Rewrap`, `MarkCompromised`) |
| The token block's rules | Allow every call (`token.AllowAll`): its one caller is session's own code in this process, the block itself refuses a type that is not its purpose's, and the seal block's rules bound what it signs |
| The block's facts | Not observed. Signing was not an audit event before, and [0008](0008-audit.md) lists the kinds |
| Claims and lifetimes | session's, unchanged: the claims as JSON with their names in order (Go's encoding of a map), the assertion's 60 seconds and `jti`, the identity header's lifetime and its 30-second reuse in the core |
| The header | The block's, which is byte for byte the one session made: `{"alg":"ES256","kid":"<key_id>","typ":"<type>"}` |
| `/_session/jwks` | The block's `KeySet` of the client assertion's purpose and, when there is an identity signer, the identity header's, in that order; session keeps the path, `Cache-Control: max-age=300` and the 503 when a key cannot be read |

## Consequences

- No JWS code is left in session; what session and sluis's `signer` sign now runs on the same code in atoom.
- The block reads each public key at its start and again for every key set, not for each signature, and checks every signature under the key before it answers: a signature that does not verify never leaves.
- The start ensures the key of each signing purpose in the seal block's start, with the wrapping key; a missing, disabled or wrong KMS key still fails it, with the same codes.
- The JWK Set has the same keys and members as before; only the order of the members inside each key differs (atoom writes `kty`, the key's members, `kid`, `alg`, `use`). Two purposes the deployment put on one KMS key would now be one entry, not the same key twice.
- The seal block's host now lets it sign, so a bug in session that called the seal client with a token purpose could sign without the token block; only the token block holds that client.

## Roads not taken

| Road | Why not |
| --- | --- |
| Keep session's own JWS code | A second copy of what atoom now has, which 0006 rules out |
| A second seal block for signing only, with its own rules | Two blocks over one wrapping key and one store prefix, and a second start that ensures the same keys; one host's rules say the same |
| A seal client per purpose instead of `key/route` | The seal block takes one key client; routing is what `key/route` is for |
| Rules in the seal block that parse what is signed (as sluis key@ checks a JWS of the expected shape) | Its one caller is the token block in this process, which builds the signing input itself; a check would repeat the block's own |
| The RFC 7638 thumbprint as kid | 0016 and 0019 keep the `key_id`, the key ARN on KMS; a new kid would make issuers and apps fetch the JWKS again for nothing |
| Handing earlier keys to `KeySet` (`HostKey`) now | No site rotates yet; it is the way the JWKS will keep the previous key (0019) until atoom's rotation ring (B8b) |

## Open

- Rotation of the signing keys: the previous key in the JWKS (0019), through `HostKey` or atoom's rotation ring, before the first site that rotates.
