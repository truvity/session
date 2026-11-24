# 0019. Signing keys on AWS KMS: the choices of step 3.3

Status: accepted, 2026-11-24 (owner decision on the pull request of step 3.3)
Date: 2026-11-24

Builds what [0005](0005-tokens-per-api-and-issuers.md) and [0006](0006-built-on-atoom.md) decide for the key port: the `private_key_jwt` key, and the key of the identity header of [0016](0016-exchange-client-and-identity-header.md), on atoom's `key/awskms` driver where the key must not leave, chosen at start.

## Context

Step 3.3 of the plan puts session's signing keys on AWS KMS. session signs with two purposes of the key port: `client-assertion` (the `private_key_jwt` assertion of S3, read by the issuer) and `identity-header` (the identity header, read by apps). Until now both lived in key files, on atoom's `key/software` driver. The design says which drivers run is a start-up setting, not part of the site file (section 10), and that the JWKS publishes each key with its kid (0016).

atoom's `key/awskms` (atoom 0.3.0; 0.4.0 and 0.5.0 change nothing in it but its pins) holds one KMS key for each purpose its host declares: found by the alias `alias/<prefix>/<purpose>`, or by a key ID, ARN or alias the host names, read once and then used by its ARN. It signs digests in KMS (atoom record 0016: a digest of the wrong length is refused), returns the public key it read once, and gives a `key_id` of the key ARN, `#` and the SHA-256 of the public key. With `CreateKeys` it may make a missing key; without, a missing key is `not_found`. Where the record and the design are silent, the build chose.

## Decision

| Subject | Choice |
| --- | --- |
| The setting | `session serve --key PURPOSE=DRIVER`, repeatable, one for each purpose: `PURPOSE=software` (a key file in `--key-dir`), `PURPOSE=awskms` (the KMS key under the alias `alias/<--kms-alias-prefix>/PURPOSE`), or `PURPOSE=awskms:KEY` (a KMS key ID, key ARN or alias name that the deployment gives). A purpose that no `--key` names is on `software`, so a local run and the tests need nothing new. An unknown purpose or driver, a purpose named twice, and a key for `software` are refused at start |
| A driver for each purpose | Each purpose may be on its own driver, so the identity key can move to KMS while the client key stays in a file the issuer already knows, or the other way round. Each mounted driver is declared only the purposes it holds, and refuses the others |
| The alias prefix | `--kms-alias-prefix`, by default `session/<site>`: one AWS account and region can hold the keys of several sites, each under its own prefix (`alias/session/docs/client-assertion`) |
| Who makes the keys | The deployment, never session: the driver runs with `CreateKeys` off. A key is `ECC_NIST_P256` with the usage `SIGN_VERIFY` (the purposes are ES256), made by the deployment code that also holds its key policy. The role of session needs `kms:DescribeKey`, `kms:GetPublicKey` and `kms:Sign` on the two keys, and nothing to make, tag or delete keys |
| At start | `Ensure` of each purpose finds its key: a missing key, a key of another spec or usage, a disabled key and a KMS that does not answer fail the start, with the purpose's name. Nothing is made over a key |
| The KMS client | The AWS SDK's default configuration (the same as the store's: region and credentials from the environment or the cloud identity), made only when a purpose is on `awskms`, so an install without AWS needs no AWS configuration. `--kms-endpoint` names another endpoint, as `--dynamodb-endpoint` does |
| The kid | Unchanged: the key port's `key_id`, as for the software key (0016, atoom record 0016). On KMS it is `<key ARN>#<fingerprint>`. `/_session/jwks` still publishes the two keys, each with its kid |
| Cost on the request path | Unchanged: the identity header is reused for half its life (0016), so KMS signs about twice a minute for each session and audience on a replica, never on every check. A client assertion is one KMS `Sign` for each call to the issuer (PAR, the code, a refresh, an exchange), which the exchange cache already bounds. The public key is read once at start; the JWKS calls no KMS |
| A KMS failure | As any key driver failure: the identity header is a 503 (0016), and a client assertion that cannot be signed is an issuer outage, a 503. A header kept for reuse is still served, because it is only asked after the session read |
| Tests | No AWS is called. atoom's fake KMS is internal to its driver module, so session has a small double of the KMS API the driver calls (`internal/kmstest`, real P-256 keys, `Sign` counted): the driver selection and the start refusals, the identity header's reuse counted in KMS calls, and the whole sign-in, exchange and identity header against Keycloak with both keys on it. The real-AWS check is step 5 |

### Not in this step

- **Sealing** stays on the local sealer (`internal/localseal`). Moving it onto atoom's `seal` block, whose data keys are wrapped through the key port's `Ecdh` (on KMS a key-agreement key), is its own change.
- **The atoom pins** stay at 0.3.0: `key/awskms` is added at 0.3.0, the same driver as 0.5.0's.

### Rotating a key on KMS (decided)

The driver reads a key once and keeps its ARN, so a new key under the alias takes a restart, and the JWKS then publishes the new key only. An identity header signed by the old key in its last minute, held by an app that has not yet fetched the new JWKS (`max-age=300`), fails at that app; the issuer refetches its JWKS on an unknown kid. The software driver has the same shape today. Whether to publish the previous key for a while, and how many keys a purpose may have, is for the owner; nothing in this step depends on it.

Decided by the owner on the pull request: the restart-only rotation is accepted for now. Before the first site that rotates a signing key, the JWKS also publishes the previous key of a purpose for a while after a rotation (a second key per purpose and a way to name it); that build is its own change. The kid keeps the key ARN (the row below on a kid that session makes stays a road not taken): the account id and region in the public JWKS are accepted.

## Consequences

- A site on AWS keeps both signing keys in KMS: they never leave it, and a stolen disk or image holds no key.
- The deployment makes two KMS keys and an IAM policy of three actions for each site; session's Helm chart and the Lambda packaging will take `--key` and the cloud identity.
- The kid on KMS carries the key ARN: the public JWKS, every client assertion and every identity header show the AWS account id, the region and the key id. They are not secrets (the key policy guards the key, not its name); hiding them would change the kid rule (see the roads not taken).
- A rotation is a restart, and, until the open question above is settled, briefly breaks identity headers at apps with a cached JWKS.

## Roads not taken

| Road | Why not |
| --- | --- |
| One driver for every purpose (`--key-driver awskms`) | Both keys must move at once; the client key's JWKS at the issuer and the identity key's apps would change together |
| A flag for each purpose (`--client-key`, `--identity-key`) | A new flag for every new purpose; `--key PURPOSE=...` takes the purposes session declares |
| The key driver in the site file | The design keeps the drivers a start-up setting: the site file is the same in every environment, and the key a deployment's |
| session makes its keys (`CreateKeys`) | The role would need `kms:CreateKey`, `kms:CreateAlias`, `kms:TagResource` and `kms:ScheduleKeyDeletion`, and the key policy would be the driver's default, not the deployment's |
| A kid that session makes (a hash of the `key_id`, or the fingerprint alone) | Hides the ARN, but changes the kid rule of 0016 and atoom's record 0016 (the store names the key that signed); left to the owner if the ARN in the JWKS matters |
| atoom's fake KMS | Internal to the driver's module, so session cannot import it |
| A test against real AWS KMS here | session's tests never call AWS; the real-AWS check is step 5 |
| Moving the atoom pins to 0.5.0 | `key/awskms` 0.5.0 is the same driver as 0.3.0; the pins move with the policy loader, in its own pull request |
