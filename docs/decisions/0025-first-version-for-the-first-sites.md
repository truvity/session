# 0025. The first version for the first sites: step 4, and what step 5 waits for

Status: accepted, 2026-11-25 (owner decision)
Date: 2026-11-25

Defines step 4 of the plan (design section 16), which was one line, "First version for the first sites". It keeps every rule of the records before it, and it clarifies when the rotation decided in [0019](0019-signing-keys-on-aws-kms.md) is built. It also writes down what step 5, Lambda, waits for in atoom.

## Context

Step 3 built the parts a site needs on a cluster: the check core, the sign-in handler, the Envoy and nginx adapters, the exchange client and the identity header ([0016](0016-exchange-client-and-identity-header.md)), the signing keys on AWS KMS ([0019](0019-signing-keys-on-aws-kms.md)), the conformance suite ([0020](0020-conformance-suite.md)), atoom's policy loader, seal block and token block ([0021](0021-atoom-policy-loader-and-seal-block.md), [0022](0022-atoom-token-block.md)) and the emitter of `truvity/audit` ([0023](0023-audit-emitter.md)). Everything runs in CI against a test Keycloak, and nothing is deployed. The plan named the first version, but not which issuer, which sites, which host, which key and audit settings, when it is done, or what the version is.

session has no release yet. CI judges pull requests and `master` and never publishes. The changelog collects every change under "Unreleased". The version is a semantic version, because the audit writer takes nothing else, and the default build's is `0.0.0-dev` ([0023](0023-audit-emitter.md)). The modules session builds on are tagged `v0.<minor>.0` (atoom `v0.6.0`, `truvity/audit` `v0.19.0`).

## Decision

### The first version (step 4)

| Subject | Choice |
| --- | --- |
| The issuer | Keycloak. Sites whose issuer is sluis v1 wait for sluis v2, which is step 6 ([0005](0005-tokens-per-api-and-issuers.md), design section 12) |
| The first sites | Staff-facing sites on a development environment, behind Envoy (external authorisation, gRPC preferred, [0011](0011-host-adapter-rules.md), [0015](0015-envoy-http-mode-csrf-header-and-step-2-choices.md)). nginx and API Gateway sites come later; API Gateway is step 5 |
| The signing keys | On AWS KMS, both purposes: `--key client-assertion=awskms` and `--key identity-header=awskms`, made by the deployment with their key policy, never by session ([0019](0019-signing-keys-on-aws-kms.md)) |
| Audit | `--audit-socket` to the emit socket of the spool sidecar (atoom's `transport-spool`) in the same pod on the cluster, whose consumer is the environment's audit writer ([0023](0023-audit-emitter.md)) |
| Key rotation | None at the first sites (see below) |
| Done when | The conformance scenarios ([0020](0020-conformance-suite.md)) pass against the deployed site: through its Envoy, against its Keycloak, with its keys on KMS and its records through the spool sidecar |
| The version | The first release of session is `v0.1.0`: an annotated tag on a commit of `master`, as the modules session builds on are tagged. The binary of that commit is built with the version `0.1.0` (`session version` prints it and the audit records name it), and the changelog's "Unreleased" becomes "0.1.0". Before 1.0, a breaking change raises the minor version. The tag needs the owner's approval; nothing in this record makes it |

### No key rotation at the first sites

The first version ships without key rotation at the first sites: a signing key that a first site uses is not rotated while it serves.

[0019](0019-signing-keys-on-aws-kms.md) stands. Its rotation is still a restart, and its decision still holds: before the first site that rotates a signing key, the JWKS also publishes the previous key of a purpose for a while after a rotation. This record only says when that is built. It comes with atoom's B8b, the rotation ring of the `token` block ([0022](0022-atoom-token-block.md) names it as a later step), and before the first site that rotates a signing key, not before the first version.

### What step 5 (Lambda) waits for

Step 5 depends on atoom's B9, which brings:

- **A Go `transport/sqs` driver, mounted in session's process for audit.** On Lambda there is no spool sidecar: the emitter of `truvity/audit` sends through `transport/sqs` in-process, over the same `transport` port. [0023](0023-audit-emitter.md) already names `transport/sqs` as the Lambda shape's driver.
- **A Go `source/ssm` or `source/appconfig` driver** for the site file and the policy bundle, read through the `source` port as on every other shape (the documents `site` and `policy-bundle`).

Which of the two source drivers, and what that leaves of the configuration layer of [0012](0012-lambda.md), is decided at step 5.

## Consequences

- Step 4 has one issuer, one host and one kind of site, so its run of the conformance scenarios is the whole test of the deployment.
- The first sites need no change of session's code beyond what step 3 built; the work of step 4 is the deployment, the KMS keys, the spool sidecar and the release.
- A first site that has to rotate a signing key waits for B8b; a compromised key is replaced by a restart under 0019, with the short break at apps that it describes.
- Step 5 cannot start before atoom's B9. Audit on Lambda has no sidecar and no socket.

## Roads not taken

| Road | Why not |
| --- | --- |
| Sites on sluis v1 first | v1 cannot exchange a confidential `private_key_jwt` client's token and has no PAR ([0005](0005-tokens-per-api-and-issuers.md)); a public-client workaround is rejected |
| Customer-facing sites first | A development environment and staff are the smallest blast radius for a first deployment |
| Software keys at the first sites | The keys must not leave; KMS is built ([0019](0019-signing-keys-on-aws-kms.md)) |
| The previous-key build before the first version | No first site rotates a key; it would be built before atoom's rotation ring, which would then replace it |
| A spool sidecar on Lambda | A function has no sidecar; a driver in the process is atoom's shape for Lambda ([0006](0006-built-on-atoom.md)) |
| Version `v1.0.0` for the first release | session's contracts and its atoom pins still change by minor versions; 1.0 waits until they settle |

## Open

- How the release's binary and image are built and published: CI judges and never publishes today.
- The seal block's wrapping key at the first sites (`--key wrapping=awskms` or a key file, [0021](0021-atoom-policy-loader-and-seal-block.md)): not decided here.
