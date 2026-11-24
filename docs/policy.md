# Route policy

Who may reach a route is decided by Cedar, as a library (`cedar-go`, in-process), on every check of a route that needs a session ([0007](decisions/0007-policy.md)). The code is `internal/policy`.

## What a decision reads

Only the session item the check has already read and the route of the site file. No extra read and no call out.

| Cedar | Value |
| --- | --- |
| principal | `User::"<subject>"`, with the attributes `issuer`, `email`, `name` and `groups` (a set of strings), and one parent `Group::"<name>"` for each group |
| action | `Action::"<METHOD>"`: `GET`, `POST`, and so on, as the proxy saw it. The schema declares the actions |
| resource | `Route::"<route name>"`, with the attributes `site` and `mode`. A route's name is its `name` in the site file, else its match (`/api/`) |
| context | `path` (without the query) and `method` |

A route that does not need a session (`public`) is never asked about. Without a policy bundle the route table decides alone. A denial is a 403 `{"error":"forbidden"}` and a security-audit event `denied` that carries the digest of the policy set. A request that does not fit the bundle's schema (a method it does not declare, say) is a denial too, audited with the reason `misfit`.

## The bundle

A bundle is atoom's signed policy bundle ([0021](decisions/0021-atoom-policy-loader-and-seal-block.md), atoom record 0019): a JWS in the general JSON serialisation, signed with ES384, with the protected header `{"alg":"ES384","kid":"<kid>","seq":<n>,"kind":"PolicyBundle"}`. Its payload is a JSON object of the schema (Cedar schema syntax) and the policies by id; `cedar-go` has no templates, so a bundle with templates or links is refused. `seq` grows with every bundle: a lower one, or the same one with another payload, is refused.

The schema of the entities above is `internal/policy.Schema`. The example payload, [examples/policy-bundle.json](../examples/policy-bundle.json), carries it:

```cedar
// Everyone with a session may reach every route but the admin pages.
permit (principal, action, resource) unless { resource == Route::"admin" };
// The admin pages are for the group admins.
permit (principal in Group::"admins", action, resource == Route::"admin");
```

The site file names the bundle and pins the one key that verifies it:

```yaml
policy:
  bundle: policy-bundle          # the document policy-bundle.jws next to site.jws
  verify_key:
    kid: publisher-1             # the kid of the bundle's signature
    public_key: |                # the publisher's P-384 public key, PEM
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
```

`session` does not sign bundles: the publisher's pipeline does, in atoom's format (the format of sluis's signed config). A new publisher key is a new site file and a restart.

## Loading

atoom's loader (`github.com/truvity/atoom/policy`) keeps the set, by the loading rules of 0007:

- the signature is verified under the pinned key before the payload is read, and the payload is validated against its schema in strict mode;
- the set is compiled once and swapped in atomically; a reload that fails keeps the last good set; a cold start without a valid set refuses to run;
- the loader watches `policy-bundle.jws` and reads it again on a change, at least a second apart; each reload's outcome is a line in the operational log;
- a decision does no I/O and carries the digest of its set: the SHA-384 of the payload, in lower-case hex, the `policy_digest` of the audit event.
