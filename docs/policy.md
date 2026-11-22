# Route policy

Who may reach a route is decided by Cedar, as a library (`cedar-go`, in-process), on every check of a route that needs a session ([0007](decisions/0007-policy.md)). The code is `internal/policy`.

## What a decision reads

Only the session item the check has already read and the route of the site file. No extra read and no call out.

| Cedar | Value |
| --- | --- |
| principal | `User::"<subject>"`, with the attributes `issuer`, `email`, `name` and `groups` (a set of strings), and one parent `Group::"<name>"` for each group |
| action | `Action::"<METHOD>"`: `GET`, `POST`, and so on, as the proxy saw it |
| resource | `Route::"<route name>"`, with the attributes `site` and `mode`. A route's name is its `name` in the site file, else its match (`/api/`) |
| context | `path` (without the query) and `method` |

A route that does not need a session (`public`) is never asked about. Without a policy bundle the route table decides alone. A denial is a 403 `{"error":"forbidden"}` and a security-audit event that carries the digest of the policy set.

Example:

```cedar
// Everyone with a session may reach every route but the admin pages.
permit (principal, action, resource) unless { resource == Route::"admin" };
// The admin pages are for the group admins.
permit (principal in Group::"admins", action, resource == Route::"admin");
```

## Loading, until atoom's loader exists

atoom's signed bundle, its loading rules, the Go loader (B5) and the decision test set are planned ([0006](decisions/0006-built-on-atoom.md)). Until they exist:

- The bundle is a Cedar policy document read through the `source` port by the name the site file gives (`policy.bundle`). The Go `source/file` driver serves the name `policy-bundle` from the file `policy-bundle.jws`; the file holds plain Cedar text.
- What is kept from the loading rules: compile once and swap atomically; keep the last good set when a reload fails; refuse a cold start without a valid set; no I/O during a decision; the digest of the set (SHA-256 of its text) on every decision.
- What waits for the loader: the signature check before parsing, and strict validation against a schema (`cedar-go` has schema validation only in its experimental package).

The loader sits behind the `policy.Loader` interface, so atoom's replaces it without a change in the check.
