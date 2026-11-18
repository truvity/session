# 0013. Logout without a secondary index: pointer items and one tombstone read at creation

Status: proposed, coordinator's call 2026-11-18, for review by the maintainers. Settles design question Q11.

## Context

Back-channel logout used a secondary index on `sid` and subject (design, first draft). Secondary indexes are eventually consistent, so a logout token that arrives just after sign-in could miss the new session. The spike (docs/spike-2026-11-18.md, section 5.1) tested two ways to close the gap on DynamoDB Local. DynamoDB Local's indexes are synchronous, so the lag was reproduced by ordering, not observed. Latencies are from DynamoDB Local only; the real service was not measured.

## Options considered

| Option | Meaning | Cost, from the spike |
| --- | --- | --- |
| A | Accept the gap. The missed session ends by idle or maximum time | No extra cost. A stolen or unwanted session can live up to 8 hours after a logout |
| B | Write a tombstone for each `sid` and subject. The check reads the tombstones with the session and refuses a session not newer than a tombstone | Correct in the test. 3 read units for each check instead of 1 (the tombstone keys come from the session record, so two round trips: 0.46 ms against 0.24 ms on DynamoDB Local). The tombstone must live as long as the maximum session lifetime, because a missed session can be checked hours later |
| C | Pointer items per `sid` and per subject, written in the session-creation transaction. The logout reads a pointer with a strongly consistent GetItem. The callback reads the tombstones once at creation | 1 read unit and one round trip for each check. Creation costs about 4 times the write units of a plain put (8 against 2 for a 2 kB session; 1.3 ms against 0.3 ms on DynamoDB Local). Logout is one GetItem plus the deletes. Rare paths pay |

## Decision

C.

- Each session creation writes, in one transaction, the session item and a pointer item for its `sid` and one for its subject. Each pointer holds a set of session keys.
- A back-channel logout writes a tombstone (by `sid`, or by subject when the token has no `sid`), reads the pointer with a strongly consistent GetItem, deletes the sessions it lists and the pointer.
- The callback, after it stored the session, reads the tombstones once. If one is newer than the start of the sign-in, it ends the session it just made. The check on each request reads only the session item.
- `created` and `logout_at` are in milliseconds, so a sign-in in the same second after a logout is not refused.
- There is no secondary index on the session table.

## Consequences

- The per-request path stays at one strongly consistent read.
- The pointer set grows with the number of sessions of one subject (400 KB item limit). A sort-key form (`pk` = pointer, `sk` = session key, read with a strongly consistent Query) is the answer if that matters. It was not built.
- Pointer items carry a TTL for the maximum lifetime. A stale member costs one failed delete.
- The reserved word `keys` cannot be an attribute name in an update expression. The spike used `members`.
- Roads not taken: B and A, with the numbers above.
