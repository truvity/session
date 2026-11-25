# 0010. Logout without a secondary index: pointer items and one tombstone read at creation

Status: accepted; partly superseded by [0031](0031-logout-across-hosts.md) (a session is found by atoom's index entries, not by pointer items; the tombstones stay)
Date: 2026-11-21

## Context

Back-channel logout needs to find a person's sessions from the logout token's `sid` or subject. A secondary index on `sid` and subject is eventually consistent, so a logout token that arrives just after sign-in could miss the new session.

The first spike tested ways to close the gap on DynamoDB Local. Its indexes are synchronous, so the lag was reproduced by ordering, not observed. The latencies below are from DynamoDB Local only; the real service was not measured.

## Decision

- Each session creation writes, in one transaction, the session item and a **pointer item** for its `sid` and one for its subject. Each pointer holds a set of session keys.
- A back-channel logout writes a **tombstone** (by `sid`, or by subject when the token has no `sid`), reads the pointer with a strongly consistent get, deletes the sessions it lists, their exchanged tokens and the pointer.
- The callback, after it stored the session, reads the tombstones once. If one is newer than the start of the sign-in, it ends the session it just made. This closes the race of a logout that arrives before the sign-in has finished. The check on each request reads only the session item.
- `created` and `logout_at` are in milliseconds, so a sign-in in the same second after a logout is not refused.
- There is no secondary index on the session table.
- Tombstones and pointers carry a TTL for the maximum session lifetime. A stale pointer member costs one failed delete.

The store port's operations cover this: the items of a session, the pointer items and the tombstones go through `Transact` with the entries written in the item's transaction ([0006](0006-built-on-atoom.md)).

## Consequences

- The per-request path stays at one strongly consistent read, one read unit for an item under 4 KB.
- Creation costs about 4 times the write units of a plain put (8 against 2 for a 2 kB session; 1.3 ms against 0.3 ms on DynamoDB Local). Logout is one get plus the deletes. The rare paths pay.
- The pointer set grows with the number of sessions of one subject, within an item size limit (400 KB on DynamoDB). A sort-key form (partition key the pointer, sort key the session key, read with a strongly consistent query) answers that if it ever matters. It is not built.
- The reserved word `keys` cannot be an attribute name in a DynamoDB update expression. The spike used `members`.
- Replicas keep no session state, so the next check on any replica sees a deletion at once.

## Roads not taken

| Road | Cost | Why not |
| --- | --- | --- |
| Accept the gap | No extra cost | A stolen or unwanted session lives up to 8 hours after a logout |
| A tombstone read on each check | 3 read units instead of 1, and two round trips (0.46 ms against 0.24 ms) | Every request pays for a rare event. The tombstone would also have to live as long as the maximum session lifetime, because a missed session can be checked hours later |
| A secondary index on `sid` and subject | Eventually consistent | The gap this record closes |
