# 0009. The session core is a block, built inside session first

Status: accepted
Date: 2026-11-20

## Context

atoom has a layer of blocks above its ports. A block is a contract built from other ports and blocks. Its dependencies are declared and passed in, it has no backend code and no cycles, and its host supplies the rules. There is one implementation per block, in the language of its main host. A block moves into atoom at its second consumer.

The browser-session logic is independent of any proxy and could serve sluis's own sign-in sessions too.

## Decision

The core of `session` is a block: the session records, the sealed cookie, idle and absolute expiry, logout pointers and the exchange cache.

- It is built inside `truvity/session` (`core/`, [0003](0003-repository-contents.md)).
- Its dependencies are atoom's `store` port and the `seal` block, passed in by `session`.
- `session` supplies the rules. The lifetimes, the cookie rules and the paths stay session's.
- It moves into atoom when sluis's sign-in actor, its second consumer, adopts it. It moves with its contract and its kit.

## Consequences

- The check core has a clear boundary and can be tested over atoom's memory drivers.
- The move to atoom later is a change of repository, not of design.
- Until then, the core is `session`'s code, and its contract can still change.

## Roads not taken

| Road | Why not |
| --- | --- |
| Put the core into atoom now | A block moves into atoom at its second consumer; guessing the shape before it is wasted work |
| No block, the logic inside the check service | The second consumer would have to copy it |
