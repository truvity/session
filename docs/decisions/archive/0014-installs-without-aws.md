# 0014. Installs without AWS: a DynamoDB table they can reach

> Archived. Kept as history; the current decision is [0006](../0006-built-on-atoom.md). The numbers in this file are those before the clean rewrite of the records (see the [renumbering table](../README.md#renumbering-in-the-clean-rewrite)).

Status: proposed, coordinator's call 2026-11-18, for review by the maintainers. Settles design question Q10. Superseded by [0006 (renumbered)](../0006-built-on-atoom.md) on 2026-11-20: any atoom store driver that passes the store kit.

## Context

Sessions live in DynamoDB on every shape (0010). A self-hosted nginx install may have no AWS account to hold a table.

## Options considered

| Option | Meaning |
| --- | --- |
| A | Every install uses a DynamoDB table it can reach. No second store |
| B | A store implementation for a DynamoDB-compatible local service |
| C | Another store, for example a relational database, behind the store port |

## Decision

A. Another store only when a real site needs it. The store port (0009) keeps B and C possible. No second store is written before then.

## Consequences

- One backend to build, test and secure.
- Installs without any AWS account cannot use `session` until a real site asks for B or C.
- The spike ran against DynamoDB Local, which is also what tests and local development use.
