# 0014. Installs without AWS: a DynamoDB table they can reach

Status: proposed, coordinator's call 2026-11-18, for review by the maintainers. Settles design question Q10.

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
