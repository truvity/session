# 0010. Sessions live in DynamoDB on every shape; Valkey is dropped

> Archived. Kept as history; the current decision is [0006](../0006-built-on-atoom.md). The numbers in this file are those before the clean rewrite of the records (see the [renumbering table](../README.md#renumbering-in-the-clean-rewrite)).

Status: accepted, 2026-11-18. Amended by [0006 (renumbered)](../0006-built-on-atoom.md) on 2026-11-20: any atoom store that passes the kit, DynamoDB first; Valkey is no longer dropped.

## Context

The first draft kept sessions in Valkey, with DynamoDB only for API Gateway installs. That means two stores to build, test and run. The Helm chart had to carry a Valkey connection with high availability, authentication and TLS.

## Options considered

| Option | For | Against |
| --- | --- | --- |
| A. Valkey for clusters, DynamoDB for API Gateway | Fast reads on clusters | Two backends. A store to run and secure |
| B. DynamoDB on every shape | One backend. Nothing to run. The same behaviour everywhere | A network read for each check. Needs an AWS table for each install |
| C. Valkey on every shape | One backend | Lambda installs would need a network to the store. A store to run |

## Decision

B. Sessions live in DynamoDB on every shape. Valkey is dropped from the design.

## Consequences

- S2 changes: sessions are encrypted, in DynamoDB. Idle and maximum lifetimes for each site stay.
- The Helm chart takes a table name and a cloud identity. It does not run a store.
- Locks and expiry use conditional writes and a TTL attribute. The logout lookup uses pointer items, not a secondary index (0013, coordinator's call 2026-11-18, for review).
- No local session cache at first. The spike measures DynamoDB latency and cost (0012).
- Installs without AWS: every install uses a DynamoDB table it can reach (0014, coordinator's call 2026-11-18, for review).
- The store port (0009) keeps another store possible later.
