# 0010. Sessions live in DynamoDB on every shape; Valkey is dropped

Status: accepted, 2026-11-18

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
- Locks, expiry and the logout lookup use conditional writes, a TTL attribute and a secondary index.
- No local session cache at first. The spike measures DynamoDB latency and cost (0012).
- Installs without AWS are an open question in the design.
- The store port (0009) keeps another store possible later.
