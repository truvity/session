# 0013. Reuse of the group SSO reference stand

Status: accepted
Date: 2026-11-20

## Context

The group has a reference stand of its SSO design: Apache with `mod_auth_openidc` and a Go audience broker. It proves the design against a real issuer, with browser scenarios. It is not the implementation of `session` ([0002](0002-own-go-service-and-external-authorisation.md)).

## Decision

`session` stays our own Go service. Its code may be reused where it fits:

- the broker's rules: the forgery check, the route allowlist, the exchange per audience and its cache keys, and step-up;
- the stand's browser library;
- the stand's conformance suites and browser scenarios.

The stand's Keycloak findings go into the conformance suite:

- redirect to sign-in only on a navigation;
- `passMaxAge` for step-up through a broker;
- the client assertion's audience is the token endpoint;
- `id_token_hint` at logout;
- the reuse of a client assertion at logout.

## Consequences

- Less to write for the exchange rules and the browser helper.
- Reused code is checked against `session`'s own contract ([0004](0004-browser-session-contract.md)), not copied on trust.
- The conformance suite starts with scenarios that have already met a real issuer.

## Roads not taken

| Road | Why not |
| --- | --- |
| The Apache shape packaged for atoom | No authorizer, and a C fork for the store and KMS |
| Both shapes behind one contract | Two implementations to keep in agreement |
