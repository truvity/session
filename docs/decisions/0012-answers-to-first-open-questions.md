# 0012. Answers to the open questions of the first draft

Status: accepted, 2026-11-18. Q1, Q6 and Q8 amended after the first spike, coordinator's call 2026-11-18, for review: see 0015 and 0016. Q3 and Q4 amended by [0017](0017-atoom-ports-and-blocks.md) on 2026-11-20: the keys go through atoom's key port and the `keyring` block.

## Context

The first draft ended with nine open questions. The maintainers answered them, and the choice of DynamoDB (0010) and the ports (0009) settled three more.

## Decision

| Question | Decision | Roads not taken |
| --- | --- | --- |
| Q1. Sign-in and callback on API Gateway | C: both, for each install. An HTTP integration to the service, or the same binary as a second Lambda handler. The default is the Lambda handler where there is no cluster | Only an HTTP integration (needs a reachable service). Only a Lambda handler (no choice for installs that have a cluster) |
| Q2. Local session cache | A: none at first. The spike measures DynamoDB latency and cost | A cache cleared by pub/sub (needs a bus, which we dropped with Valkey). A cache without invalidation (logout lags) |
| Q3. Where the `private_key_jwt` key lives | Through the key port, with a key file and AWS KMS implementations (0009) | Only a file (key can leave the host). Only KMS (no simple start, no Keycloak test without AWS) |
| Q4. Signing the identity header | A: the service's own key through the key port, public keys at `/_session/jwks`, lifetime about a minute | An exchanged token (that is the `exchange` mode). A shared HMAC (every app becomes a signer) |
| Q5. Sites and hosts | A: one site per host. The `__Host-` cookie needs `Path=/` | Path-based sites with a `__Secure-` cookie |
| Q6. Authorizer caching on API Gateway | A: off by default. A site may opt in later, with the logout lag documented | A cache of minutes (logout lag too long) |
| Q7. Keeping the subject token fresh | A: store the refresh token, refresh under a lock, end the session if refresh fails | No refresh (sessions as short as one access token). Asking the issuer to accept the ID token as subject token (depends on the issuer) |
| Q8. Envoy adapters | B: HTTP and gRPC from the start | HTTP first and gRPC later |
| Q9. Refused exchange | A: JSON 403 for API routes, a plain error page for page routes, with a template for each site | Always JSON |

## Consequences

- The open-questions list of the design now holds only the two questions that came from dropping Valkey.
- The spike gains items: DynamoDB latency and cost, the Lambda sign-in handler, and gRPC next to HTTP.
- Refresh under a lock uses the same conditional-write lock as the exchange.

## Amendments after the first spike (coordinator's call 2026-11-18, for review)

- Q6: "off by default" holds only if the authorizer's TTL is set to 0 explicitly. The REST API default is 300 seconds (0015).
- Q8: gRPC mode is preferred. HTTP mode stays, documented with its limits (0016).
- Q1: both API Gateway handlers stay. The docs default to the HTTP API (0015).
- Q2: the DynamoDB latency was measured on DynamoDB Local only. Real latency from the target region is still open (design, "Open for the maintainers").
