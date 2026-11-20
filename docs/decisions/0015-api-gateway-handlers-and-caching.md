# 0015. API Gateway: both handlers, HTTP API by default, caching set to zero

Status: proposed, coordinator's call 2026-11-18, for review by the maintainers. Amends 0012 Q1 and Q6 and S4 and S8 of 0005. Evidence: docs/spike-2026-11-18.md, section 4. The API Gateway facts come from the AWS documentation, not from a real account; the unverified ones are listed in the design under "Open for the maintainers". Amended by [0017](0017-atoom-ports-and-blocks.md) on 2026-11-20: every function runs behind the Lambda Web Adapter; the authorizer case is tested in the fit spike.

## Context

The spike ran the Lambda handlers on sample events only. The AWS documentation shows that the two API Gateway products differ, and that the authorizer cannot change the request or the response.

## Decision

- Both handlers stay: the REST API `REQUEST` authorizer and the HTTP API payload 2.0 authorizer with simple responses. The docs and examples default to the HTTP API.
- The authorizer's result cache is configured explicitly to 0 seconds on both products. The REST API default is 300 seconds when `authorizerResultTtlInSeconds` is not set, so "off by default" (0012 Q6 A) is true only with the explicit setting. The examples and the chart set it, and the examples carry a test for it. A site may opt in later with the logout lag documented (the cache key is the identity sources, such as the `Cookie` header).
- "No session" is answered with the error `Unauthorized`, which API Gateway turns into a 401. A deny policy is a 403 on the REST API and is not used for "no session".
- Stripping browser headers (S8) is done by the integration's parameter mapping, not by the allow answer: only `principalId` and `context` reach the integration.
- The HTTP API reserves `Authorization` and some other headers in parameter mapping. The per-API token (0006) therefore travels in a non-reserved header, `X-Session-Token`, and the site ignores a browser-sent `Authorization`.
- The sign-in paths go to the service over an HTTP integration, or to the same binary as a second Lambda handler (0012 Q1 stays). That handler wraps the same router for an HTTP API proxy integration and returns `Set-Cookie` lines in the response `cookies` array.

## Consequences

- One behaviour for S4 on both products: a 401 the browser helper can act on.
- The HTTP API event carries the cookies in a separate array. The handler joins them before the check.
- A cookie-based identity source makes API Gateway skip the function when no cookie is present (401), and puts the whole `Cookie` header in the cache key if caching is ever turned on.
- To be checked in a real AWS account: the HTTP API status for `isAuthorized: false`, the HTTP API cache default, and parameter mapping from `$context.authorizer.*`.
