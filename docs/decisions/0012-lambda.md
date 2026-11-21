# 0012. Lambda: every function behind the Web Adapter

Status: accepted
Date: 2026-11-20

## Context

On API Gateway installs, `session` runs as Lambda functions: the sign-in handler, and the authorizer. Atoom distributes each driver also as a Lambda extension zip, and one function may take at most five layers.

## Decision

- **Every Lambda function of `session` runs behind the Lambda Web Adapter**, vendored and pinned in `session`'s own layer. The binary is the same HTTP server on every shape.
- **A function is the app zip, the adapter's layer and one configuration layer** (the site file and the policy bundle). Drivers are in-process, so there is no drivers layer. A merged drivers layer is added only where a driver's language differs from the function's. Atoom's install tooling merges the extensions one function needs into one layer.
- **The sign-in paths** run as the same function behind an HTTP API proxy integration, and return `Set-Cookie` lines in the response `cookies` array ([0011](0011-host-adapter-rules.md)).
- **The authorizer is the open case.** The adapter does not list API Gateway authorizer events among the events it supports. The fit spike tests whether authorizer events arrive correctly. Open: if they do not, the authorizer alone keeps a native Go handler, in the same binary. Everything else stays behind the adapter.

## Consequences

- One HTTP server and one set of tests on every shape.
- A function stays well within Lambda's limit of five layers.
- The fit spike runs the check core on atoom 0.2.0 drivers, tests authorizer events through the adapter, and makes the short check in a real AWS account that the first spike could not make ([0011](0011-host-adapter-rules.md)).
- The authorizer may be the one function with a native handler.

## Roads not taken

| Road | Why not |
| --- | --- |
| A native handler for the authorizer from the start | It is an exception to one rule on every function, and the adapter may handle it. The spike decides |
| A second Lambda handler for the sign-in paths | A second entry point to keep in step with the HTTP server |
| A drivers layer for Go drivers | A Go driver used by a Go function is linked in-process |
| A layer for each driver | Five layers at most for a function; atoom merges extensions into one layer |
