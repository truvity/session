// Package conformance holds the conformance suite (design section 14): one set of browser scenarios, run in a real headless
// browser against the test Keycloak through every host the examples ship (Envoy over gRPC, Envoy over HTTP, nginx), with the
// example configurations run as they are. Where hosts differ by design (decisions 0011, 0015 and 0018), the suite asserts each
// host's documented answer. The suite is in the package's tests; `just test-conformance` runs it. This file only names the package.
package conformance
