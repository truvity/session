# 0028. The image of session, and what else a deployed first site needs from this repository

Status: accepted, 2026-11-25 (owner decision on the pull request)
Date: 2026-11-25

Answers the first Open line of [0025](0025-first-version-for-the-first-sites.md), how the binary and the image are built and published, and lists what else step 4 needs from this repository before its done-line can be checked against a deployed site.

## Context

CI judges pull requests and `master` and never publishes. A deployment of a first site ([0025](0025-first-version-for-the-first-sites.md)) needs an image it can pin by digest before the first release exists, and the release `v0.1.0` needs an image of its own, built with the version `0.1.0` (the audit writer takes nothing but a semantic version, [0023](0023-audit-emitter.md)).

## Decision

| Subject | Choice |
| --- | --- |
| The registry | `ghcr.io/truvity/session`, public: a deployment pulls it with no credential, through a pull-through cache if it has one |
| On a push to `master` | The tag `master-<the first 12 characters of the commit>`, built with the version `0.0.0-master.<the same 12 characters>`. For development deployments, pinned by digest; never a release |
| On a tag `vX.Y.Z` | The tag `X.Y.Z`, built with the version `X.Y.Z`. The workflow makes no tag: the owner approves each (0025) |
| No floating tag | No `latest`, no `master`. A tag that is already in the registry is never moved: the push fails |
| The build | `just build-image ARCH VERSION`: Go with CGO off, `-trimpath`, the version set with `-X main.version`, for `linux/amd64` and `linux/arm64` |
| Two jobs | `build` holds no token and compiles; `publish` holds `packages: write`, builds nothing and copies the executables into a distroless image (`deploy/image/Dockerfile`, no `RUN`), as the rest of the group's public images do |
| The image | `gcr.io/distroless/static-debian12:nonroot` by digest, user 65532, entrypoint `/usr/bin/session`, the OCI labels title, description, source, licence, revision and version |

### Not in this record (planned, step 4)

- **The conformance scenarios against a deployed site.** The suite of [0020](0020-conformance-suite.md) builds its own stand: an in-process store, a clock it can move, the records of a JSON-lines driver it reads, and a realm it makes through the admin API with a password sign-in. A deployed site has none of these. A runner that points the same scenarios at a site's origin is its own change: which scenarios run without a movable clock (or against a site file with short lifetimes), how the browser signs in at an issuer whose sign-in is brokered, and how the records are checked when they go to a spool.
- **The site's test backend.** The scenarios read what the site received (the method, the path and the headers, as JSON). A deployed first site needs a backend that answers the same way; whether it is a subcommand of this image or an image of its own is decided with the runner.
- **A Helm chart** (`charts/session`, [0003](0003-repository-contents.md)) is not built for the first sites: the first deployment writes its own manifests. A chart follows when a second deployment needs the same objects.

## Consequences

- A deployment pins `ghcr.io/truvity/session:master-<commit>@sha256:...` until `v0.1.0`, then `0.1.0@sha256:...`.
- The organisation must let a workflow publish a public package; the first push makes the package, and its visibility is set once.
- `session version` of a development image prints `0.0.0-master.<commit>`, and its audit records name that version.

## Roads not taken

| Road | Why not |
| --- | --- |
| A floating `latest` or `master` tag | A deployment pins by digest; a tag that moves hides what runs |
| Build the image from source in the job that holds the token | The credential would sit beside the build of every dependency |
| Images only on a release tag | The first site must run before `v0.1.0` can be tagged: its done-line is what the tag waits for |
| A Go release tool (goreleaser) | Two architectures and one image need nothing it adds |
