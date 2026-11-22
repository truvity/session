# Recipes for session: what CI and people run. Run them inside the devbox shell (`devbox shell`, or `devbox run -- just <recipe>`).
# The test containers are pinned by digest here and nowhere else; each recipe that starts one removes it at the end.

set shell := ["bash", "-euo", "pipefail", "-c"]

dynamodb_image := "amazon/dynamodb-local@sha256:6ada631ec7aa5fc83446855eb17233e3dad184fec47477e8140c6c569cfe0c86"

default:
    @just --list

# Everything CI runs.
check: lint build test test-dynamodb vuln

# Build every package. CGO is off: the binary is static.
build:
    CGO_ENABLED=0 go build ./...

# The unit tests: no container, no network. The store is the in-process test double. Verbose, so that a skip shows its reason.
test:
    go test -race -count=1 -v ./... 2>&1 \
      | awk '!/^=== (RUN|PAUSE|CONT|NAME)/ && !/^[[:space:]]*--- PASS/ && !/^PASS$/' ; test "${PIPESTATUS[0]}" -eq 0

# The core's store tests again on atoom's store/dynamodb driver, against DynamoDB Local in a container that is removed at the end.
test-dynamodb:
    #!/usr/bin/env bash
    set -euo pipefail
    name="session-test-ddb-$$"
    port=$((20000 + RANDOM % 20000))
    docker run -d --rm --name "$name" -p "127.0.0.1:$port:8000" {{ dynamodb_image }} -jar DynamoDBLocal.jar -inMemory -sharedDb >/dev/null
    trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
    for _ in $(seq 1 60); do
        curl -s -o /dev/null "http://127.0.0.1:$port" && break
        sleep 0.5
    done
    SESSION_TEST_DYNAMODB="http://127.0.0.1:$port" go test -count=1 -v ./core/... 2>&1 \
      | awk '!/^=== (RUN|PAUSE|CONT|NAME)/ && !/^[[:space:]]*--- PASS/ && !/^PASS$/ && !/WARN refused method=Transact code=aborted/' ; test "${PIPESTATUS[0]}" -eq 0

# Format check, vet and lint of the Go code, and the workflows.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    unformatted=$(find . -name '*.go' -not -path './spike/*' -not -path './.devbox/*' -print0 | xargs -0 gofmt -l)
    if [ -n "$unformatted" ]; then echo "not gofmt'ed:"; echo "$unformatted"; exit 1; fi
    go vet ./...
    golangci-lint run ./...
    actionlint

# Known vulnerabilities in the dependencies.
vuln:
    govulncheck ./...
