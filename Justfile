# Recipes for session: what CI and people run. Run them inside the devbox shell (`devbox shell`, or `devbox run -- just <recipe>`).
# The test containers are pinned by digest here and nowhere else; each recipe that starts one removes it at the end.

set shell := ["bash", "-euo", "pipefail", "-c"]

keycloak_image := "quay.io/keycloak/keycloak:26.8.1@sha256:3f3c5f8e03c614774b4bd9173b88391fefa4153bfc010d8012d59ad825377332"
envoy_image := "envoyproxy/envoy:v1.39.6@sha256:1fde8efee875e4e4f6a39a90fe49d9338e1caacce5762034ef9fb4bbb9ad6aed"
dynamodb_image := "amazon/dynamodb-local@sha256:6ada631ec7aa5fc83446855eb17233e3dad184fec47477e8140c6c569cfe0c86"

default:
    @just --list

# Everything CI runs.
check: lint build test test-dynamodb test-keycloak test-envoy vuln

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

# The sign-in handler against a test Keycloak in a container (host network, a free port, a random admin password), removed at the
# end. The tests make their own realms through the admin API.
test-keycloak:
    #!/usr/bin/env bash
    set -euo pipefail
    name="session-test-kc-$$"
    port=$((20000 + RANDOM % 20000))
    mport=$((port + 1))
    password=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
    docker run -d --rm --name "$name" --network host \
      -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$password" \
      {{ keycloak_image }} start-dev --http-host=127.0.0.1 --http-port="$port" --http-management-port="$mport" >/dev/null
    trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
    up=""
    for _ in $(seq 1 180); do
        if curl -sf -o /dev/null "http://127.0.0.1:$port/realms/master/.well-known/openid-configuration"; then up=1; break; fi
        sleep 1
    done
    if [ -z "$up" ]; then docker logs "$name" 2>&1 | tail -40; exit 1; fi
    SESSION_TEST_KEYCLOAK="http://127.0.0.1:$port" SESSION_TEST_KEYCLOAK_ADMIN_PASSWORD="$password" \
      go test -count=1 -v ./internal/signin/... 2>&1 \
      | awk '!/^=== (RUN|PAUSE|CONT|NAME)/ && !/^[[:space:]]*--- PASS/ && !/^PASS$/' ; test "${PIPESTATUS[0]}" -eq 0

# The Envoy adapters through a real Envoy (examples/envoy/envoy.yaml, both modes) in a container on the host network. The test
# starts the container on free ports and removes it at the end.
test-envoy:
    docker pull -q {{ envoy_image }} >/dev/null
    SESSION_TEST_ENVOY_IMAGE="{{ envoy_image }}" go test -count=1 -v ./internal/envoy/... 2>&1 \
      | awk '!/^=== (RUN|PAUSE|CONT|NAME)/ && !/^[[:space:]]*--- PASS/ && !/^PASS$/' ; test "${PIPESTATUS[0]}" -eq 0

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
