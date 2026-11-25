# Recipes for session: what CI and people run. Run them inside the devbox shell (`devbox shell`, or `devbox run -- just <recipe>`).
# The test containers are pinned by digest here and nowhere else; each recipe that starts one removes it at the end.

set shell := ["bash", "-euo", "pipefail", "-c"]

keycloak_image := "quay.io/keycloak/keycloak:26.8.1@sha256:3f3c5f8e03c614774b4bd9173b88391fefa4153bfc010d8012d59ad825377332"
envoy_image := "envoyproxy/envoy:v1.39.6@sha256:1fde8efee875e4e4f6a39a90fe49d9338e1caacce5762034ef9fb4bbb9ad6aed"
nginx_image := "nginx:1.30.8-alpine-slim@sha256:e9eaa7298465eab06d618c51556fdcf3fb5061f9ff40bd28ee898fbd7ee7f900"
browser_image := "chromedp/headless-shell:157.0.8103.27@sha256:7bee201478b2f6266aae01243740ee85c16281e32f42d3aed9fdf04f4eace7a1"
dynamodb_image := "amazon/dynamodb-local@sha256:6ada631ec7aa5fc83446855eb17233e3dad184fec47477e8140c6c569cfe0c86"

default:
    @just --list

# Everything CI runs.
check: lint build test test-dynamodb test-keycloak test-envoy test-nginx test-conformance vuln

# Build every package. CGO is off: the binary is static.
build:
    CGO_ENABLED=0 go build ./...

# The executables of the images for one architecture (decision 0028): dist/image/linux/<arch>/session, with its version, a
# semantic version which `session version` prints and the audit records name; and beside it session-echo, the test backend of a
# deployed conformance site (decision 0029). The image workflow runs it for amd64 and arm64.
build-image arch version:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ "{{ version }}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "build-image: {{ version }} is not a semantic version" >&2; exit 1; }
    out="dist/image/linux/{{ arch }}"
    mkdir -p "$out"
    CGO_ENABLED=0 GOOS=linux GOARCH="{{ arch }}" go build -trimpath -ldflags "-s -w -X main.version={{ version }}" -o "$out/session" ./cmd/session
    CGO_ENABLED=0 GOOS=linux GOARCH="{{ arch }}" go build -trimpath -ldflags "-s -w" -o "$out/session-echo" ./conformance/echo/session-echo

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

# The nginx adapter through a real nginx (examples/nginx/nginx.conf) in a container on the host network. The test starts the
# container on a free port and removes it at the end.
test-nginx:
    docker pull -q {{ nginx_image }} >/dev/null
    SESSION_TEST_NGINX_IMAGE="{{ nginx_image }}" go test -count=1 -v ./internal/nginx/... 2>&1 \
      | awk '!/^=== (RUN|PAUSE|CONT|NAME)/ && !/^[[:space:]]*--- PASS/ && !/^PASS$/' ; test "${PIPESTATUS[0]}" -eq 0

# The conformance suite (conformance/): the same browser scenarios through every host, Envoy over gRPC, Envoy over HTTP and
# nginx, each running its example as it is, in a real headless browser (Chromium's headless shell, driven by chromedp) against
# a test Keycloak. Keycloak and the browser run for the whole suite, and the hosts' containers one at a time; all on the host
# network, all removed at the end.
test-conformance:
    #!/usr/bin/env bash
    set -euo pipefail
    docker pull -q {{ envoy_image }} >/dev/null
    docker pull -q {{ nginx_image }} >/dev/null
    docker pull -q {{ browser_image }} >/dev/null
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
      SESSION_TEST_ENVOY_IMAGE="{{ envoy_image }}" SESSION_TEST_NGINX_IMAGE="{{ nginx_image }}" SESSION_TEST_BROWSER_IMAGE="{{ browser_image }}" \
      go test -count=1 -v ./conformance/... 2>&1 \
      | awk '!/^=== (RUN|PAUSE|CONT|NAME)/ && !/^[[:space:]]*--- PASS/ && !/^PASS$/' ; test "${PIPESTATUS[0]}" -eq 0

# Settings are KEY=VALUE arguments, each one becoming SESSION_REMOTE_<KEY>:
#   just test-remote HOST=docs.devel.example.com ISSUER=https://idp.devel.example.com/realms/x IDP=mimic HINT=alice
# Keys: HOST (required), ISSUER, SITE_FILE, IDP, HINT, EMAIL, CA, RESOLVE, PROXY, MIMIC, MIMIC_TOKEN_FILE, USERNAME, AUDIT; SKIP
# is go test's -skip. A
# token or a password goes in the environment (SESSION_REMOTE_MIMIC_TOKEN, SESSION_REMOTE_PASSWORD), never on the command line.
# The conformance scenarios that can run against a deployed site (decision 0029, conformance/remote/README.md), in the pinned
# headless browser, which is removed at the end.
[positional-arguments]
test-remote *settings:
    #!/usr/bin/env bash
    set -euo pipefail
    for kv in "$@"; do
        key=${kv%%=*}
        case "$key" in
            HOST|ISSUER|SITE_FILE|IDP|HINT|EMAIL|CA|RESOLVE|PROXY|MIMIC|MIMIC_TOKEN_FILE|USERNAME|AUDIT|SKIP) ;;
            *) echo "test-remote: unknown setting $key (see the recipe's comment)" >&2; exit 2 ;;
        esac
        [ "$kv" != "$key" ] || { echo "test-remote: $kv is not KEY=VALUE" >&2; exit 2; }
        value=${kv#*=}
        case "$key" in SITE_FILE|CA|MIMIC_TOKEN_FILE) value=$(cd "{{ invocation_directory() }}" && realpath "$value") ;; esac
        export "SESSION_REMOTE_$key=$value"
    done
    [ -n "${SESSION_REMOTE_HOST:-}" ] || { echo "test-remote: HOST=... is required" >&2; exit 2; }
    docker pull -q {{ browser_image }} >/dev/null
    SESSION_TEST_BROWSER_IMAGE="{{ browser_image }}" go test -count=1 -timeout 30m -v -run '^TestRemote$' \
      ${SESSION_REMOTE_SKIP:+-skip "$SESSION_REMOTE_SKIP"} ./conformance/ 2>&1 \
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
