#!/usr/bin/env bash
# Runs the Lambda Web Adapter test: builds the image, starts it with the emulator, sends the events of lwa/events,
# prints each answer and the app's log lines, stops the container. One container, removed at the end.
# usage: lwa/run.sh [extra docker -e options, e.g. -e AWS_LWA_ERROR_STATUS_CODES=401]
#        MODE=native lwa/run.sh      the native Go handler (cmd/authorizer-lambda) with no adapter
# Run from the spike/ directory.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
spike=$(dirname "$here")
work=$(mktemp -d)
trap 'docker rm -f fit-rie >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
if [ "${MODE:-adapter}" = native ]; then app=authorizer-lambda; df=Dockerfile.native; else app=fitapp; df=Dockerfile; fi
(cd "$spike" && CGO_ENABLED=0 GOOS=linux go build -o "$work/bootstrap" "./cmd/$app")
cp "$here/$df" "$work/Dockerfile"
docker build -q -t fit-rie:spike "$work" >/dev/null
docker run -d --rm --name fit-rie -p 127.0.0.1:19000:8080 "$@" fit-rie:spike >/dev/null
for _ in $(seq 1 50); do curl -s -o /dev/null http://127.0.0.1:19000/ && break; sleep 0.2; done
invoke() { # name, event file, session value
  local name=$1 file=$2 sess=$3
  echo "=== $name"
  sed "s/SESSION/$sess/g" "$file" | curl -s -D - -o /tmp/fit-rie-body.$$ -X POST --data-binary @- \
    http://127.0.0.1:19000/2015-03-31/functions/function/invocations | tr -d '\r' | grep -i -E '^(HTTP|x-amz-function-error|content-type)' || true
  echo "--- answer body:"; cat /tmp/fit-rie-body.$$; echo; rm -f /tmp/fit-rie-body.$$
}
invoke "REST API REQUEST authorizer event, valid session"     "$here/events/rest-request.json"    sess-ok
invoke "REST API REQUEST authorizer event, no session"        "$here/events/rest-request.json"    nope
invoke "HTTP API 2.0 authorizer event, valid session"         "$here/events/http-v2-request.json" sess-ok
invoke "HTTP API 2.0 authorizer event, no session"            "$here/events/http-v2-request.json" nope
invoke "HTTP API 2.0 authorizer event, store down"            "$here/events/http-v2-request.json" boom
invoke "REST API REQUEST authorizer event, store down"        "$here/events/rest-request.json"    boom
invoke "HTTP API 2.0 event WITHOUT identitySource, valid"     "$here/events/http-v2-no-identity-source.json" sess-ok
invoke "HTTP API 2.0 event with an EMPTY identitySource"      "$here/events/http-v2-empty-identity-source.json" sess-ok
invoke "REST API TOKEN authorizer event"                      "$here/events/rest-token.json"      x
invoke "non-HTTP event (control)"                             "$here/events/non-http.json"        x
echo "=== app log"
docker logs fit-rie 2>&1 | grep -E 'REQ |fitapp up|ERROR|WARN|EXTENSION|START|END' | sed 's/^[0-9\/: ]* //' || true
