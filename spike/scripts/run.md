# How the spike was run (throwaway notes, commands as run on 2026-11-18)

Everything is local. Host networking is used so that the containers reach the Go processes on 127.0.0.1.
At most two containers ran at once. Replace `$W` with a scratch directory.

```sh
export CGO_ENABLED=0 AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x
go run ./cmd/genrealm $W/kc            # client key (never committed) and Keycloak realm import
go build -o $W/ ./cmd/spike ./cmd/echo ./cmd/e2e ./cmd/bench
export CLIENT_KEY=$W/kc/client-key.pem

# container 1, kept for the whole run
docker run -d --rm --name ddb -p 127.0.0.1:18000:8000 amazon/dynamodb-local:latest -jar DynamoDBLocal.jar -inMemory -sharedDb
# container 2, one at a time
docker run -d --rm --name kc --network host -v $W/kc/realm.json:/opt/keycloak/data/import/realm.json:ro \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KC_HTTP_PORT=18080 -e KC_HTTP_HOST=127.0.0.1 \
  quay.io/keycloak/keycloak:26.8 start-dev --import-realm --hostname-strict=false
docker run -d --rm --name envoy --network host -v $PWD/envoy/envoy.yaml:/e.yaml:ro envoyproxy/envoy:v1.34-latest -c /e.yaml
sed 's/ORIG_URI/$uri$is_args$args/' nginx/nginx.conf > $W/nginx.conf      # or $request_uri for the unsafe variant
docker run -d --rm --name nginx --network host -v $W/nginx.conf:/etc/nginx/nginx.conf:ro nginx:1.27-alpine

$W/echo & $W/spike &                                   # upstream on 18095, check service on 18090 (HTTP) and 18091 (gRPC)
$W/e2e signin http://127.0.0.1:18081 $W/cookie.txt     # code + PKCE + PAR + private_key_jwt through Envoy and Keycloak
$W/e2e checks envoy-http http://127.0.0.1:18081 $W/cookie.txt
$W/e2e checks envoy-grpc http://127.0.0.1:18083 $W/cookie.txt
$W/e2e checks nginx http://127.0.0.1:18082 $W/cookie.txt
$W/bench 1000                                          # latency against DynamoDB Local
go test ./...                                          # needs DynamoDB Local on 127.0.0.1:18000, else the store tests skip
```
