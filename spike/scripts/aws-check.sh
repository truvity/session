#!/usr/bin/env bash
# aws-check.sh: the checks of the fit spike that need a real AWS account (docs/spike-2026-11-22.md, section 4).
#
# What it checks, and why (design section 17, items 1, 2 and 4; decision records 0011 and 0012):
#   A. HTTP API, Lambda authorizer, payload 2.0, simple responses:
#        A1 the status for {"isAuthorized": false}
#        A2 the default cache TTL when authorizerResultTtlInSeconds is not set, with and without an identity source,
#           and whether a second request with the same cookie reaches the function (is the answer cached)
#        A3 the status when the authorizer function fails, and when it returns the error "Unauthorized"
#        A4 the event the authorizer receives, with and without an identity source (the Lambda Web Adapter
#           classifies it by its shape: identitySource as an array, absent, or empty)
#        A5 integration parameter mapping from $context.authorizer.*: into a non-reserved header (X-Session-Token),
#           into the reserved Authorization header (expected to be refused), and "remove:header.cookie"
#   B. REST API, REQUEST authorizer: the default cache TTL, the statuses for allow, a deny policy, the error
#      "Unauthorized" and a function failure, and the event the authorizer receives
#   C. Real DynamoDB latency of the one strongly consistent read of a check, from inside the region: a Lambda
#      function runs cmd/awsbench (the first spike's direct path against the atoom store port in-process)
#
# DRY RUN by default: it prints every command it would run and changes nothing. --apply acts.
# It uses only the profile given with --profile, and the region given with --region. Neither has a default.
# Everything it creates has the name prefix (default: session-fit-<random>) and is deleted at the end,
# also when a step fails or you press Ctrl-C. A leftover is listed by the last lines of the output.
# It appends its output to ~/log-sluis-v2.
# Needs: aws CLI v2, curl, jq, zip, and go (to build the benchmark function). Region must have Lambda arm64.
#
# usage: spike/scripts/aws-check.sh --profile NAME --region REGION [--prefix P] [--bench-n N] [--bench-rounds R] [--apply]
set -uo pipefail

PROFILE="" REGION="" PREFIX="" APPLY=0 BENCH_N=1000 BENCH_ROUNDS=3
while [ $# -gt 0 ]; do
  case $1 in
    --profile) PROFILE=${2:-}; shift 2 ;;
    --region) REGION=${2:-}; shift 2 ;;
    --prefix) PREFIX=${2:-}; shift 2 ;;
    --bench-n) BENCH_N=${2:-}; shift 2 ;;
    --bench-rounds) BENCH_ROUNDS=${2:-}; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help) sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$PROFILE" ] || { echo "--profile is required (there is no default)" >&2; exit 2; }
[ -n "$REGION" ] || { echo "--region is required (there is no default)" >&2; exit 2; }
[[ $PROFILE =~ ^[A-Za-z0-9_.@-]+$ ]] || { echo "the profile name has odd characters" >&2; exit 2; }
[[ $REGION =~ ^[a-z]{2}(-[a-z]+)+-[0-9]$ ]] || { echo "the region does not look like a region" >&2; exit 2; }
[ -n "$PREFIX" ] || PREFIX="session-fit-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
[[ $PREFIX =~ ^[a-z][a-z0-9-]{2,30}$ ]] || { echo "the prefix must be lower-case letters, digits and dashes, 3 to 31 characters" >&2; exit 2; }

LOG="$HOME/log-sluis-v2"
exec > >(tee -a "$LOG") 2>&1
echo
echo "##### aws-check.sh $(date -u +%FT%TZ) profile=$PROFILE region=$REGION prefix=$PREFIX apply=$APPLY"

# Only the named profile: nothing from the environment can pick another identity.
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE AWS_REGION AWS_DEFAULT_REGION AWS_ENDPOINT_URL
export AWS_PAGER="" AWS_RETRY_MODE=standard
aws_() { aws --profile "$PROFILE" --region "$REGION" "$@"; }

spike_dir=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
CLEANUP=()   # commands, run in reverse at the end
FAILED=0

show() { local c="$*"; echo "${c/#aws_/aws --profile $PROFILE --region $REGION}"; }
run() {      # run CMD...: print it, and run it only with --apply
  if [ $APPLY -eq 1 ]; then echo "+ $(show "$@")"; "$@" || { echo "FAILED: $(show "$@")"; exit 1; }; else echo "DRY: $(show "$@")"; fi
}
# val VAR -- cmd... : run a command that prints one value (an id), store it in VAR; a dry run stores a placeholder
val() {
  local var=$1; shift 2
  if [ $APPLY -eq 1 ]; then
    echo "+ $(show "$@")"
    local out; out=$("$@") || { echo "FAILED: $(show "$@")"; exit 1; }
    [ -n "$out" ] && [ "$out" != None ] || { echo "FAILED (no value): $(show "$@")"; exit 1; }
    printf -v "$var" '%s' "$out"
  else echo "DRY: $(show "$@")"; printf -v "$var" '%s' "<$var>"; fi
}
later() { CLEANUP+=("$*"); }   # register a cleanup command (a shell string)
result() { echo "RESULT $*"; }
http() {      # http URL [curl args]: prints the status code, and the body in $work/body
  if [ $APPLY -ne 1 ]; then echo "DRY: curl -s -o body -w '%{http_code}' $*" >&2; echo "<status>"; return; fi
  rm -f "$work/body"; curl -s -o "$work/body" -w '%{http_code}' --max-time 20 "$@" || true
}

cleanup() {
  local rc=$?
  echo "--- cleanup (exit status of the run: $rc)"
  local i
  for ((i=${#CLEANUP[@]}-1; i>=0; i--)); do
    if [ $APPLY -eq 1 ]; then echo "+ $(show "${CLEANUP[$i]}")"; eval "${CLEANUP[$i]}" >/dev/null 2>&1 || echo "  (already gone or failed: ${CLEANUP[$i]})"
    else echo "DRY (cleanup): $(show "${CLEANUP[$i]}")"; fi
  done
  rm -rf "$work"
  if [ $APPLY -eq 1 ]; then
    echo "--- left over with the prefix $PREFIX (should be empty):"
    local left=""
    left+=$(aws_ lambda list-functions --query "Functions[?starts_with(FunctionName, '$PREFIX')].FunctionName" --output text 2>&1)
    left+=$(aws_ apigatewayv2 get-apis --query "Items[?starts_with(Name, '$PREFIX')].ApiId" --output text 2>&1)
    left+=$(aws_ apigateway get-rest-apis --query "items[?starts_with(name, '$PREFIX')].id" --output text 2>&1)
    left+=$(aws_ dynamodb list-tables --query "TableNames[?starts_with(@, '$PREFIX')]" --output text 2>&1)
    left+=$(aws_ iam list-roles --query "Roles[?starts_with(RoleName, '$PREFIX')].RoleName" --output text 2>&1)
    left+=$(aws_ logs describe-log-groups --log-group-name-prefix "/aws/lambda/$PREFIX" --query 'logGroups[].logGroupName' --output text 2>&1)
    echo "${left:-  none}"
  fi
  echo "##### done $(date -u +%FT%TZ)"
}
trap cleanup EXIT
trap 'echo "interrupted"; exit 130' INT TERM

# ---------------------------------------------------------------- preflight
for t in aws curl jq zip go; do command -v $t >/dev/null || { echo "missing tool: $t"; [ $APPLY -eq 1 ] && exit 2; }; done
if [ $APPLY -eq 1 ]; then
  acct=$(aws_ sts get-caller-identity --query Account --output text) || { echo "the profile does not work"; exit 2; }
  echo "profile works, account ends in ...${acct: -4}"
else
  acct="<account>"; echo "DRY: aws --profile $PROFILE --region $REGION sts get-caller-identity (the account is not printed in full)"
fi

# ---------------------------------------------------------------- code of the two functions
# One Python function plays the authorizer for both products and echoes. The cookie value picks the answer:
#   ok -> allow, deny -> deny, boom -> the function fails, unauth -> the error "Unauthorized".
AUTH_PY='import json, uuid, os
def handler(event, ctx):
    ck = ""
    if "cookies" in event: ck = ";".join(event["cookies"])
    else: ck = (event.get("headers") or {}).get("cookie") or (event.get("headers") or {}).get("Cookie") or ""
    v2 = event.get("version") == "2.0"
    if "boom" in ck: raise RuntimeError("boom")
    if "unauth" in ck: raise Exception("Unauthorized")
    allow = "ok" in ck
    # the context carries the event itself (cut), a token for the mapping test and an id that shows whether an answer is cached
    c = {"token": "tok-" + ("alice" if allow else "none"), "sub": "alice", "invocation": str(uuid.uuid4()), "event": json.dumps(event)[:1800]}
    if v2: return {"isAuthorized": allow, "context": c}
    eff = "Allow" if allow else "Deny"
    return {"principalId": "alice", "policyDocument": {"Version": "2012-10-17", "Statement": [{"Action": "execute-api:Invoke", "Effect": eff, "Resource": event["methodArn"]}]}, "context": c}
'
ECHO_PY='import json
def handler(event, ctx):
    return {"statusCode": 200, "headers": {"content-type": "application/json"}, "body": json.dumps({"headers": event.get("headers"), "cookies": event.get("cookies"), "authorizer": (event.get("requestContext") or {}).get("authorizer")})}
'

ROLE="$PREFIX-role"
echo; echo "=== IAM role for the functions (basic logging, and DynamoDB on tables named $PREFIX-* only)"
TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
DDB_POLICY="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:CreateTable\",\"dynamodb:DescribeTable\",\"dynamodb:DeleteTable\",\"dynamodb:UpdateTimeToLive\",\"dynamodb:GetItem\",\"dynamodb:BatchGetItem\",\"dynamodb:PutItem\",\"dynamodb:DeleteItem\",\"dynamodb:Query\",\"dynamodb:TransactWriteItems\"],\"Resource\":\"arn:aws:dynamodb:$REGION:$acct:table/$PREFIX-*\"}]}"
val ROLE_ARN -- aws_ iam create-role --role-name "$ROLE" --assume-role-policy-document "$TRUST" --query Role.Arn --output text
later "aws_ iam delete-role --role-name $ROLE"
run aws_ iam attach-role-policy --role-name "$ROLE" --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
later "aws_ iam detach-role-policy --role-name $ROLE --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
run aws_ iam put-role-policy --role-name "$ROLE" --policy-name ddb --policy-document "$DDB_POLICY"
later "aws_ iam delete-role-policy --role-name $ROLE --policy-name ddb"
[ $APPLY -eq 1 ] && { echo "waiting 12 s for the role to propagate"; sleep 12; }

make_fn() {   # make_fn NAME HANDLER-MODULE PYTHON-SOURCE
  local name=$1 src=$2 body=$3
  if [ $APPLY -eq 1 ]; then printf '%s' "$body" > "$work/$src.py"; (cd "$work" && zip -q "$src.zip" "$src.py"); fi
  run aws_ lambda create-function --function-name "$name" --runtime python3.13 --architectures arm64 --role "$ROLE_ARN" \
    --handler "$src.handler" --zip-file "fileb://$work/$src.zip" --timeout 10 --memory-size 256 --query FunctionArn --output text
  later "aws_ lambda delete-function --function-name $name"
  later "aws_ logs delete-log-group --log-group-name /aws/lambda/$name"
  run aws_ lambda wait function-active-v2 --function-name "$name"
}
echo; echo "=== the authorizer function and the echo function"
make_fn "$PREFIX-auth" auth "$AUTH_PY"
make_fn "$PREFIX-echo" echo "$ECHO_PY"
val AUTH_ARN -- aws_ lambda get-function --function-name "$PREFIX-auth" --query Configuration.FunctionArn --output text
val ECHO_ARN -- aws_ lambda get-function --function-name "$PREFIX-echo" --query Configuration.FunctionArn --output text

# ---------------------------------------------------------------- A. HTTP API
echo; echo "=== A. HTTP API, authorizer payload 2.0, simple responses"
val API -- aws_ apigatewayv2 create-api --name "$PREFIX-http" --protocol-type HTTP --query ApiId --output text
later "aws_ apigatewayv2 delete-api --api-id $API"
for f in auth echo; do
  run aws_ lambda add-permission --function-name "$PREFIX-$f" --statement-id apigw-http --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:$REGION:$acct:$API/*"
done
# three authorizers: with the Cookie identity source and no TTL set (A2 default), with none and no TTL set, and with TTL 0
val AZ_COOKIE -- aws_ apigatewayv2 create-authorizer --api-id "$API" --name cookie-default --authorizer-type REQUEST \
  --authorizer-uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$AUTH_ARN/invocations" \
  --authorizer-payload-format-version 2.0 --enable-simple-responses --identity-source '$request.header.Cookie' --query AuthorizerId --output text
val AZ_NONE -- aws_ apigatewayv2 create-authorizer --api-id "$API" --name nosource-default --authorizer-type REQUEST \
  --authorizer-uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$AUTH_ARN/invocations" \
  --authorizer-payload-format-version 2.0 --enable-simple-responses --query AuthorizerId --output text
val AZ_TTL0 -- aws_ apigatewayv2 create-authorizer --api-id "$API" --name cookie-ttl0 --authorizer-type REQUEST \
  --authorizer-uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$AUTH_ARN/invocations" \
  --authorizer-payload-format-version 2.0 --enable-simple-responses --identity-source '$request.header.Cookie' \
  --authorizer-result-ttl-in-seconds 0 --query AuthorizerId --output text
for az in "cookie-default:$AZ_COOKIE" "nosource-default:$AZ_NONE" "cookie-ttl0:$AZ_TTL0"; do
  n=${az%%:*}; id=${az#*:}
  if [ $APPLY -eq 1 ]; then
    ttl=$(aws_ apigatewayv2 get-authorizer --api-id "$API" --authorizer-id "$id" --query AuthorizerResultTtlInSeconds --output text)
    src=$(aws_ apigatewayv2 get-authorizer --api-id "$API" --authorizer-id "$id" --query IdentitySource --output text)
    result "A2 authorizer $n: AuthorizerResultTtlInSeconds=$ttl IdentitySource=$src"
  else echo "DRY: aws apigatewayv2 get-authorizer ... (prints AuthorizerResultTtlInSeconds of $n)"; fi
done
val INTEG -- aws_ apigatewayv2 create-integration --api-id "$API" --integration-type AWS_PROXY --payload-format-version 2.0 \
  --integration-uri "$ECHO_ARN" --query IntegrationId --output text
# one route for each authorizer, so that each is tested alone
for r in "cookie:$AZ_COOKIE" "nosource:$AZ_NONE" "ttl0:$AZ_TTL0"; do
  n=${r%%:*}; id=${r#*:}
  run aws_ apigatewayv2 create-route --api-id "$API" --route-key "GET /$n" --target "integrations/$INTEG" \
    --authorization-type CUSTOM --authorizer-id "$id" --query RouteId --output text
done
run aws_ apigatewayv2 create-stage --api-id "$API" --stage-name '$default' --auto-deploy
val HTTP_URL -- aws_ apigatewayv2 get-api --api-id "$API" --query ApiEndpoint --output text
[ $APPLY -eq 1 ] && { echo "waiting 15 s for the stage"; sleep 15; }

echo "--- A1, A3: statuses (route /cookie has the Cookie identity source, /nosource has none)"
for c in ok deny boom unauth; do
  s=$(http "$HTTP_URL/cookie" -H "Cookie: __Host-s=$c"); result "A1/A3 HTTP API, /cookie, cookie=$c -> $s"
  s=$(http "$HTTP_URL/nosource" -H "Cookie: __Host-s=$c"); result "A1/A3 HTTP API, /nosource, cookie=$c -> $s"
done
s=$(http "$HTTP_URL/cookie"); result "A3 HTTP API, /cookie, no cookie at all -> $s (identity source missing: expected 401, function not invoked)"
s=$(http "$HTTP_URL/nosource"); result "A3 HTTP API, /nosource, no cookie at all -> $s"

echo "--- A2: is an answer cached? two requests with the same cookie; the context carries a fresh id from each invocation"
for r in cookie ttl0 nosource; do
  http "$HTTP_URL/$r" -H "Cookie: __Host-s=ok" >/dev/null; [ $APPLY -eq 1 ] && i1=$(jq -r .authorizer.lambda.invocation "$work/body" 2>/dev/null)
  http "$HTTP_URL/$r" -H "Cookie: __Host-s=ok" >/dev/null; [ $APPLY -eq 1 ] && i2=$(jq -r .authorizer.lambda.invocation "$work/body" 2>/dev/null)
  if [ $APPLY -eq 1 ]; then
    if [ -z "$i1" ] || [ "$i1" = null ] || [ -z "$i2" ] || [ "$i2" = null ]; then result "A2 /$r: no invocation id in the answer (the request did not reach the integration)"
    elif [ "$i1" = "$i2" ]; then result "A2 /$r: same invocation id twice, the answer IS cached"
    else result "A2 /$r: two invocation ids, the answer is NOT cached"; fi
  fi
done

echo "--- A4: the event the authorizer receives (from the context of an allowed request; cut at 1800 characters)"
for r in cookie nosource; do
  http "$HTTP_URL/$r" -H "Cookie: __Host-s=ok" >/dev/null
  [ $APPLY -eq 1 ] && result "A4 HTTP API /$r event: $(jq -r .authorizer.lambda.event "$work/body" 2>/dev/null | jq -c '{version, type, identitySource, has_identitySource: has("identitySource"), cookies, routeKey}' 2>/dev/null || echo 'cut or not JSON')"
done

echo "--- A5: parameter mapping from the authorizer context (each update replaces the previous mapping)"
for m in '{"overwrite:header.X-Session-Token":"$context.authorizer.token"}' \
         '{"overwrite:header.Authorization":"$context.authorizer.token"}' \
         '{"remove:header.cookie":""}'; do
  if [ $APPLY -eq 1 ]; then
    out=$(aws_ apigatewayv2 update-integration --api-id "$API" --integration-id "$INTEG" --request-parameters "$m" 2>&1) && st=accepted || st=REFUSED
    result "A5 mapping $m: $st $(echo "$out" | tr '\n' ' ' | cut -c1-240)"
    if [ "$st" = accepted ]; then
      sleep 6
      s=$(http "$HTTP_URL/ttl0" -H "Cookie: __Host-s=ok" -H "Authorization: Bearer browser-sent" -H "X-Session-Token: browser-sent")
      result "A5 request after $m: status $s; the integration saw: $(jq -c '{authorization: .headers.authorization, token: .headers["x-session-token"], cookie_header: .headers.cookie, cookies_array: .cookies}' "$work/body" 2>/dev/null)"
    fi
  else echo "DRY: aws --profile $PROFILE --region $REGION apigatewayv2 update-integration --request-parameters '$m', then one request"; fi
done

# ---------------------------------------------------------------- B. REST API
echo; echo "=== B. REST API, REQUEST authorizer"
val RAPI -- aws_ apigateway create-rest-api --name "$PREFIX-rest" --query id --output text
later "aws_ apigateway delete-rest-api --rest-api-id $RAPI"
val RROOT -- aws_ apigateway get-resources --rest-api-id "$RAPI" --query 'items[0].id' --output text
val RRES -- aws_ apigateway create-resource --rest-api-id "$RAPI" --parent-id "$RROOT" --path-part app --query id --output text
for f in auth echo; do
  run aws_ lambda add-permission --function-name "$PREFIX-$f" --statement-id apigw-rest --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:$REGION:$acct:$RAPI/*"
done
val RAZ -- aws_ apigateway create-authorizer --rest-api-id "$RAPI" --name cookie-default --type REQUEST --identity-source method.request.header.Cookie \
  --authorizer-uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$AUTH_ARN/invocations" --query id --output text
if [ $APPLY -eq 1 ]; then
  result "B REST authorizer, TTL not set: authorizerResultTtlInSeconds=$(aws_ apigateway get-authorizer --rest-api-id "$RAPI" --authorizer-id "$RAZ" --query authorizerResultTtlInSeconds --output text)"
fi
run aws_ apigateway put-method --rest-api-id "$RAPI" --resource-id "$RRES" --http-method GET --authorization-type CUSTOM --authorizer-id "$RAZ"
run aws_ apigateway put-integration --rest-api-id "$RAPI" --resource-id "$RRES" --http-method GET --type AWS_PROXY --integration-http-method POST \
  --uri "arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/$ECHO_ARN/invocations"
run aws_ apigateway create-deployment --rest-api-id "$RAPI" --stage-name test
val REST_URL -- echo "https://$RAPI.execute-api.$REGION.amazonaws.com/test"
[ $APPLY -eq 1 ] && { echo "waiting 15 s for the deployment"; sleep 15; }
for c in ok deny boom unauth; do
  s=$(http "$REST_URL/app" -H "Cookie: __Host-s=$c"); result "B REST API /app, cookie=$c -> $s"
done
s=$(http "$REST_URL/app"); result "B REST API /app, no cookie -> $s"
http "$REST_URL/app" -H "Cookie: __Host-s=ok" >/dev/null; [ $APPLY -eq 1 ] && i1=$(jq -r '.authorizer.invocation' "$work/body" 2>/dev/null)
http "$REST_URL/app" -H "Cookie: __Host-s=ok" >/dev/null; [ $APPLY -eq 1 ] && i2=$(jq -r '.authorizer.invocation' "$work/body" 2>/dev/null)
if [ $APPLY -eq 1 ]; then
  if [ -z "$i1" ] || [ "$i1" = null ]; then result "B REST API: no invocation id in the answer (the request did not reach the integration)"
  elif [ "$i1" = "$i2" ]; then result "B REST API: same invocation id twice, the answer IS cached (default TTL)"
  else result "B REST API: two invocation ids, the answer is NOT cached"; fi
fi
[ $APPLY -eq 1 ] && result "B REST API event: $(jq -r '.authorizer.event' "$work/body" 2>/dev/null | jq -c '{type, resource, path, httpMethod}' 2>/dev/null || echo 'cut or not JSON')"

# ---------------------------------------------------------------- C. DynamoDB latency from inside the region
echo; echo "=== C. real DynamoDB latency, from a Lambda function in $REGION (cmd/awsbench)"
if [ $APPLY -eq 1 ]; then
  (cd "$spike_dir" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$work/bootstrap" ./cmd/awsbench) || { echo "build failed"; FAILED=1; }
  (cd "$work" && rm -f bench.zip && zip -q bench.zip bootstrap)
else echo "DRY: (cd spike && GOOS=linux GOARCH=arm64 go build -o bootstrap ./cmd/awsbench) and zip"; fi
run aws_ lambda create-function --function-name "$PREFIX-bench" --runtime provided.al2023 --architectures arm64 --role "$ROLE_ARN" \
  --handler bootstrap --zip-file "fileb://$work/bench.zip" --timeout 900 --memory-size 1024 \
  --environment "Variables={BENCH_PREFIX=$PREFIX-b,BENCH_N=$BENCH_N,BENCH_ROUNDS=$BENCH_ROUNDS,BENCH_CONCURRENT=1}" --query FunctionArn --output text
later "aws_ lambda delete-function --function-name $PREFIX-bench"
later "aws_ logs delete-log-group --log-group-name /aws/lambda/$PREFIX-bench"
# the function drops its tables; these two lines drop them if it did not get so far
later "aws_ dynamodb delete-table --table-name $PREFIX-b-atoom"
later "aws_ dynamodb delete-table --table-name $PREFIX-b-direct"
run aws_ lambda wait function-active-v2 --function-name "$PREFIX-bench"
if [ $APPLY -eq 1 ]; then
  echo "+ aws lambda invoke $PREFIX-bench (takes some minutes)"
  if aws_ lambda invoke --function-name "$PREFIX-bench" --cli-read-timeout 900 --payload '{}' --cli-binary-format raw-in-base64-out "$work/bench.json" >"$work/invoke.out" 2>&1; then
    result "C bench function region: $(jq -r .region "$work/bench.json")"
    echo "RESULT C real DynamoDB, from the function (times in ms; the table is the one to copy into the findings):"
    jq -r '.result // .' "$work/bench.json"
  else echo "invoke failed:"; cat "$work/invoke.out"; FAILED=1; fi
else echo "DRY: aws lambda invoke $PREFIX-bench ; print its table"; fi

echo; echo "=== end of checks"
[ $FAILED -eq 0 ] || exit 1
