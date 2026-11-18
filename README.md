# session

Browser sessions for websites behind Envoy Gateway, nginx or AWS API Gateway.

`session` is an OIDC client that keeps a website's browser session on the server and answers "may this request pass?" for the proxy in front of the site (external authorisation: Envoy `ext_authz`, nginx `auth_request`, an API Gateway Lambda authorizer). It can also run in the request path as a reverse proxy.

Status: design. The design document comes next.
