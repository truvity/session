package signin

import "html/template"

// pageData is what the sign-in page is given: the issuers in the site file's order, each with its label and the address of its
// sign-in. A site's own template, when sites may give one, gets the same (decision 0034).
type pageData struct {
	Issuers []pageIssuer
}

type pageIssuer struct {
	Label string
	URL   string // /_session/login?issuer=<id>&return_to=<path>
}

// pageCSP lets the page show itself and its own inline style, and nothing else: no script, no frame, no form, no other origin.
const pageCSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// signInPage is session's own sign-in page: small, neutral, plain links, no script. html/template escapes each label and
// address.
var signInPage = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #f6f6f6; color: #1a1a1a; }
main { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 2rem; width: min(22rem, calc(100vw - 2rem)); box-sizing: border-box; }
h1 { font-size: 1.25rem; margin: 0 0 1.25rem; }
ul { list-style: none; margin: 0; padding: 0; }
li + li { margin-top: 0.75rem; }
a { display: block; padding: 0.75rem 1rem; border: 1px solid #888; border-radius: 6px; color: inherit; text-decoration: none; text-align: center; }
a:hover, a:focus { background: #eee; }
@media (prefers-color-scheme: dark) {
  body { background: #161616; color: #eee; }
  main { background: #222; border-color: #444; }
  a { border-color: #777; }
  a:hover, a:focus { background: #333; }
}
</style>
</head>
<body>
<main>
<h1>Sign in</h1>
<ul>
{{- range .Issuers}}
<li><a href="{{.URL}}">Sign in with {{.Label}}</a></li>
{{- end}}
</ul>
</main>
</body>
</html>
`))
