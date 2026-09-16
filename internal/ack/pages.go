package ack

import "html/template"

// The pages are deliberately plain: inline CSS, no scripts, no external
// resources. They are opened on a phone at 3am, often on a bad connection,
// by somebody who is not fully awake. Nothing here should need to load before
// the button works.
//
// A Content-Security-Policy of "default-src 'none'" is set on every response,
// so anything fetched from elsewhere would be blocked anyway.

const pageHead = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NotifyMatrix</title>
<style>
 body{font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
      margin:0;padding:24px;background:#12151a;color:#e6e9ef}
 main{max-width:34rem;margin:0 auto}
 h1{font-size:1.35rem;margin:0 0 .25rem}
 .sev{display:inline-block;font-size:.75rem;letter-spacing:.08em;
      text-transform:uppercase;padding:.15rem .5rem;border-radius:.25rem;
      background:#3a2226;color:#ffb4b4;margin-bottom:1rem}
 .detail{white-space:pre-wrap;background:#1a1f27;border-radius:.5rem;
      padding:.9rem 1rem;margin:1rem 0;color:#c3cad6;font-size:.95rem}
 button{font:inherit;font-weight:600;width:100%;padding:.9rem 1rem;
      border:0;border-radius:.6rem;background:#2f6f4f;color:#fff}
 .muted{color:#8b95a5;font-size:.9rem}
 .ok{color:#7fd6a2}
 .bad{color:#ffb4b4}
</style></head><body><main>`

const pageFoot = `</main></body></html>`

// pageConfirm is what a GET renders. The acknowledgement happens on the POST
// behind this button -- see the note on ServeHTTP about mail scanners.
var pageConfirm = template.Must(template.New("confirm").Parse(pageHead + `
<h1>Acknowledge this alert?</h1>
<div class="sev">{{.Incident.Severity}}</div>
<p><strong>{{.Incident.Title}}</strong></p>
{{if .Incident.Detail}}<div class="detail">{{.Incident.Detail}}</div>{{end}}
<form method="post" action="{{.Action}}{{if .Via}}?via={{.Via}}{{end}}">
  <button type="submit">Acknowledge</button>
</form>
<p class="muted">This stops the alert repeating. It does <em>not</em> mean the
problem is fixed &mdash; the incident stays open until the condition clears.</p>
` + pageFoot))

var pageDone = template.Must(template.New("done").Parse(pageHead + `
<h1 class="ok">Acknowledged</h1>
<p><strong>{{.Title}}</strong></p>
<p class="muted">You will not be alerted about this again.
{{if not .Resolved}}The condition has not cleared yet, so it stays on the board
until it does.{{end}}</p>
` + pageFoot))

var pageAlready = template.Must(template.New("already").Parse(pageHead + `
<h1 class="ok">Already acknowledged</h1>
<p><strong>{{.Title}}</strong></p>
<p class="muted">Nothing more to do.</p>
` + pageFoot))

// pageInvalid is shown for a wrong token AND for an unknown incident. One page
// for both, on purpose: telling them apart would let a stranger find out which
// incident ids exist.
var pageInvalid = template.Must(template.New("invalid").Parse(pageHead + `
<h1 class="bad">That link is not valid</h1>
<p class="muted">It may have been mistyped or truncated. Acknowledgement links
are long; if this came from an email, check that the whole link was copied.</p>
` + pageFoot))

var pageError = template.Must(template.New("error").Parse(pageHead + `
<h1 class="bad">Something went wrong</h1>
<p class="muted">The acknowledgement was not recorded. The alert will keep
repeating, which is the safe direction to fail in. Try again.</p>
` + pageFoot))
