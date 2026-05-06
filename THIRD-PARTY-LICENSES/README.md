# Third-Party Licenses

This directory ships the license text of upstream projects whose
research findings or source materials informed parts of aikey-proxy.

| File | Upstream | License | Where used |
|---|---|---|---|
| [sub2api-LGPL-3.0.txt](sub2api-LGPL-3.0.txt) | [Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api) | LGPL-3.0 | Anthropic OAuth body-fingerprint mimicry — see [internal/proxy/oauth_inject_waf_full.go](../internal/proxy/oauth_inject_waf_full.go) and the project [NOTICE](../NOTICE) for the attribution and provenance details. |

The Go source in `internal/proxy/oauth_inject_waf_full.go` is an
independent re-expression of publicly-observable wire-format facts; the
LGPL-3.0 text is shipped here as a defensive measure. See [NOTICE](../NOTICE)
for the full attribution.
