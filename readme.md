# ConditionalForwardAuth

A Traefik middleware with the exact semantics of the official Traefik ForwardAuth middleware, plus `skipAuthWhen`: rule-based exemptions that let chosen requests bypass authentication entirely.

## Configuration

All fields of the official Traefik `ForwardAuth` configuration are supported, plus `skipAuthWhen`.

```yaml
# Add this under traefik definitions
http:
  middlewares:
    my-conditional-forwardauth:
      plugin:
        conditionalforwardauth:
          address: "http://auth-server:8080/"

          # --- exemptions ---
          skipAuthWhen:
            # Match on the host alone.
            - expression: "{ .Host }"
              isExactly:
                - "public.example.com"
              endsWith:
                - ".internal"

            # Match on "GET example.com/health".
            - expression: "{ .Method } { .Host }{ .Path }"
              isExactly:
                - "GET example.com/health"

            # Match on "host/path".
            - expression: "{ .Host }{ .Path }"
              startsWith:
                - "cdn.example.com/assets/"
              contains:
                - "/public/"
              matchesRegex:
                - "^api\\.example\\.com/v[0-9]+/ping$"

          # --- inherited from ForwardAuth ---
          trustForwardHeader: true
          authResponseHeaders:
            - X-Auth-User

          # --- diagnostics ---
          debug: false
```

### How `skipAuthWhen` works

Each rule renders `expression` as a [Go template](https://pkg.go.dev/text/template) — with single-brace delimiters, `{ .Host }`, see below — against the request, then tests the rendered string against its predicates.

- A **rule** matches when **any value of any predicate** matches (logical OR).
- Authentication is skipped when **any rule** matches.
- A skip means **no authentication at all** — the auth server is never contacted.

### Template substitutions

| Substitution | Value | Example |
|---|---|---|
| `{ .Host }` | Request host. May include a port. | `api.example.com` |
| `{ .Path }` | URL path only, cleaned. Never includes query or fragment. | `/v1/users` |
| `{ .Method }` | HTTP method. | `GET` |
| `{ .Scheme }` | `https` or `http`, from the connection Traefik accepted. `X-Forwarded-Proto` is never consulted. | `https` |
| `{ .UserAgent }` | `User-Agent` header. | `curl/8.5.0` |
| `{ .ClientIp }` | Peer IP from `RemoteAddr`, no port, IPv6 safe. `X-Forwarded-For` is never consulted. | `2001:db8::1` |

Each substitution has exactly one spelling: the names above are the only ones accepted. Anything else — a typo such as `{ .Hsot }` or a lowercase form such as `{ .host }` — is rejected at startup rather than silently never matching.

> [!IMPORTANT]
> Expressions use **single braces**, `{ .Host }`, not Go's usual `{{ .Host }}`.
>
> Traefik uses `{{ }}` itself, both in file-provider configuration templates and in the label/tag values read by the Docker, Consul and Kubernetes providers, so a `{{ }}` expression risks being consumed before this plugin ever sees it.
>
> - An expression still written as `{{ .Host }}` is a **startup error**, not a silent mismatch.
> - **Quote expressions in YAML.** A bare `expression: { .Host }` is a YAML flow mapping, not a string.
> - A literal `{` can no longer appear in an expression; it opens a substitution.

### Predicates

| Predicate | Matching | Notes |
|---|---|---|
| `isExactly` | Exact equality | Backed by a lookup map — constant cost regardless of list length |
| `startsWith` | Prefix | |
| `endsWith` | Suffix | |
| `contains` | Substring | |
| `matchesRegex` | RE2 regex | Partial match; anchor with `^`/`$` for a full match |

All matching is **case-sensitive**. Every rule requires an `expression` and at least one predicate; violations are startup errors.

> [!IMPORTANT]
> These rules decide whether to **bypass authentication**, so the plugin deliberately fails closed:
> - **Paths are normalized** with `path.Clean` before matching. `/public/../admin` is matched as `/admin`, so it cannot satisfy a `startsWith: /public/` rule while the backend serves `/admin`. Note this also drops a trailing slash (`/health/` matches as `/health`).
> - **Query strings and fragments are never matched.** A value smuggled into `?redirect=/health` cannot trigger an exemption.
> - **No `X-Forwarded-*` header is ever consulted**, regardless of `trustForwardHeader`. `{ .Scheme }` comes from the accepted connection and `{ .ClientIp }` from `RemoteAddr`, so a client cannot spoof its way into an exemption. (`trustForwardHeader` still configures the ForwardAuth request itself — it just has no bearing on skip matching.)
> - Consequently `{ .ClientIp }` is the **direct peer**. If Traefik sits behind another proxy or load balancer, that is the intermediary's address, not the end user's, and an IP rule would exempt everything arriving through it. Prefer `{ .Host }` / `{ .Path }` rules in that topology.
> - A template that fails to render at request time is treated as **not matching**, so the request is authenticated.


## Debugging

`debug: true` explains what the middleware decided and why. It logs the compiled rules once at startup, then one line per request.

Traefik exposes no logger to plugins — [its documentation](https://plugins.traefik.io/create) states the only way to emit anything is writing to `os.Stdout` / `os.Stderr` — so these lines land in Traefik's own stdout, prefixed with the plugin and middleware name so they can be grepped apart:

```
[conditionalforwardauth:my-auth] debug on, 3 skip rule(s):
[conditionalforwardauth:my-auth] rule[0] "{ .Host }" isExactly ["public.example.com"] endsWith [".internal"]
[conditionalforwardauth:my-auth] rule[1] "{ .Method } { .Host }{ .Path }" isExactly ["GET example.com/health"]
[conditionalforwardauth:my-auth] rule[2] "{ .Host }{ .Path }" startsWith ["cdn.example.com/assets/"]
[conditionalforwardauth:my-auth] skip GET http://example.com/health from 192.0.2.10 -> rule[1] isExactly "GET example.com/health"
[conditionalforwardauth:my-auth] skip GET http://cdn.example.com/assets/app.css from 192.0.2.10 -> rule[2] startsWith "cdn.example.com/assets/" in "cdn.example.com/assets/app.css"
[conditionalforwardauth:my-auth] auth GET http://example.com/private from 192.0.2.10
```

- `skip` — the request bypassed authentication; the rule index, predicate and pattern that fired are named, and `in "…"` shows the rendered expression when it differs from the pattern.
- `auth` — no rule matched, so the request went to the auth server.
- Rule indexes refer to the startup dump, which lists rules in configuration order.

> [!CAUTION]
> Do not leave `debug` on in production. It writes a line per request, and those lines contain the host, path and client IP.

When `debug` is off the logger is not allocated at all and the call sites cost a single nil check; matching performance is unchanged (verified by the benchmarks in `authskipper_test.go`).

## Source layout

| File | Responsibility |
|---|---|
| `config.go` | Every configuration type (`Config`, `SkipRule`, `ClientTLS`), `CreateConfig`, and `RequestArgs` — the single representation of a request that expressions render against. |
| `conditionalforwardauth.go` | Plugin entry points (`New`, `ServeHTTP`) and all `*http.Request` handling: building `RequestArgs`, cleaning the path, deriving the scheme and client IP. |
| `authskipper.go` | The `AuthSkipper` rule engine: `NewAuthSkipper` compiles and probes the rules at startup, `ShouldSkip` evaluates a `RequestArgs` against them. Knows nothing about `net/http` requests. |
| `debuglog.go` | What a debug line looks like and where it goes. The only file that touches `os.Stdout`. |
| `forwardauth.go` | The vendored, stripped copy of upstream Traefik's ForwardAuth. See Provenance below. |

## Provenance

This plugin's internal `forwardAuth` handler is natively derived from upstream `traefik/traefik` codebase `pkg/middlewares/auth/forward.go`.

All dependencies on metrics, tracing, internal dynamic Config structs, and third-party libraries have been stripped to conform to standard-library-only Yaegi requirements.

### Deliberate divergences from upstream

These are intentional and should be re-checked whenever the vendored file is refreshed:

| Divergence | Upstream | Here | Why |
|---|---|---|---|
| `maxBodySize` default | `-1` (unlimited) | `4194304` (4 MiB) | Traefik's own docs call unlimited a DoS/memory-exhaustion risk and recommend a limit. Set `maxBodySize: -1` to restore upstream behaviour. |
| Legacy `oldWriteHeader` path | Used when `trustForwardHeader` is unset, with a startup deprecation warning | Retained, matching upstream — but with no warning, since a plugin has no logger | Behaviour matches upstream exactly. **Set `trustForwardHeader` explicitly** (`true` or `false`): leaving it unset silently selects the deprecated legacy header handling, which forwards some `X-Forwarded-*` headers untouched. |
| Tracing / access logs | OpenTelemetry spans, `accesslog.ClientUsername` | Removed | Not reachable from a plugin. `headerField` still propagates the authenticated user as a request header. |

### Re-diffing against upstream

```bash
curl -s https://raw.githubusercontent.com/traefik/traefik/master/pkg/middlewares/auth/forward.go -o /tmp/forward.upstream.go
diff /tmp/forward.upstream.go forwardauth.go     # expect: stripped imports, no tracing/logging, inlined helpers
```
