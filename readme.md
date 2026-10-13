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
          # Every key is optional. Auth is skipped when ANY key matches.
          skipAuthWhen:
            host:
              isExactly:
                - "public.example.com"
              endsWith:
                - ".internal"
            path:
              isExactly:
                - "/healthz"
              startsWith:
                - "/.well-known/"
            url:                                  # host and path joined
              startsWith:
                - "cdn.example.com/assets/"
              matchesRegex:
                - "^api\\.example\\.com/v[0-9]+/ping$"
            clientIp:
              inSubnet:
                - "10.0.0.0/8"
                - "127.0.0.1"
            userAgent:
              startsWith:
                - "kube-probe/"
            # Anything the keys above cannot express, as Go templates.
            custom:
              - expression: "{ .Method } { .Host }{ .Path }"
                isExactly:
                  - "GET example.com/health"

          # --- inherited from ForwardAuth ---
          trustForwardHeader: true
          authResponseHeaders:
            - X-Auth-User

          # --- diagnostics ---
          debug: false
```

### How `skipAuthWhen` works

`skipAuthWhen` is a fixed set of **keys**. Each key names one attribute of the request and carries the predicates to test it with:

- A **key** matches when **any value of any of its predicates** matches (logical OR).
- Authentication is skipped when **any key** matches.
- A skip means **no authentication at all** — the auth server is never contacted.
- Keys are evaluated in the order of the table below, then `custom` rules in configuration order; the first match wins (this only affects which rule the debug log names).

### Keys

| Key | Value tested | Example | Custom equivalent |
|---|---|---|---|
| `host` | Request host. May include a port. | `api.example.com` | `{ .Host }` |
| `path` | URL path only, cleaned. Never includes query or fragment. | `/v1/users` | `{ .Path }` |
| `url` | Host and path joined with no separator. No scheme. | `api.example.com/v1/users` | `{ .Host }{ .Path }` |
| `clientIp` | Peer IP from `RemoteAddr`, no port, IPv6 safe. `X-Forwarded-For` is never consulted. The only key that accepts `inSubnet`. | `2001:db8::1` | `{ .ClientIp }` |
| `userAgent` | `User-Agent` header. | `curl/8.5.0` | `{ .UserAgent }` |
| `custom` | A **list** of template rules, each with an `expression` rendered against the request. For method, scheme, or any combination. | | — |

Prefer a predefined key whenever one fits: it is evaluated without rendering a template, and only the attributes that some key actually reads are extracted from the request. See [Performance](#performance).

### Predicates

| Predicate | Matching | Notes |
|---|---|---|
| `isExactly` | Exact equality | Backed by a lookup map — constant cost regardless of list length |
| `startsWith` | Prefix | |
| `endsWith` | Suffix | |
| `contains` | Substring | |
| `matchesRegex` | RE2 regex | Partial match; anchor with `^`/`$` for a full match |
| `inSubnet` | IP within network | **`clientIp` only.** CIDR (`10.0.0.0/8`, `2001:db8::/32`) or a bare address (`127.0.0.1`), which stands for itself. Host bits in a CIDR are masked off (`10.0.0.7/24` means `10.0.0.0/24`). IPv4 clients seen as IPv4-mapped IPv6 (`::ffff:10.0.0.7`) still match IPv4 networks. |

All string matching is **case-sensitive**. Every key requires at least one predicate, `expression` is required under `custom` and rejected anywhere else, and `inSubnet` is rejected outside `clientIp`; each of these is a startup error that names the offending key (`skipAuthWhen.path: inSubnet is only valid under clientIp`).

### Custom expressions

A `custom` rule renders `expression` as a [Go template](https://pkg.go.dev/text/template) — with single-brace delimiters, see below — against the request, then tests the rendered string with the string predicates above. Available substitutions:

| Substitution | Value |
|---|---|
| `{ .Host }`, `{ .Path }`, `{ .UserAgent }`, `{ .ClientIp }` | As the keys of the same name |
| `{ .Method }` | HTTP method, e.g. `GET` |
| `{ .Scheme }` | `https` or `http`, from the connection Traefik accepted. `X-Forwarded-Proto` is never consulted. |

Each substitution has exactly one spelling: the names above are the only ones accepted. Anything else — a typo such as `{ .Hsot }` or a lowercase form such as `{ .host }` — is rejected at startup rather than silently never matching.

> [!IMPORTANT]
> Expressions use **single braces**, `{ .Host }`, not Go's usual `{{ .Host }}`.
>
> Traefik uses `{{ }}` itself, both in file-provider configuration templates and in the label/tag values read by the Docker, Consul and Kubernetes providers, so a `{{ }}` expression risks being consumed before this plugin ever sees it.
>
> - An expression still written as `{{ .Host }}` is a **startup error**, not a silent mismatch.
> - **Quote expressions in YAML.** A bare `expression: { .Host }` is a YAML flow mapping, not a string.
> - A literal `{` cannot appear in an expression; it opens a substitution.

> [!IMPORTANT]
> These rules decide whether to **bypass authentication**, so the plugin deliberately fails closed:
> - **Paths are normalized** with `path.Clean` before matching. `/public/../admin` is matched as `/admin`, so it cannot satisfy a `startsWith: /public/` rule while the backend serves `/admin`. Note this also drops a trailing slash (`/health/` matches as `/health`).
> - **Query strings and fragments are never matched.** A value smuggled into `?redirect=/health` cannot trigger an exemption.
> - **No `X-Forwarded-*` header is ever consulted**, regardless of `trustForwardHeader`. `{ .Scheme }` comes from the accepted connection and `clientIp` from `RemoteAddr`, so a client cannot spoof its way into an exemption. (`trustForwardHeader` still configures the ForwardAuth request itself — it just has no bearing on skip matching.)
> - Consequently `clientIp` is the **direct peer**. If Traefik sits behind another proxy or load balancer, that is the intermediary's address, not the end user's, and an IP rule would exempt everything arriving through it. Prefer `host` / `path` rules in that topology.
> - A client address that does not parse is in **no** subnet, and a template that fails to render at request time is treated as **not matching**: either way the request is authenticated.

### Migrating from the list form (pre-1.0)

Before 1.0, `skipAuthWhen` was a list of `expression` rules. That form is **no longer accepted**: Traefik fails to decode the configuration (`expected a map, got 'slice'`) and the middleware does not start, so no exemption is silently lost. Move each rule under the key its expression names; keep only genuinely composite expressions under `custom`:

```yaml
# before
skipAuthWhen:
  - expression: "{ .Host }"
    isExactly: ["public.example.com"]
    endsWith: [".internal"]
  - expression: "{ .Host }{ .Path }"
    startsWith: ["cdn.example.com/assets/"]
  - expression: "{ .ClientIp }"
    isExactly: ["10.0.0.5"]
  - expression: "{ .Method } { .Host }{ .Path }"
    isExactly: ["GET example.com/health"]

# after
skipAuthWhen:
  host:
    isExactly: ["public.example.com"]
    endsWith: [".internal"]
  url:
    startsWith: ["cdn.example.com/assets/"]
  clientIp:
    isExactly: ["10.0.0.5"]          # or inSubnet: ["10.0.0.5"]
  custom:
    - expression: "{ .Method } { .Host }{ .Path }"
      isExactly: ["GET example.com/health"]
```

Two rules on the same attribute merge into one key — predicates within a key are OR-ed, exactly as rules were. The even older `skipUrls` / `skipUrlsRegex` fields are still rejected at startup with a pointer to `skipAuthWhen`.

## Performance

Traefik runs plugins through the [Yaegi](https://github.com/traefik/yaegi) interpreter, so `make bench` measures every benchmark twice: `bench_go` is the compiled algorithm, `bench_yaegi` is what production actually pays. Interpreted cost is dominated by the number of interpreted statements and allocations rather than by the work compiled Go would do, which is why the two columns do not scale together.

Each predefined key has a `_Custom` twin benchmark expressing the same rule as a template. Per-request cost of the skip decision, including request-attribute extraction (`BenchmarkSkipAuth_EndToEnd*`), on the benchmarks' reference machine:

| Rule | compiled Go: key | compiled Go: custom | Yaegi: key | Yaegi: custom |
|---|---|---|---|---|
| `host` / `isExactly` hit | 21 ns, 0 allocs | 479 ns, 6 allocs | 7.6 µs | 11.8 µs |
| `path` / `startsWith` | 20 ns, 0 allocs | 466 ns, 6 allocs | 8.0 µs | 12.1 µs |
| `path` / `matchesRegex` | 112 ns, 0 allocs | 614 ns, 6 allocs | 9.0 µs | 13.2 µs |
| `url` / `startsWith` | 48 ns, 1 allocs | 651 ns, 6 allocs | 8.2 µs | 12.2 µs |
| realistic config (host, url, path; last matches) | 127 ns, 0 allocs | 1.8 µs, 18 allocs | 13.5 µs | 30.5 µs |
| end-to-end: extraction + host, url | 94 ns, 1 allocs | 1.3 µs, 12 allocs | 16.4 µs | 27.8 µs |

Rules without a template equivalent:

| Rule | compiled Go | Yaegi |
|---|---|---|
| `clientIp` / `inSubnet` hit (2 networks) | 141 ns, 2 allocs | 12.7 µs |
| every key configured, none match | 256 ns, 1 allocs | 33.1 µs |
| no rules, debug off | 1 ns, 0 allocs | 85 ns |

What the predefined keys buy:

- **No template rendering.** A `custom` rule executes `text/template` per request, which reflects over `RequestArgs` and allocates a buffer and the rendered string; a key compares the attribute in place.
- **Only the needed attributes are extracted.** The handler computes once, at startup, which request fields the configured keys read (`host` → `Host`; `url` → `Host`+`Path`; …) and extracts only those. A `custom` rule forces all of them, because a template may reference any. With no rules and `debug` off the request is not inspected at all.
- **A key is a single comparison site**, where several list rules on the same attribute used to each re-render it.

`custom` remains the right tool for method, scheme and composite conditions; it is only the slower one for conditions a key already covers.

> [!NOTE]
> Under Yaegi the cost is dominated by interpreter overhead per call and per statement, not by the work itself — a method call costs about four times a plain function call, and even a call on a nil receiver is a full call. The request-time path in `authskipper.go` is shaped around those measurements; the comment above `matchRules` lists them. Compared with the pre-1.0 list form, the same host/url exemption costs about half under Yaegi (31 µs → 16 µs) and about a thirteenth compiled (1.3 µs → 94 ns).

## Debugging

`debug: true` explains what the middleware decided and why. It logs the compiled rules once at startup, then one line per request.

Traefik exposes no logger to plugins — [its documentation](https://plugins.traefik.io/create) states the only way to emit anything is writing to `os.Stdout` / `os.Stderr` — so these lines land in Traefik's own stdout, prefixed with the plugin and middleware name so they can be grepped apart:

```
[conditionalforwardauth:my-auth] debug on, 4 skip rule(s):
[conditionalforwardauth:my-auth] host isExactly ["public.example.com"] endsWith [".internal"]
[conditionalforwardauth:my-auth] url startsWith ["cdn.example.com/assets/"]
[conditionalforwardauth:my-auth] clientIp inSubnet ["10.0.0.0/8"]
[conditionalforwardauth:my-auth] custom[0] "{ .Method } { .Host }{ .Path }" isExactly ["GET example.com/health"]
[conditionalforwardauth:my-auth] skip GET http://example.com/health from 192.0.2.10 -> custom[0] isExactly "GET example.com/health"
[conditionalforwardauth:my-auth] skip GET http://cdn.example.com/assets/app.css from 192.0.2.10 -> url startsWith "cdn.example.com/assets/" in "cdn.example.com/assets/app.css"
[conditionalforwardauth:my-auth] skip GET http://example.com/private from 10.1.2.3 -> clientIp inSubnet "10.0.0.0/8" in "10.1.2.3"
[conditionalforwardauth:my-auth] auth GET http://example.com/private from 192.0.2.10
```

- `skip` — the request bypassed authentication; the key (or `custom[i]`), predicate and pattern that fired are named, and `in "…"` shows the value that was tested when it differs from the pattern.
- `auth` — no rule matched, so the request went to the auth server.
- The startup dump lists rules in evaluation order: the keys in the order of the [table above](#keys), then `custom` in configuration order.

> [!CAUTION]
> Do not leave `debug` on in production. It writes a line per request, and those lines contain the host, path and client IP.

When `debug` is off the logger is not allocated at all and the call sites cost a single nil check; matching performance is unchanged (verified by the benchmarks in `authskipper_test.go`). Note that `debug: true` also forces every request attribute to be extracted, since the lines print them.

## Source layout

| File | Responsibility |
|---|---|
| `config.go` | Every configuration type (`Config`, `SkipRules`, `SkipRule`, `ClientTLS`), `CreateConfig`, and `RequestArgs` — the single representation of a request that rules are evaluated against — with `argsNeed`, the bit set saying which of its fields a configuration reads. |
| `conditionalforwardauth.go` | Plugin entry points (`New`, `ServeHTTP`) and all `*http.Request` handling: building `RequestArgs` (only the needed fields), cleaning the path, deriving the scheme and client IP. |
| `authskipper.go` | The `AuthSkipper` rule engine: `NewAuthSkipper` compiles and probes the rules at startup, `matchRules` evaluates a `RequestArgs` against them. Knows nothing about `net/http` requests. The request-time functions are shaped for Yaegi; the comment above `matchRules` says how and why. |
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
