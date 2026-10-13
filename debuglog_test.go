package conditionalforwardauth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureDebug redirects debug output into a buffer for the duration of a test.
func captureDebug(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer

	previous := debugOutput
	debugOutput = &buf
	t.Cleanup(func() { debugOutput = previous })

	return &buf
}

// newDebugPlugin builds a plugin with debug on and returns it alongside the
// captured output, which is reset so the caller sees only request lines.
func newDebugPlugin(t *testing.T, rules SkipRules) (http.Handler, *bytes.Buffer) {
	t.Helper()

	buf := captureDebug(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	cfg := CreateConfig()
	cfg.Address = server.URL
	cfg.SkipAuthWhen = rules
	cfg.Debug = true

	h, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "mw")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	buf.Reset()

	return h, buf
}

// ---------------------------------------------------------------------------
// Startup dump
// ---------------------------------------------------------------------------

func TestDebug_LogsRulesAtStartup(t *testing.T) {
	buf := captureDebug(t)

	// Declared out of evaluation order on purpose: the dump must follow the
	// order rules are tested in (host, path, url, clientIp, userAgent, then
	// custom), not the order they happen to be written in, so that an
	// operator reading it can tell which rule wins a request.
	skipper, err := NewAuthSkipper(SkipRules{
		Custom: []SkipRule{{
			Expression: "{ .Method } { .Host }{ .Path }",
			IsExactly:  []string{"GET example.com/health"},
		}},
		ClientIP: &SkipRule{
			IsExactly: []string{"127.0.0.1"},
			InSubnet:  []string{"10.0.0.0/8", "2001:db8::/32"},
		},
		Path: &SkipRule{
			StartsWith:   []string{"/v1/"},
			Contains:     []string{"/public/"},
			MatchesRegex: []string{`^/v[0-9]+/ping$`},
		},
		Host: &SkipRule{
			IsExactly: []string{"a.example.com", "b.example.com"},
			EndsWith:  []string{".internal"},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}

	newDebugLog(true, "mw").logStartup(skipper)

	// Only custom rules carry an expression, so only they print one.
	want := `[conditionalforwardauth:mw] debug on, 4 skip rule(s):
[conditionalforwardauth:mw] host isExactly ["a.example.com" "b.example.com"] endsWith [".internal"]
[conditionalforwardauth:mw] path startsWith ["/v1/"] contains ["/public/"] matchesRegex ["^/v[0-9]+/ping$"]
[conditionalforwardauth:mw] clientIp isExactly ["127.0.0.1"] inSubnet ["10.0.0.0/8" "2001:db8::/32"]
[conditionalforwardauth:mw] custom[0] "{ .Method } { .Host }{ .Path }" isExactly ["GET example.com/health"]
`

	if got := buf.String(); got != want {
		t.Errorf("startup dump:\n%s\nwant:\n%s", got, want)
	}
}

func TestDebug_LogsStartupWithoutRules(t *testing.T) {
	buf := captureDebug(t)

	skipper, err := NewAuthSkipper(SkipRules{})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}

	newDebugLog(true, "mw").logStartup(skipper)

	want := "[conditionalforwardauth:mw] debug on, no skip rules: every request goes to forward auth\n"
	if got := buf.String(); got != want {
		t.Errorf("startup dump = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Per-request lines
// ---------------------------------------------------------------------------

func TestDebug_LogsRequestResolution(t *testing.T) {
	// One predicate per rule, so the logged rule and predicate names can be
	// checked against the ones that actually fired.
	rules := SkipRules{
		Host:      &SkipRule{EndsWith: []string{".internal"}},
		Path:      &SkipRule{Contains: []string{"/public/"}},
		URL:       &SkipRule{StartsWith: []string{"cdn.example.com/assets/"}},
		ClientIP:  &SkipRule{InSubnet: []string{"10.0.0.0/8"}},
		UserAgent: &SkipRule{MatchesRegex: []string{`^kube-probe/`}},
		Custom: []SkipRule{
			{Expression: "{ .Method } { .Host }{ .Path }", IsExactly: []string{"GET a.example.com/health"}},
		},
	}

	tests := []struct {
		name       string
		host       string
		target     string
		remoteAddr string
		userAgent  string
		want       string
	}{
		{
			name: "isExactly", host: "a.example.com", target: "/health",
			// No "in" clause: for isExactly the tested value is the pattern.
			want: `skip GET http://a.example.com/health from 192.0.2.1 -> custom[0] isExactly "GET a.example.com/health"`,
		},
		{
			name: "startsWith", host: "cdn.example.com", target: "/assets/app.css",
			want: `skip GET http://cdn.example.com/assets/app.css from 192.0.2.1 -> url startsWith "cdn.example.com/assets/" in "cdn.example.com/assets/app.css"`,
		},
		{
			name: "endsWith", host: "svc.internal", target: "/x",
			want: `skip GET http://svc.internal/x from 192.0.2.1 -> host endsWith ".internal" in "svc.internal"`,
		},
		{
			name: "contains", host: "example.com", target: "/a/public/b",
			want: `skip GET http://example.com/a/public/b from 192.0.2.1 -> path contains "/public/" in "/a/public/b"`,
		},
		{
			name: "matchesRegex", host: "example.com", target: "/x", userAgent: "kube-probe/1.29",
			want: `skip GET http://example.com/x from 192.0.2.1 -> userAgent matchesRegex "^kube-probe/" in "kube-probe/1.29"`,
		},
		{
			// The pattern is the network as configured and the value the
			// peer address, so an operator can see which range caught it.
			name: "inSubnet", host: "example.com", target: "/x", remoteAddr: "10.1.2.3:4567",
			want: `skip GET http://example.com/x from 10.1.2.3 -> clientIp inSubnet "10.0.0.0/8" in "10.1.2.3"`,
		},
		{
			name: "no rule matches", host: "example.com", target: "/private",
			want: `auth GET http://example.com/private from 192.0.2.1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, buf := newDebugPlugin(t, rules)

			req := httptest.NewRequest(http.MethodGet, "http://"+tt.host+tt.target, nil)
			req.Host = tt.host
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}

			h.ServeHTTP(httptest.NewRecorder(), req)

			want := "[conditionalforwardauth:mw] " + tt.want + "\n"
			if got := buf.String(); got != want {
				t.Errorf("log = %q\nwant  %q", got, want)
			}
		})
	}
}

// The query string is not matched on, so it must not appear in the log either:
// a debug line has to describe what was actually tested.
func TestDebug_RequestLineOmitsQuery(t *testing.T) {
	h, buf := newDebugPlugin(t, SkipRules{Path: &SkipRule{Contains: []string{"/health"}}})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/private?redirect=/health", nil)
	req.Host = "example.com"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := buf.String(); strings.Contains(got, "redirect") {
		t.Errorf("log = %q, want no query string", got)
	}
}

// Exactly one line per request, whatever the outcome.
func TestDebug_OneLinePerRequest(t *testing.T) {
	h, buf := newDebugPlugin(t, SkipRules{Path: &SkipRule{IsExactly: []string{"/health"}}})

	for _, target := range []string{"/health", "/private", "/health"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+target, nil)
		req.Host = "example.com"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	if got := strings.Count(buf.String(), "\n"); got != 3 {
		t.Errorf("logged %d lines for 3 requests, want 3:\n%s", got, buf)
	}
}

// ---------------------------------------------------------------------------
// Disabled
// ---------------------------------------------------------------------------

func TestDebug_DisabledWritesNothing(t *testing.T) {
	buf := captureDebug(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	cfg := CreateConfig()
	cfg.Address = server.URL
	cfg.SkipAuthWhen = SkipRules{Path: &SkipRule{IsExactly: []string{"/health"}}}
	// cfg.Debug stays false.

	h, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "mw")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The disabled state is a nil *debugLog, which is what makes the call
	// sites free; assert it rather than only its visible effect.
	plugin, ok := h.(*ConditionalForwardAuth)
	if !ok {
		t.Fatalf("New returned %T, want *ConditionalForwardAuth", h)
	}
	if plugin.debug != nil {
		t.Error("debug logger was created while debug is false")
	}

	for _, target := range []string{"/health", "/private"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+target, nil)
		req.Host = "example.com"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	if buf.Len() != 0 {
		t.Errorf("debug output = %q, want nothing", buf.String())
	}
}

// A nil *debugLog must absorb every call rather than panic: that is how
// `debug: false` is implemented.
func TestDebug_NilLoggerIsSafe(t *testing.T) {
	var d *debugLog

	d.printf("ignored %d", 1)
	d.logStartup(&AuthSkipper{})
	d.logAuth(probeArgs)
	d.logSkip(probeArgs, ruleMatch{rule: "host", predicate: predicateContains, pattern: "x", value: "y"})
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// Cost of the debug path itself, discarding the output. Compare with
// BenchmarkSkipAuth_EndToEnd for what debug: true actually costs per request.
// Debug forces full extraction (needAll) regardless of the rules, exactly as
// New does.
func BenchmarkSkipAuth_EndToEnd_Debug(b *testing.B) {
	previous := debugOutput
	debugOutput = io.Discard

	defer func() { debugOutput = previous }()

	skipper, err := NewAuthSkipper(SkipRules{
		Host: &SkipRule{IsExactly: []string{"public.example.com"}},
		URL:  &SkipRule{StartsWith: []string{"api.example.com/v1/"}},
	})
	if err != nil {
		b.Fatalf("NewAuthSkipper: %v", err)
	}

	debug := newDebugLog(true, "mw")
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		args := newRequestArgs(req, needAll)
		if m, ok := matchRules(skipper, args); ok {
			debug.logSkip(args, m)
		} else {
			debug.logAuth(args)
		}
	}
}
