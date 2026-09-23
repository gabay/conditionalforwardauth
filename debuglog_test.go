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
func newDebugPlugin(t *testing.T, rules []SkipRule) (http.Handler, *bytes.Buffer) {
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

	skipper, err := NewAuthSkipper([]SkipRule{
		{
			Expression: "{ .Host }",
			IsExactly:  []string{"a.example.com", "b.example.com"},
			EndsWith:   []string{".internal"},
		},
		{
			Expression:   "{ .Path }",
			StartsWith:   []string{"/v1/"},
			Contains:     []string{"/public/"},
			MatchesRegex: []string{`^/v[0-9]+/ping$`},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}

	newDebugLog(true, "mw").logStartup(skipper)

	want := `[conditionalforwardauth:mw] debug on, 2 skip rule(s):
[conditionalforwardauth:mw] rule[0] "{ .Host }" isExactly ["a.example.com" "b.example.com"] endsWith [".internal"]
[conditionalforwardauth:mw] rule[1] "{ .Path }" startsWith ["/v1/"] contains ["/public/"] matchesRegex ["^/v[0-9]+/ping$"]
`

	if got := buf.String(); got != want {
		t.Errorf("startup dump:\n%s\nwant:\n%s", got, want)
	}
}

func TestDebug_LogsStartupWithoutRules(t *testing.T) {
	buf := captureDebug(t)

	skipper, err := NewAuthSkipper(nil)
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
	// One rule per predicate, so the logged predicate name can be checked
	// against the one that actually fired.
	rules := []SkipRule{
		{Expression: "{ .Method } { .Host }{ .Path }", IsExactly: []string{"GET a.example.com/health"}},
		{Expression: "{ .Host }{ .Path }", StartsWith: []string{"cdn.example.com/assets/"}},
		{Expression: "{ .Host }", EndsWith: []string{".internal"}},
		{Expression: "{ .Path }", Contains: []string{"/public/"}},
		{Expression: "{ .Path }", MatchesRegex: []string{`^/v[0-9]+/ping$`}},
	}

	tests := []struct {
		name   string
		host   string
		target string
		want   string
	}{
		{
			name: "isExactly", host: "a.example.com", target: "/health",
			// No "in" clause: for isExactly the rendered value is the pattern.
			want: `skip GET http://a.example.com/health from 192.0.2.1 -> rule[0] isExactly "GET a.example.com/health"`,
		},
		{
			name: "startsWith", host: "cdn.example.com", target: "/assets/app.css",
			want: `skip GET http://cdn.example.com/assets/app.css from 192.0.2.1 -> rule[1] startsWith "cdn.example.com/assets/" in "cdn.example.com/assets/app.css"`,
		},
		{
			name: "endsWith", host: "svc.internal", target: "/x",
			want: `skip GET http://svc.internal/x from 192.0.2.1 -> rule[2] endsWith ".internal" in "svc.internal"`,
		},
		{
			name: "contains", host: "example.com", target: "/a/public/b",
			want: `skip GET http://example.com/a/public/b from 192.0.2.1 -> rule[3] contains "/public/" in "/a/public/b"`,
		},
		{
			name: "matchesRegex", host: "example.com", target: "/v2/ping",
			want: `skip GET http://example.com/v2/ping from 192.0.2.1 -> rule[4] matchesRegex "^/v[0-9]+/ping$" in "/v2/ping"`,
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
	h, buf := newDebugPlugin(t, []SkipRule{{Expression: "{ .Path }", Contains: []string{"/health"}}})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/private?redirect=/health", nil)
	req.Host = "example.com"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := buf.String(); strings.Contains(got, "redirect") {
		t.Errorf("log = %q, want no query string", got)
	}
}

// Exactly one line per request, whatever the outcome.
func TestDebug_OneLinePerRequest(t *testing.T) {
	h, buf := newDebugPlugin(t, []SkipRule{{Expression: "{ .Path }", IsExactly: []string{"/health"}}})

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
	cfg.SkipAuthWhen = []SkipRule{{Expression: "{ .Path }", IsExactly: []string{"/health"}}}
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
	d.logSkip(probeArgs, ruleMatch{predicate: predicateContains, pattern: "x", rendered: "y"})
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// Cost of the debug path itself, discarding the output. Compare with
// BenchmarkSkipAuth_EndToEnd for what debug: true actually costs per request.
func BenchmarkSkipAuth_EndToEnd_Debug(b *testing.B) {
	previous := debugOutput
	debugOutput = io.Discard

	defer func() { debugOutput = previous }()

	skipper, err := NewAuthSkipper([]SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"public.example.com"}},
		{Expression: "{ .Host }{ .Path }", StartsWith: []string{"api.example.com/v1/"}},
	})
	if err != nil {
		b.Fatalf("NewAuthSkipper: %v", err)
	}

	debug := newDebugLog(true, "mw")
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		args := newRequestArgs(req)
		if m, ok := skipper.matches(args); ok {
			debug.logSkip(args, m)
		} else {
			debug.logAuth(args)
		}
	}
}
