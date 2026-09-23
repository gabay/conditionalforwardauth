package conditionalforwardauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestPlugin wires a plugin whose auth server and next handler both count calls.
func newTestPlugin(t *testing.T, rules []SkipRule, trustForwardHeader *bool) (h http.Handler, authCalls, nextCalls *int) {
	t.Helper()

	authCalls = new(int)
	nextCalls = new(int)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*authCalls++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	cfg := CreateConfig()
	cfg.Address = server.URL
	cfg.SkipAuthWhen = rules
	cfg.TrustForwardHeader = trustForwardHeader

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { *nextCalls++ })

	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return h, authCalls, nextCalls
}

func TestSkipAuthWhen_Predicates(t *testing.T) {
	rules := []SkipRule{
		{
			Expression: "{ .Host }",
			IsExactly:  []string{"a.example.com"},
			EndsWith:   []string{".internal"},
		},
		{
			Expression: "{ .Method } { .Host }{ .Path }",
			IsExactly:  []string{"GET example.com/health"},
		},
		{
			Expression: "{ .Host }{ .Path }",
			StartsWith: []string{"cdn.example.com/assets/"},
			Contains:   []string{"/public/"},
		},
		{
			Expression:   "{ .Path }",
			MatchesRegex: []string{`^/v[0-9]+/ping$`},
		},
	}

	tests := []struct {
		name       string
		method     string
		host       string
		target     string
		expectSkip bool
	}{
		{"isExactly on host", "GET", "a.example.com", "/anything", true},
		{"isExactly is not a prefix match", "GET", "a.example.com.evil.net", "/", false},
		{"endsWith on host", "GET", "svc.internal", "/x", true},
		{"method+host+path exact", "GET", "example.com", "/health", true},
		{"same path wrong method", "POST", "example.com", "/health", false},
		{"startsWith on host+path", "GET", "cdn.example.com", "/assets/app.css", true},
		{"contains on host+path", "GET", "example.com", "/a/public/b", true},
		{"matchesRegex on path", "GET", "example.com", "/v2/ping", true},
		{"regex is anchored so no match", "GET", "example.com", "/v2/ping/extra", false},
		{"nothing matches", "GET", "example.com", "/private", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, authCalls, nextCalls := newTestPlugin(t, rules, boolPtr(true))

			req := httptest.NewRequest(tt.method, "http://"+tt.host+tt.target, nil)
			req.Host = tt.host

			h.ServeHTTP(httptest.NewRecorder(), req)

			if *nextCalls != 1 {
				t.Fatalf("next called %d times, want 1", *nextCalls)
			}
			if gotSkip := *authCalls == 0; gotSkip != tt.expectSkip {
				t.Fatalf("skip = %v, want %v (auth server called %d times)", gotSkip, tt.expectSkip, *authCalls)
			}
		})
	}
}

// Query strings and fragments must not participate in matching: the plugin
// matches on the path only, so a skip value smuggled into ?q= cannot exempt a
// protected route.
func TestSkipAuthWhen_IgnoresQueryAndFragment(t *testing.T) {
	rules := []SkipRule{{
		Expression: "{ .Host }{ .Path }",
		Contains:   []string{"/health"},
	}}

	h, authCalls, _ := newTestPlugin(t, rules, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/private?redirect=/health", nil)
	req.Host = "example.com"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if *authCalls != 1 {
		t.Fatalf("auth server called %d times, want 1: query string must not trigger a skip", *authCalls)
	}
}

// path.Clean is applied before matching, so traversal cannot be used to match a
// skip rule while the backend serves a different, protected path.
func TestSkipAuthWhen_PathTraversalCannotBypassAuth(t *testing.T) {
	rules := []SkipRule{{
		Expression: "{ .Path }",
		StartsWith: []string{"/public/"},
	}}

	h, authCalls, _ := newTestPlugin(t, rules, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/public/../admin", nil)
	req.Host = "example.com"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if *authCalls != 1 {
		t.Fatalf("auth server called %d times, want 1: /public/../admin must not match a /public/ rule", *authCalls)
	}
}

func TestSkipAuthWhen_AllSubstitutions(t *testing.T) {
	rules := []SkipRule{{
		Expression: "{ .Method }|{ .Scheme }|{ .Host }|{ .Path }|{ .UserAgent }|{ .ClientIp }",
		IsExactly:  []string{"GET|http|example.com|/x|curl/8|192.0.2.9"},
	}}

	h, authCalls, _ := newTestPlugin(t, rules, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Host = "example.com"
	req.Header.Set("User-Agent", "curl/8")
	req.RemoteAddr = "192.0.2.9:33333"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if *authCalls != 0 {
		t.Fatalf("expected skip, auth server called %d times", *authCalls)
	}
}

// X-Forwarded-* are client-supplied, so they must never influence the skip
// decision - not even when trustForwardHeader is true. .Scheme comes from the
// connection and .ClientIp from RemoteAddr, always.
func TestSkipAuthWhen_ForwardedHeadersNeverAffectMatching(t *testing.T) {
	// This rule matches only if the spoofed headers were believed.
	spoofRules := []SkipRule{{
		Expression: "{ .Scheme } { .ClientIp }",
		IsExactly:  []string{"https 203.0.113.7"},
	}}

	// This rule matches the true connection values.
	realRules := []SkipRule{{
		Expression: "{ .Scheme } { .ClientIp }",
		IsExactly:  []string{"http 10.0.0.1"},
	}}

	for _, trust := range []*bool{nil, boolPtr(false), boolPtr(true)} {
		name := "trust=unset"
		if trust != nil {
			name = fmt.Sprintf("trust=%v", *trust)
		}

		t.Run(name+"/spoofed values ignored", func(t *testing.T) {
			h, authCalls, _ := newTestPlugin(t, spoofRules, trust)
			h.ServeHTTP(httptest.NewRecorder(), spoofedRequest())

			if *authCalls != 1 {
				t.Fatalf("auth server called %d times, want 1: spoofed X-Forwarded-* must not cause a skip", *authCalls)
			}
		})

		t.Run(name+"/connection values used", func(t *testing.T) {
			h, authCalls, _ := newTestPlugin(t, realRules, trust)
			h.ServeHTTP(httptest.NewRecorder(), spoofedRequest())

			if *authCalls != 0 {
				t.Fatalf("auth server called %d times, want 0: connection values should match", *authCalls)
			}
		})
	}
}

// spoofedRequest is a plaintext request from 10.0.0.1 that claims, via headers,
// to be HTTPS from 203.0.113.7.
func spoofedRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Host = "example.com"
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	return req
}

func TestSkipAuthWhen_IPv6ClientIP(t *testing.T) {
	rules := []SkipRule{{
		Expression: "{ .ClientIp }",
		IsExactly:  []string{"2001:db8::1"},
	}}

	h, authCalls, _ := newTestPlugin(t, rules, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Host = "example.com"
	req.RemoteAddr = "[2001:db8::1]:54321"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if *authCalls != 0 {
		t.Fatalf("expected skip for IPv6 client, auth server called %d times", *authCalls)
	}
}

func TestSkipAuthWhen_ConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name:    "missing expression",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: []SkipRule{{IsExactly: []string{"x"}}}},
			wantErr: "expression is required",
		},
		{
			name:    "no predicates",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: []SkipRule{{Expression: "{ .Host }"}}},
			wantErr: "at least one of",
		},
		{
			name:    "unparseable template",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: []SkipRule{{Expression: "{ .Host", IsExactly: []string{"x"}}}},
			wantErr: "invalid expression",
		},
		{
			name:    "unknown substitution",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: []SkipRule{{Expression: "{ .Hsot }", IsExactly: []string{"x"}}}},
			wantErr: "cannot be evaluated",
		},
		{
			name:    "invalid regex",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: []SkipRule{{Expression: "{ .Host }", MatchesRegex: []string{"["}}}},
			wantErr: "invalid matchesRegex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), tt.cfg, "test")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestSkipAuthWhen_NoRulesAlwaysAuthenticates(t *testing.T) {
	h, authCalls, _ := newTestPlugin(t, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/anything", nil)
	req.Host = "example.com"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if *authCalls != 1 {
		t.Fatalf("auth server called %d times, want 1", *authCalls)
	}
}

func TestCreateConfig(t *testing.T) {
	c := CreateConfig()

	if c.MaxBodySize == nil || *c.MaxBodySize != 4194304 {
		t.Errorf("MaxBodySize = %v, want 4194304", c.MaxBodySize)
	}
	if c.MaxResponseBodySize == nil || *c.MaxResponseBodySize != -1 {
		t.Errorf("MaxResponseBodySize = %v, want -1", c.MaxResponseBodySize)
	}
}

func TestCleanPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "/"},
		{"/", "/"},
		{"/a/b", "/a/b"},
		{"/a/b/", "/a/b"},
		{"/public/../admin", "/admin"},
		{"/a/./b", "/a/b"},
	}

	for _, tt := range tests {
		if got := cleanPath(tt.in); got != tt.want {
			t.Errorf("cleanPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Request -> RequestArgs extraction
// ---------------------------------------------------------------------------

func TestNewRequestArgs(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/a/b?x=1#frag", nil)
	req.Host = "example.com:8080"
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.RemoteAddr = "198.51.100.4:9999"

	got := newRequestArgs(req)

	want := RequestArgs{
		Host:      "example.com:8080",
		Path:      "/a/b",
		Method:    http.MethodPost,
		Scheme:    "http",
		UserAgent: "test-agent/1.0",
		ClientIp:  "198.51.100.4",
	}

	if got != want {
		t.Errorf("newRequestArgs() = %+v, want %+v", got, want)
	}

	// Query and fragment must not leak into any substitution.
	for name, v := range map[string]string{
		"Host": got.Host, "Path": got.Path, "Method": got.Method,
		"Scheme": got.Scheme, "UserAgent": got.UserAgent, "ClientIp": got.ClientIp,
	} {
		if strings.Contains(v, "x=1") || strings.Contains(v, "frag") {
			t.Errorf("%s = %q leaks query or fragment", name, v)
		}
	}
}

func TestRequestScheme(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	plain.Header.Set("X-Forwarded-Proto", "https") // must be ignored
	if got := requestScheme(plain); got != "http" {
		t.Errorf("requestScheme(plain) = %q, want %q", got, "http")
	}

	tls := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	if got := requestScheme(tls); got != "https" {
		t.Errorf("requestScheme(tls) = %q, want %q", got, "https")
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"ipv4", "192.0.2.5:1234", "", "192.0.2.5"},
		{"ipv6", "[2001:db8::1]:54321", "", "2001:db8::1"},
		{"no port falls back to raw value", "192.0.2.5", "", "192.0.2.5"},
		{"x-forwarded-for is ignored", "192.0.2.5:1234", "203.0.113.9", "192.0.2.5"},
		{"spoofed xff list is ignored", "192.0.2.5:1234", "203.0.113.9, 198.51.100.1", "192.0.2.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			if got := clientIP(req); got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmarks for the per-request work done before any rule is evaluated.
// ---------------------------------------------------------------------------

func benchRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1/users?page=2", nil)
	req.Host = "api.example.com"
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = "192.0.2.10:44444"
	return req
}

func BenchmarkNewRequestArgs(b *testing.B) {
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = newRequestArgs(req)
	}
}

// End-to-end skip decision, including RequestArgs extraction.
func BenchmarkSkipAuth_EndToEnd(b *testing.B) {
	skipper, err := NewAuthSkipper([]SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"public.example.com"}},
		{Expression: "{ .Host }{ .Path }", StartsWith: []string{"api.example.com/v1/"}},
	})
	if err != nil {
		b.Fatalf("NewAuthSkipper: %v", err)
	}

	plugin := &ConditionalForwardAuth{skipper: *skipper}
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = !plugin.skipper.empty() && plugin.skipper.ShouldSkip(newRequestArgs(req))
	}
}

// Deployments without exemptions must not pay for RequestArgs extraction.
func BenchmarkSkipAuth_NoRules(b *testing.B) {
	skipper, err := NewAuthSkipper(nil)
	if err != nil {
		b.Fatalf("NewAuthSkipper: %v", err)
	}

	plugin := &ConditionalForwardAuth{skipper: *skipper}
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = !plugin.skipper.empty() && plugin.skipper.ShouldSkip(newRequestArgs(req))
	}
}

// boolPtr is defined in forwardauth_test.go.
