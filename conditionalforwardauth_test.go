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
func newTestPlugin(t *testing.T, rules SkipRules, trustForwardHeader *bool) (h http.Handler, authCalls, nextCalls *int) {
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
	// Every predicate is exercised, spread over the predefined keys where one
	// fits and over a custom template where the expression is genuinely
	// composite, so that both code paths are covered end-to-end.
	rules := SkipRules{
		Host: &SkipRule{
			IsExactly: []string{"a.example.com"},
			EndsWith:  []string{".internal"},
		},
		Path: &SkipRule{
			MatchesRegex: []string{`^/v[0-9]+/ping$`},
		},
		URL: &SkipRule{
			StartsWith: []string{"cdn.example.com/assets/"},
			Contains:   []string{"/public/"},
		},
		Custom: []SkipRule{{
			Expression: "{ .Method } { .Host }{ .Path }",
			IsExactly:  []string{"GET example.com/health"},
		}},
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
		{"startsWith on url", "GET", "cdn.example.com", "/assets/app.css", true},
		{"contains on url", "GET", "example.com", "/a/public/b", true},
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
	rules := SkipRules{URL: &SkipRule{Contains: []string{"/health"}}}

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
	rules := SkipRules{Path: &SkipRule{StartsWith: []string{"/public/"}}}

	h, authCalls, _ := newTestPlugin(t, rules, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/public/../admin", nil)
	req.Host = "example.com"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if *authCalls != 1 {
		t.Fatalf("auth server called %d times, want 1: /public/../admin must not match a /public/ rule", *authCalls)
	}
}

// A custom template may reference every RequestArgs field, and a custom rule
// must therefore have all of them populated at request time.
func TestSkipAuthWhen_AllSubstitutions(t *testing.T) {
	rules := SkipRules{Custom: []SkipRule{{
		Expression: "{ .Method }|{ .Scheme }|{ .Host }|{ .Path }|{ .UserAgent }|{ .ClientIp }",
		IsExactly:  []string{"GET|http|example.com|/x|curl/8|192.0.2.9"},
	}}}

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
	spoofRules := SkipRules{Custom: []SkipRule{{
		Expression: "{ .Scheme } { .ClientIp }",
		IsExactly:  []string{"https 203.0.113.7"},
	}}}

	// This rule matches the true connection values.
	realRules := SkipRules{Custom: []SkipRule{{
		Expression: "{ .Scheme } { .ClientIp }",
		IsExactly:  []string{"http 10.0.0.1"},
	}}}

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
	rules := SkipRules{ClientIP: &SkipRule{IsExactly: []string{"2001:db8::1"}}}

	h, authCalls, _ := newTestPlugin(t, rules, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Host = "example.com"
	req.RemoteAddr = "[2001:db8::1]:54321"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if *authCalls != 0 {
		t.Fatalf("expected skip for IPv6 client, auth server called %d times", *authCalls)
	}
}

// inSubnet is the one predicate that is not a string comparison, so it gets
// its own end-to-end check: the decision has to hold for the address formats
// RemoteAddr actually takes, including the bracketed IPv6 form.
func TestSkipAuthWhen_ClientIPInSubnet(t *testing.T) {
	rules := SkipRules{ClientIP: &SkipRule{
		InSubnet: []string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32"},
	}}

	tests := []struct {
		name       string
		remoteAddr string
		expectSkip bool
	}{
		{"ipv4 cidr hit", "10.1.2.3:1234", true},
		{"ipv4 cidr miss", "11.0.0.1:1234", false},
		{"bare address hit", "192.0.2.7:1234", true},
		{"bare address is a single host", "192.0.2.8:1234", false},
		{"ipv6 cidr hit", "[2001:db8::1]:54321", true},
		{"ipv6 cidr miss", "[2001:db9::1]:54321", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, authCalls, nextCalls := newTestPlugin(t, rules, nil)

			req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
			req.Host = "example.com"
			req.RemoteAddr = tt.remoteAddr

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

func TestSkipAuthWhen_ConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name:    "custom missing expression",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: SkipRules{Custom: []SkipRule{{IsExactly: []string{"x"}}}}},
			wantErr: "skipAuthWhen.custom[0]: expression is required",
		},
		{
			name:    "no predicates",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: SkipRules{Host: &SkipRule{}}},
			wantErr: "skipAuthWhen.host: at least one of",
		},
		{
			name:    "unparseable template",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: SkipRules{Custom: []SkipRule{{Expression: "{ .Host", IsExactly: []string{"x"}}}}},
			wantErr: "invalid expression",
		},
		{
			name:    "unknown substitution",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: SkipRules{Custom: []SkipRule{{Expression: "{ .Hsot }", IsExactly: []string{"x"}}}}},
			wantErr: "cannot be evaluated",
		},
		{
			name:    "invalid regex",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: SkipRules{Host: &SkipRule{MatchesRegex: []string{"["}}}},
			wantErr: "skipAuthWhen.host: invalid matchesRegex",
		},
		{
			// The error names the offending entry, not just "custom".
			name: "invalid regex in second custom rule",
			cfg: &Config{Address: "http://auth", SkipAuthWhen: SkipRules{Custom: []SkipRule{
				{Expression: "{ .Host }", IsExactly: []string{"x"}},
				{Expression: "{ .Host }", MatchesRegex: []string{"["}},
			}}},
			wantErr: "skipAuthWhen.custom[1]: invalid matchesRegex",
		},
		{
			// A predefined key already names what is tested; an expression
			// under it is a sign the operator meant custom.
			name:    "expression under host",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: SkipRules{Host: &SkipRule{Expression: "{ .Host }", IsExactly: []string{"x"}}}},
			wantErr: "skipAuthWhen.host: expression is only valid under custom",
		},
		{
			// inSubnet on a path is meaningless and must not be silently
			// ignored, which would leave the operator believing a network
			// exemption is in place.
			name:    "inSubnet under path",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: SkipRules{Path: &SkipRule{InSubnet: []string{"10.0.0.0/8"}}}},
			wantErr: "skipAuthWhen.path: inSubnet is only valid under clientIp",
		},
		{
			name:    "invalid inSubnet",
			cfg:     &Config{Address: "http://auth", SkipAuthWhen: SkipRules{ClientIP: &SkipRule{InSubnet: []string{"10.0.0.0/33"}}}},
			wantErr: `skipAuthWhen.clientIp: invalid inSubnet "10.0.0.0/33"`,
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
	h, authCalls, _ := newTestPlugin(t, SkipRules{}, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/anything", nil)
	req.Host = "example.com"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if *authCalls != 1 {
		t.Fatalf("auth server called %d times, want 1", *authCalls)
	}
}

// New derives from the rules which RequestArgs fields ServeHTTP extracts. This
// is what makes a predefined key cheaper than a custom template, and what lets
// a deployment without exemptions skip request inspection altogether.
func TestNew_ComputesNeed(t *testing.T) {
	tests := []struct {
		name  string
		rules SkipRules
		debug bool
		want  argsNeed
	}{
		{"no rules", SkipRules{}, false, needNone},
		{"host only", SkipRules{Host: &SkipRule{IsExactly: []string{"a"}}}, false, needHost},
		{"path only", SkipRules{Path: &SkipRule{IsExactly: []string{"/a"}}}, false, needPath},
		{"url", SkipRules{URL: &SkipRule{IsExactly: []string{"a/b"}}}, false, needHost | needPath},
		{"clientIp", SkipRules{ClientIP: &SkipRule{InSubnet: []string{"10.0.0.0/8"}}}, false, needClientIP},
		{"userAgent", SkipRules{UserAgent: &SkipRule{Contains: []string{"bot"}}}, false, needUserAgent},
		{
			"host and clientIp are unioned",
			SkipRules{Host: &SkipRule{IsExactly: []string{"a"}}, ClientIP: &SkipRule{IsExactly: []string{"b"}}},
			false, needHost | needClientIP,
		},
		{"custom needs everything", SkipRules{Custom: []SkipRule{{Expression: "{ .Host }", IsExactly: []string{"a"}}}}, false, needAll},
		// A debug line prints the request, so debug forces full extraction
		// even when no rule reads anything.
		{"no rules with debug", SkipRules{}, true, needAll},
		{"host only with debug", SkipRules{Host: &SkipRule{IsExactly: []string{"a"}}}, true, needAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.Address = "http://auth"
			cfg.SkipAuthWhen = tt.rules
			cfg.Debug = tt.debug

			h, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			plugin, ok := h.(*ConditionalForwardAuth)
			if !ok {
				t.Fatalf("New returned %T, want *ConditionalForwardAuth", h)
			}
			if plugin.need != tt.want {
				t.Errorf("need = %06b, want %06b", plugin.need, tt.want)
			}
		})
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

	got := newRequestArgs(req, needAll)

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

// Only the requested fields are extracted; the rest stay at their zero value.
// A rule never reads a field it did not ask for, so leaving the others empty
// is both safe and the point: it is where the per-request saving comes from.
func TestNewRequestArgs_OnlyRequestedFields(t *testing.T) {
	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "http://example.com/a/b", nil)
		req.Host = "example.com:8080"
		req.Header.Set("User-Agent", "test-agent/1.0")
		req.RemoteAddr = "198.51.100.4:9999"
		return req
	}

	tests := []struct {
		name string
		need argsNeed
		want RequestArgs
	}{
		{"none", needNone, RequestArgs{}},
		{"host", needHost, RequestArgs{Host: "example.com:8080"}},
		{"path", needPath, RequestArgs{Path: "/a/b"}},
		{"method", needMethod, RequestArgs{Method: http.MethodPost}},
		{"scheme", needScheme, RequestArgs{Scheme: "http"}},
		{"userAgent", needUserAgent, RequestArgs{UserAgent: "test-agent/1.0"}},
		{"clientIp", needClientIP, RequestArgs{ClientIp: "198.51.100.4"}},
		{"host and path", needHost | needPath, RequestArgs{Host: "example.com:8080", Path: "/a/b"}},
		{
			"all", needAll,
			RequestArgs{
				Host: "example.com:8080", Path: "/a/b", Method: http.MethodPost,
				Scheme: "http", UserAgent: "test-agent/1.0", ClientIp: "198.51.100.4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newRequestArgs(newReq(), tt.need); got != tt.want {
				t.Errorf("newRequestArgs(req, %06b) = %+v, want %+v", tt.need, got, tt.want)
			}
		})
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

	// An absolute-form request line, "GET https://example.com/ HTTP/1.1",
	// sent over plaintext leaves req.URL.Scheme = "https" with no TLS state.
	// The scheme is client-supplied there and must not be believed.
	// httptest.NewRequest sets both TLS and URL.Scheme for an https URL, so
	// TLS is cleared by hand to reproduce what the server would see.
	spoofed := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	spoofed.TLS = nil
	if got := requestScheme(spoofed); got != "http" {
		t.Errorf("requestScheme(absolute-form over plaintext) = %q, want %q", got, "http")
	}
}

// End-to-end version of the absolute-form check: a { .Scheme } exemption for
// https must not be satisfiable by writing "https://" into the request line.
func TestSkipAuthWhen_SchemeFromRequestLineIsIgnored(t *testing.T) {
	rules := SkipRules{Custom: []SkipRule{{
		Expression: "{ .Scheme }",
		IsExactly:  []string{"https"},
	}}}

	h, authCalls, _ := newTestPlugin(t, rules, nil)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/metrics", nil)
	req.TLS = nil // plaintext connection carrying an absolute-form target
	req.Host = "example.com"

	h.ServeHTTP(httptest.NewRecorder(), req)

	if *authCalls != 1 {
		t.Fatalf("auth server called %d times, want 1: request-line scheme must not cause a skip", *authCalls)
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

// Full extraction, which is what a custom rule or debug: true pays.
func BenchmarkNewRequestArgs(b *testing.B) {
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = newRequestArgs(req, needAll)
	}
}

// Extraction for the cheapest configuration: a single host rule.
func BenchmarkNewRequestArgs_HostOnly(b *testing.B) {
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = newRequestArgs(req, needHost)
	}
}

// End-to-end skip decision with predefined keys, including RequestArgs
// extraction. Compare with BenchmarkSkipAuth_EndToEnd_Custom, which expresses
// the same two rules as templates.
func BenchmarkSkipAuth_EndToEnd(b *testing.B) {
	skipper, err := NewAuthSkipper(SkipRules{
		Host: &SkipRule{IsExactly: []string{"public.example.com"}},
		URL:  &SkipRule{StartsWith: []string{"api.example.com/v1/"}},
	})
	if err != nil {
		b.Fatalf("NewAuthSkipper: %v", err)
	}

	plugin := &ConditionalForwardAuth{skipper: *skipper, need: skipper.need}
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = plugin.need != needNone && plugin.skipper.ShouldSkip(newRequestArgs(req, plugin.need))
	}
}

// The same decision as BenchmarkSkipAuth_EndToEnd, written as custom templates:
// every RequestArgs field is extracted and each template is rendered per
// request. The gap between the two is what the predefined keys buy.
func BenchmarkSkipAuth_EndToEnd_Custom(b *testing.B) {
	skipper, err := NewAuthSkipper(SkipRules{Custom: []SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"public.example.com"}},
		{Expression: "{ .Host }{ .Path }", StartsWith: []string{"api.example.com/v1/"}},
	}})
	if err != nil {
		b.Fatalf("NewAuthSkipper: %v", err)
	}

	plugin := &ConditionalForwardAuth{skipper: *skipper, need: skipper.need}
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = plugin.need != needNone && plugin.skipper.ShouldSkip(newRequestArgs(req, plugin.need))
	}
}

// Deployments without exemptions must not pay for RequestArgs extraction.
func BenchmarkSkipAuth_NoRules(b *testing.B) {
	skipper, err := NewAuthSkipper(SkipRules{})
	if err != nil {
		b.Fatalf("NewAuthSkipper: %v", err)
	}

	plugin := &ConditionalForwardAuth{skipper: *skipper, need: skipper.need}
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = plugin.need != needNone && plugin.skipper.ShouldSkip(newRequestArgs(req, plugin.need))
	}
}

// boolPtr is defined in forwardauth_test.go.
