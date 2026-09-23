package conditionalforwardauth

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"text/template"
)

// benchArgs is the request the matching benchmarks and several tests run
// against. It mirrors what newRequestArgs would produce for
// "GET http://api.example.com/v1/users?page=2".
func benchArgs() RequestArgs {
	return RequestArgs{
		Host:      "api.example.com",
		Path:      "/v1/users",
		Method:    http.MethodGet,
		Scheme:    "http",
		UserAgent: "Mozilla/5.0",
		ClientIp:  "192.0.2.10",
	}
}

// ---------------------------------------------------------------------------
// NewAuthSkipper
// ---------------------------------------------------------------------------

func TestNewAuthSkipper_Valid(t *testing.T) {
	rules := []SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"a.example.com", "b.example.com"}},
		{Expression: "{ .Path }", MatchesRegex: []string{`^/v[0-9]+/ping$`}},
		{Expression: "{ .Host }{ .Path }", Contains: []string{"/public/"}},
	}

	skipper, err := NewAuthSkipper(rules)
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}
	if len(skipper.rules) != len(rules) {
		t.Fatalf("compiled %d rules, want %d", len(skipper.rules), len(rules))
	}

	// isExactly must become a lookup map, not a slice scan.
	if got := len(skipper.rules[0].isExactly); got != 2 {
		t.Errorf("isExactly map has %d entries, want 2", got)
	}
	if _, ok := skipper.rules[0].isExactly["a.example.com"]; !ok {
		t.Error("isExactly map missing a.example.com")
	}
	if len(skipper.rules[1].regexes) != 1 {
		t.Errorf("compiled %d regexes, want 1", len(skipper.rules[1].regexes))
	}
}

func TestNewAuthSkipper_Errors(t *testing.T) {
	tests := []struct {
		name    string
		rule    SkipRule
		wantErr string
	}{
		{"empty expression", SkipRule{IsExactly: []string{"x"}}, "expression is required"},
		{"whitespace expression", SkipRule{Expression: "   ", IsExactly: []string{"x"}}, "expression is required"},
		{"unterminated action", SkipRule{Expression: "{ .Host", IsExactly: []string{"x"}}, "invalid expression"},
		// Expressions use single braces; the text/template default must not be
		// accepted silently, or a copied {{ }} rule would never match and the
		// route would stay authenticated with no signal.
		{"old {{ }} syntax", SkipRule{Expression: "{{ .Host }}", IsExactly: []string{"x"}}, "invalid expression"},
		{"unknown field", SkipRule{Expression: "{ .Nope }", IsExactly: []string{"x"}}, "cannot be evaluated"},
		// RequestArgs has exactly one spelling per field, so the lowercase form
		// that a map-based implementation would have accepted is now an error.
		{"lowercase field", SkipRule{Expression: "{ .host }", IsExactly: []string{"x"}}, "cannot be evaluated"},
		{"no predicates", SkipRule{Expression: "{ .Host }"}, "at least one of"},
		{"bad regex", SkipRule{Expression: "{ .Host }", MatchesRegex: []string{"[unclosed"}}, "invalid matchesRegex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthSkipper([]SkipRule{tt.rule})
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
			// The index must be reported so the operator can find the offending rule.
			if !strings.Contains(err.Error(), "skipAuthWhen[0]") {
				t.Errorf("error %q should identify the rule index", err)
			}
		})
	}
}

func TestNewAuthSkipper_ReportsCorrectRuleIndex(t *testing.T) {
	_, err := NewAuthSkipper([]SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"ok"}},
		{Expression: "{ .Host }", IsExactly: []string{"ok"}},
		{Expression: "{ .Host }", MatchesRegex: []string{"("}},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "skipAuthWhen[2]") {
		t.Errorf("error = %q, want it to point at index 2", err)
	}
}

func TestNewAuthSkipper_Empty(t *testing.T) {
	skipper, err := NewAuthSkipper(nil)
	if err != nil {
		t.Fatalf("NewAuthSkipper(nil): %v", err)
	}
	if !skipper.empty() {
		t.Errorf("compiled %d rules, want 0", len(skipper.rules))
	}
	if skipper.ShouldSkip(benchArgs()) {
		t.Error("ShouldSkip() = true with no rules, want false")
	}
}

// ---------------------------------------------------------------------------
// ShouldSkip / matches
// ---------------------------------------------------------------------------

func TestAuthSkipper_ShouldSkip(t *testing.T) {
	args := benchArgs()
	args.Scheme = "https"
	args.UserAgent = "curl/8"
	args.ClientIp = "192.0.2.1"

	tests := []struct {
		name string
		rule SkipRule
		want bool
	}{
		{"isExactly hit", SkipRule{Expression: "{ .Host }", IsExactly: []string{"api.example.com"}}, true},
		{"isExactly miss", SkipRule{Expression: "{ .Host }", IsExactly: []string{"other.example.com"}}, false},
		{"isExactly is not substring", SkipRule{Expression: "{ .Host }", IsExactly: []string{"example.com"}}, false},
		{"isExactly second value", SkipRule{Expression: "{ .Host }", IsExactly: []string{"a", "api.example.com"}}, true},
		{"startsWith hit", SkipRule{Expression: "{ .Path }", StartsWith: []string{"/v1/"}}, true},
		{"startsWith miss", SkipRule{Expression: "{ .Path }", StartsWith: []string{"/v2/"}}, false},
		{"endsWith hit", SkipRule{Expression: "{ .Host }", EndsWith: []string{".example.com"}}, true},
		{"endsWith miss", SkipRule{Expression: "{ .Host }", EndsWith: []string{".example.org"}}, false},
		{"contains hit", SkipRule{Expression: "{ .Path }", Contains: []string{"users"}}, true},
		{"contains miss", SkipRule{Expression: "{ .Path }", Contains: []string{"admin"}}, false},
		{"regex hit", SkipRule{Expression: "{ .Path }", MatchesRegex: []string{`^/v\d+/users$`}}, true},
		{"regex miss", SkipRule{Expression: "{ .Path }", MatchesRegex: []string{`^/admin`}}, false},
		{"regex is partial by default", SkipRule{Expression: "{ .Path }", MatchesRegex: []string{`users`}}, true},
		{"case sensitive", SkipRule{Expression: "{ .Host }", IsExactly: []string{"API.EXAMPLE.COM"}}, false},
		{"any predicate may match", SkipRule{
			Expression: "{ .Host }",
			IsExactly:  []string{"nope"},
			EndsWith:   []string{".example.com"},
		}, true},
		{"composite expression", SkipRule{
			Expression: "{ .Method } { .Scheme }://{ .Host }{ .Path }",
			IsExactly:  []string{"GET https://api.example.com/v1/users"},
		}, true},
		{"method substitution", SkipRule{Expression: "{ .Method }", IsExactly: []string{"GET"}}, true},
		{"userAgent substitution", SkipRule{Expression: "{ .UserAgent }", StartsWith: []string{"curl/"}}, true},
		{"clientIp substitution", SkipRule{Expression: "{ .ClientIp }", IsExactly: []string{"192.0.2.1"}}, true},
		{"literal expression with no substitution", SkipRule{Expression: "constant", IsExactly: []string{"constant"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipper, err := NewAuthSkipper([]SkipRule{tt.rule})
			if err != nil {
				t.Fatalf("NewAuthSkipper: %v", err)
			}
			if got := skipper.ShouldSkip(args); got != tt.want {
				t.Errorf("ShouldSkip() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Rules are OR-ed: any one of them is enough to exempt the request.
func TestAuthSkipper_ShouldSkip_AnyRuleMatches(t *testing.T) {
	skipper, err := NewAuthSkipper([]SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"nope.example.com"}},
		{Expression: "{ .Path }", StartsWith: []string{"/nope"}},
		{Expression: "{ .Method }", IsExactly: []string{"GET"}},
	})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}

	if !skipper.ShouldSkip(benchArgs()) {
		t.Error("ShouldSkip() = false, want true (third rule matches)")
	}
}

// A template that fails at request time must not match: failing closed means
// the request gets authenticated rather than silently exempted.
//
// NewAuthSkipper rejects such an expression at startup, so the rule is built by
// hand here to exercise the request-time guard.
func TestCompiledSkipRule_MatchesFailsClosedOnRenderError(t *testing.T) {
	// Same delimiters as NewAuthSkipper, or { .Nope } would be inert literal
	// text that renders without error.
	tmpl, err := template.New("bad").Delims(leftDelim, rightDelim).Parse("{ .Nope }")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	rule := &compiledSkipRule{
		source: SkipRule{
			Expression: "{ .Nope }",
			Contains:   []string{""}, // would match anything that rendered
		},
		tmpl:      tmpl,
		isExactly: map[string]struct{}{"": {}},
	}

	if _, ok := rule.matches(benchArgs()); ok {
		t.Error("matches() = true on render error, want false (fail closed)")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
//
// The matcher runs on every request that reaches the middleware, so the cost
// of template rendering and predicate evaluation is on the hot path.
// ---------------------------------------------------------------------------

func benchMatcher(b *testing.B, rules []SkipRule) {
	b.Helper()

	skipper, err := NewAuthSkipper(rules)
	if err != nil {
		b.Fatalf("NewAuthSkipper: %v", err)
	}
	args := benchArgs()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = skipper.ShouldSkip(args)
	}
}

func BenchmarkMatch_IsExactly_Hit(b *testing.B) {
	benchMatcher(b, []SkipRule{{Expression: "{ .Host }", IsExactly: []string{"api.example.com"}}})
}

func BenchmarkMatch_IsExactly_Miss(b *testing.B) {
	benchMatcher(b, []SkipRule{{Expression: "{ .Host }", IsExactly: []string{"nope.example.com"}}})
}

// The lookup map should make a large isExactly list cost roughly the same as a
// single-entry one. Compare against BenchmarkMatch_IsExactly_Miss.
func BenchmarkMatch_IsExactly_1000Values_Miss(b *testing.B) {
	values := make([]string, 1000)
	for i := range values {
		values[i] = fmt.Sprintf("host-%d.example.com", i)
	}
	benchMatcher(b, []SkipRule{{Expression: "{ .Host }", IsExactly: values}})
}

func BenchmarkMatch_StartsWith(b *testing.B) {
	benchMatcher(b, []SkipRule{{Expression: "{ .Path }", StartsWith: []string{"/v1/"}}})
}

func BenchmarkMatch_EndsWith(b *testing.B) {
	benchMatcher(b, []SkipRule{{Expression: "{ .Host }", EndsWith: []string{".example.com"}}})
}

func BenchmarkMatch_Contains(b *testing.B) {
	benchMatcher(b, []SkipRule{{Expression: "{ .Path }", Contains: []string{"/users"}}})
}

func BenchmarkMatch_Regex(b *testing.B) {
	benchMatcher(b, []SkipRule{{Expression: "{ .Path }", MatchesRegex: []string{`^/v[0-9]+/users$`}}})
}

// Cost of a composite template versus the single-substitution cases above.
func BenchmarkMatch_CompositeExpression(b *testing.B) {
	benchMatcher(b, []SkipRule{{
		Expression: "{ .Method } { .Scheme }://{ .Host }{ .Path }",
		IsExactly:  []string{"GET http://api.example.com/v1/users"},
	}})
}

// Worst case: every rule must be evaluated because none match.
func BenchmarkMatch_20Rules_AllMiss(b *testing.B) {
	rules := make([]SkipRule, 20)
	for i := range rules {
		rules[i] = SkipRule{
			Expression: "{ .Host }{ .Path }",
			IsExactly:  []string{fmt.Sprintf("miss-%d.example.com/x", i)},
		}
	}
	benchMatcher(b, rules)
}

// Realistic configuration: a handful of mixed rules, last one matching.
func BenchmarkMatch_RealisticConfig(b *testing.B) {
	benchMatcher(b, []SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"public.example.com", "status.example.com"}},
		{Expression: "{ .Method } { .Host }{ .Path }", IsExactly: []string{"GET example.com/health"}},
		{Expression: "{ .Host }{ .Path }", StartsWith: []string{"cdn.example.com/assets/"}},
		{Expression: "{ .Path }", MatchesRegex: []string{`^/v[0-9]+/users$`}},
	})
}

// Startup cost, for configurations with many rules.
func BenchmarkNewAuthSkipper(b *testing.B) {
	rules := []SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"a.example.com", "b.example.com"}},
		{Expression: "{ .Method } { .Host }{ .Path }", IsExactly: []string{"GET example.com/health"}},
		{Expression: "{ .Host }{ .Path }", StartsWith: []string{"cdn.example.com/assets/"}, Contains: []string{"/public/"}},
		{Expression: "{ .Path }", MatchesRegex: []string{`^/v[0-9]+/ping$`, `^/healthz$`}},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := NewAuthSkipper(rules); err != nil {
			b.Fatal(err)
		}
	}
}
