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

// rule is shorthand for the pointer every predefined key takes.
func rule(r SkipRule) *SkipRule { return &r }

// findRule returns the compiled rule with the given name, or nil.
func findRule(s *AuthSkipper, name string) *compiledSkipRule {
	for _, r := range s.rules {
		if r.name == name {
			return r
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// NewAuthSkipper
// ---------------------------------------------------------------------------

func TestNewAuthSkipper_Valid(t *testing.T) {
	skipper, err := NewAuthSkipper(SkipRules{
		Host:     rule(SkipRule{IsExactly: []string{"a.example.com", "b.example.com"}}),
		Path:     rule(SkipRule{MatchesRegex: []string{`^/v[0-9]+/ping$`}}),
		URL:      rule(SkipRule{Contains: []string{"/public/"}}),
		ClientIP: rule(SkipRule{InSubnet: []string{"10.0.0.0/8", "127.0.0.1", "2001:db8::/32"}}),
		Custom:   []SkipRule{{Expression: "{ .Method }", IsExactly: []string{"OPTIONS"}}},
	})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}

	// Names are what errors and debug lines use; they must spell the YAML
	// keys, and rules must be stored in evaluation order.
	want := []struct {
		name string
		kind ruleKind
	}{
		{"host", kindHost}, {"path", kindPath}, {"url", kindURL}, {"clientIp", kindClientIP}, {"custom[0]", kindCustom},
	}
	if len(skipper.rules) != len(want) {
		t.Fatalf("compiled %d rules, want %d", len(skipper.rules), len(want))
	}
	for i, r := range skipper.rules {
		if r.name != want[i].name || r.kind != want[i].kind {
			t.Errorf("rules[%d] = %q/%v, want %q/%v", i, r.name, r.kind, want[i].name, want[i].kind)
		}
	}

	// isExactly must become a lookup map, not a slice scan.
	host := findRule(skipper, "host")
	if _, ok := host.isExactly["a.example.com"]; !ok || len(host.isExactly) != 2 {
		t.Errorf("host.isExactly = %v, want a 2-entry map containing a.example.com", host.isExactly)
	}
	if got := len(findRule(skipper, "path").regexes); got != 1 {
		t.Errorf("compiled %d regexes, want 1", got)
	}
	if got := len(findRule(skipper, "clientIp").subnets); got != 3 {
		t.Errorf("compiled %d subnets, want 3", got)
	}
	if findRule(skipper, "custom[0]").tmpl == nil {
		t.Error("custom[0] has no parsed template")
	}
}

// Each key declares which request fields it reads; the union is what the
// handler extracts per request, so it must be exact in both directions.
func TestNewAuthSkipper_Need(t *testing.T) {
	exact := rule(SkipRule{IsExactly: []string{"x"}})

	tests := []struct {
		name  string
		rules SkipRules
		want  argsNeed
	}{
		{"none", SkipRules{}, needNone},
		{"host", SkipRules{Host: exact}, needHost},
		{"path", SkipRules{Path: exact}, needPath},
		{"url", SkipRules{URL: exact}, needHost | needPath},
		{"clientIp", SkipRules{ClientIP: exact}, needClientIP},
		{"userAgent", SkipRules{UserAgent: exact}, needUserAgent},
		{"host+clientIp", SkipRules{Host: exact, ClientIP: exact}, needHost | needClientIP},
		{"custom needs everything", SkipRules{Custom: []SkipRule{{Expression: "{ .Host }", IsExactly: []string{"x"}}}}, needAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipper, err := NewAuthSkipper(tt.rules)
			if err != nil {
				t.Fatalf("NewAuthSkipper: %v", err)
			}
			if skipper.need != tt.want {
				t.Errorf("need = %06b, want %06b", skipper.need, tt.want)
			}
			if skipper.empty() != (tt.want == needNone) {
				t.Errorf("empty() = %v, want %v", skipper.empty(), tt.want == needNone)
			}
		})
	}
}

func TestNewAuthSkipper_Errors(t *testing.T) {
	custom := func(r SkipRule) SkipRules { return SkipRules{Custom: []SkipRule{r}} }

	tests := []struct {
		name     string
		rules    SkipRules
		wantErr  string
		wantRule string // the "skipAuthWhen.<rule>" label the error must carry
	}{
		{"custom: empty expression", custom(SkipRule{IsExactly: []string{"x"}}), "expression is required", "custom[0]"},
		{"custom: whitespace expression", custom(SkipRule{Expression: "   ", IsExactly: []string{"x"}}), "expression is required", "custom[0]"},
		{"custom: unterminated action", custom(SkipRule{Expression: "{ .Host", IsExactly: []string{"x"}}), "invalid expression", "custom[0]"},
		// Expressions use single braces; the text/template default must not be
		// accepted silently, or a copied {{ }} rule would never match and the
		// route would stay authenticated with no signal.
		{"custom: old {{ }} syntax", custom(SkipRule{Expression: "{{ .Host }}", IsExactly: []string{"x"}}), "invalid expression", "custom[0]"},
		{"custom: unknown field", custom(SkipRule{Expression: "{ .Nope }", IsExactly: []string{"x"}}), "cannot be evaluated", "custom[0]"},
		// RequestArgs has exactly one spelling per field, so the lowercase form
		// that a map-based implementation would have accepted is now an error.
		{"custom: lowercase field", custom(SkipRule{Expression: "{ .host }", IsExactly: []string{"x"}}), "cannot be evaluated", "custom[0]"},
		{"custom: no predicates", custom(SkipRule{Expression: "{ .Host }"}), "at least one of", "custom[0]"},
		{"custom: bad regex", custom(SkipRule{Expression: "{ .Host }", MatchesRegex: []string{"[unclosed"}}), "invalid matchesRegex", "custom[0]"},
		// inSubnet is not a string predicate: a template has no notion of an
		// address, so it must be rejected rather than silently never matching.
		{"custom: inSubnet", custom(SkipRule{Expression: "{ .ClientIp }", InSubnet: []string{"10.0.0.0/8"}}), "inSubnet is only valid under clientIp", "custom[0]"},

		{"host: no predicates", SkipRules{Host: rule(SkipRule{})}, "at least one of", "host"},
		{"host: bad regex", SkipRules{Host: rule(SkipRule{MatchesRegex: []string{"("}})}, "invalid matchesRegex", "host"},
		// The key already names what is tested; an expression there is a
		// misplaced custom rule, not something to guess at.
		{"host: expression", SkipRules{Host: rule(SkipRule{Expression: "{ .Host }", IsExactly: []string{"x"}})}, "expression is only valid under custom", "host"},
		{"path: inSubnet", SkipRules{Path: rule(SkipRule{InSubnet: []string{"10.0.0.0/8"}})}, "inSubnet is only valid under clientIp", "path"},
		{"url: inSubnet alongside valid predicate", SkipRules{URL: rule(SkipRule{Contains: []string{"/x"}, InSubnet: []string{"10.0.0.0/8"}})}, "inSubnet is only valid under clientIp", "url"},
		{"userAgent: expression", SkipRules{UserAgent: rule(SkipRule{Expression: "x", Contains: []string{"x"}})}, "expression is only valid under custom", "userAgent"},

		{"clientIp: no predicates", SkipRules{ClientIP: rule(SkipRule{})}, "inSubnet is required", "clientIp"},
		{"clientIp: expression", SkipRules{ClientIP: rule(SkipRule{Expression: "{ .ClientIp }", InSubnet: []string{"10.0.0.0/8"}})}, "expression is only valid under custom", "clientIp"},
		{"clientIp: bad prefix length", SkipRules{ClientIP: rule(SkipRule{InSubnet: []string{"10.0.0.0/33"}})}, "invalid inSubnet", "clientIp"},
		{"clientIp: not an address", SkipRules{ClientIP: rule(SkipRule{InSubnet: []string{"example.com"}})}, "invalid inSubnet", "clientIp"},
		{"clientIp: empty entry", SkipRules{ClientIP: rule(SkipRule{InSubnet: []string{""}})}, "invalid inSubnet", "clientIp"},
		{"clientIp: address with port", SkipRules{ClientIP: rule(SkipRule{InSubnet: []string{"10.0.0.1:80"}})}, "invalid inSubnet", "clientIp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthSkipper(tt.rules)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
			// The key must be reported so the operator can find the offending rule.
			if want := "skipAuthWhen." + tt.wantRule + ":"; !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should identify the rule as %q", err, want)
			}
		})
	}
}

func TestNewAuthSkipper_ReportsCorrectCustomIndex(t *testing.T) {
	_, err := NewAuthSkipper(SkipRules{Custom: []SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"ok"}},
		{Expression: "{ .Host }", IsExactly: []string{"ok"}},
		{Expression: "{ .Host }", MatchesRegex: []string{"("}},
	}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "skipAuthWhen.custom[2]:") {
		t.Errorf("error = %q, want it to point at custom[2]", err)
	}
}

func TestNewAuthSkipper_Empty(t *testing.T) {
	skipper, err := NewAuthSkipper(SkipRules{})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}
	if !skipper.empty() {
		t.Errorf("empty() = false, want true (need = %06b)", skipper.need)
	}
	if len(skipper.rules) != 0 {
		t.Errorf("rules = %d entries, want 0", len(skipper.rules))
	}
	if skipper.ShouldSkip(benchArgs()) {
		t.Error("ShouldSkip() = true with no rules, want false")
	}
}

func TestParseSubnet(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"10.0.0.0/8", "10.0.0.0/8", false},
		// Host bits are masked off: the operator means the network.
		{"10.0.0.7/24", "10.0.0.0/24", false},
		{"127.0.0.1", "127.0.0.1/32", false},
		{"2001:db8::/32", "2001:db8::/32", false},
		{"2001:db8::1", "2001:db8::1/128", false},
		{"::1", "::1/128", false},
		{"0.0.0.0/0", "0.0.0.0/0", false},
		{"10.0.0.0/33", "", true},
		{"10.0.0/8", "", true},
		{"", "", true},
		{"10.0.0.0/", "", true},
		{"/8", "", true},
		{"localhost", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseSubnet(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSubnet(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err == nil && got.String() != tt.want {
				t.Errorf("parseSubnet(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ShouldSkip / match
// ---------------------------------------------------------------------------

func TestAuthSkipper_ShouldSkip_Predefined(t *testing.T) {
	args := benchArgs()
	args.Scheme = "https"
	args.UserAgent = "curl/8"
	args.ClientIp = "192.0.2.1"

	tests := []struct {
		name  string
		rules SkipRules
		want  bool
	}{
		{"host isExactly hit", SkipRules{Host: rule(SkipRule{IsExactly: []string{"api.example.com"}})}, true},
		{"host isExactly miss", SkipRules{Host: rule(SkipRule{IsExactly: []string{"other.example.com"}})}, false},
		{"host isExactly is not substring", SkipRules{Host: rule(SkipRule{IsExactly: []string{"example.com"}})}, false},
		{"host isExactly second value", SkipRules{Host: rule(SkipRule{IsExactly: []string{"a", "api.example.com"}})}, true},
		{"host endsWith hit", SkipRules{Host: rule(SkipRule{EndsWith: []string{".example.com"}})}, true},
		{"host endsWith miss", SkipRules{Host: rule(SkipRule{EndsWith: []string{".example.org"}})}, false},
		{"host case sensitive", SkipRules{Host: rule(SkipRule{IsExactly: []string{"API.EXAMPLE.COM"}})}, false},
		{"host any predicate may match", SkipRules{Host: rule(SkipRule{
			IsExactly: []string{"nope"},
			EndsWith:  []string{".example.com"},
		})}, true},

		{"path startsWith hit", SkipRules{Path: rule(SkipRule{StartsWith: []string{"/v1/"}})}, true},
		{"path startsWith miss", SkipRules{Path: rule(SkipRule{StartsWith: []string{"/v2/"}})}, false},
		{"path contains hit", SkipRules{Path: rule(SkipRule{Contains: []string{"users"}})}, true},
		{"path contains miss", SkipRules{Path: rule(SkipRule{Contains: []string{"admin"}})}, false},
		{"path regex hit", SkipRules{Path: rule(SkipRule{MatchesRegex: []string{`^/v\d+/users$`}})}, true},
		{"path regex miss", SkipRules{Path: rule(SkipRule{MatchesRegex: []string{`^/admin`}})}, false},
		{"path regex is partial by default", SkipRules{Path: rule(SkipRule{MatchesRegex: []string{`users`}})}, true},
		// The path alone never contains the host.
		{"path does not see host", SkipRules{Path: rule(SkipRule{Contains: []string{"api.example.com"}})}, false},

		{"url is host+path", SkipRules{URL: rule(SkipRule{IsExactly: []string{"api.example.com/v1/users"}})}, true},
		{"url startsWith host boundary", SkipRules{URL: rule(SkipRule{StartsWith: []string{"api.example.com/v1/"}})}, true},
		{"url has no scheme", SkipRules{URL: rule(SkipRule{StartsWith: []string{"https://"}})}, false},
		{"url contains across the join", SkipRules{URL: rule(SkipRule{Contains: []string{"com/v1"}})}, true},

		{"userAgent startsWith", SkipRules{UserAgent: rule(SkipRule{StartsWith: []string{"curl/"}})}, true},
		{"userAgent miss", SkipRules{UserAgent: rule(SkipRule{StartsWith: []string{"Mozilla/"}})}, false},

		{"clientIp isExactly", SkipRules{ClientIP: rule(SkipRule{IsExactly: []string{"192.0.2.1"}})}, true},
		{"clientIp startsWith is a string test", SkipRules{ClientIP: rule(SkipRule{StartsWith: []string{"192.0.2."}})}, true},

		// Rules are OR-ed across keys: any one of them is enough.
		{"any key may match", SkipRules{
			Host:     rule(SkipRule{IsExactly: []string{"nope.example.com"}}),
			Path:     rule(SkipRule{StartsWith: []string{"/nope"}}),
			ClientIP: rule(SkipRule{IsExactly: []string{"192.0.2.1"}}),
		}, true},
		{"all keys miss", SkipRules{
			Host:      rule(SkipRule{IsExactly: []string{"nope.example.com"}}),
			Path:      rule(SkipRule{StartsWith: []string{"/nope"}}),
			URL:       rule(SkipRule{Contains: []string{"/nope"}}),
			ClientIP:  rule(SkipRule{InSubnet: []string{"10.0.0.0/8"}}),
			UserAgent: rule(SkipRule{Contains: []string{"nope"}}),
			Custom:    []SkipRule{{Expression: "{ .Method }", IsExactly: []string{"POST"}}},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipper, err := NewAuthSkipper(tt.rules)
			if err != nil {
				t.Fatalf("NewAuthSkipper: %v", err)
			}
			if got := skipper.ShouldSkip(args); got != tt.want {
				t.Errorf("ShouldSkip() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthSkipper_ShouldSkip_InSubnet(t *testing.T) {
	tests := []struct {
		name     string
		subnets  []string
		clientIP string
		want     bool
	}{
		{"ipv4 in /24", []string{"10.0.0.0/24"}, "10.0.0.200", true},
		{"ipv4 outside /24", []string{"10.0.0.0/24"}, "10.0.1.1", false},
		{"ipv4 in /8", []string{"10.0.0.0/8"}, "10.255.255.254", true},
		{"ipv4 network address", []string{"10.0.0.0/24"}, "10.0.0.0", true},
		{"ipv4 broadcast address", []string{"10.0.0.0/24"}, "10.0.0.255", true},
		{"bare ipv4 matches itself", []string{"127.0.0.1"}, "127.0.0.1", true},
		{"bare ipv4 is not a prefix", []string{"127.0.0.1"}, "127.0.0.2", false},
		{"second subnet", []string{"192.168.0.0/16", "10.0.0.0/8"}, "10.1.2.3", true},
		{"host bits in config are masked", []string{"10.0.0.7/24"}, "10.0.0.9", true},
		{"ipv6 in /32", []string{"2001:db8::/32"}, "2001:db8:1::1", true},
		{"ipv6 outside /32", []string{"2001:db8::/32"}, "2001:db9::1", false},
		{"bare ipv6", []string{"::1"}, "::1", true},
		{"ipv6 zone is ignored", []string{"fe80::/10"}, "fe80::1%eth0", true},
		// A dual-stack listener may report an IPv4 peer as an IPv4-mapped IPv6
		// address; it must still match an IPv4 subnet.
		{"ipv4-mapped ipv6 client in ipv4 subnet", []string{"10.0.0.0/8"}, "::ffff:10.0.0.7", true},
		{"ipv4 client never matches ipv6 subnet", []string{"2001:db8::/32"}, "10.0.0.1", false},
		{"ipv6 client never matches ipv4 subnet", []string{"10.0.0.0/8"}, "2001:db8::1", false},
		{"everything v4", []string{"0.0.0.0/0"}, "203.0.113.9", true},
		{"everything v4 does not cover v6", []string{"0.0.0.0/0"}, "2001:db8::1", false},
		// Fail closed: an address that does not parse is in no subnet.
		{"unparseable client ip", []string{"0.0.0.0/0", "::/0"}, "not-an-ip", false},
		{"empty client ip", []string{"0.0.0.0/0"}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipper, err := NewAuthSkipper(SkipRules{ClientIP: rule(SkipRule{InSubnet: tt.subnets})})
			if err != nil {
				t.Fatalf("NewAuthSkipper: %v", err)
			}

			args := benchArgs()
			args.ClientIp = tt.clientIP

			m, got := matchRules(skipper, args)
			if got != tt.want {
				t.Fatalf("match() = %v, want %v", got, tt.want)
			}
			if got && (m.rule != ruleClientIP || m.predicate != predicateInSubnet || m.value != tt.clientIP) {
				t.Errorf("match = %+v, want rule %q predicate %q value %q", m, ruleClientIP, predicateInSubnet, tt.clientIP)
			}
		})
	}
}

// clientIp carries both the string predicates and inSubnet; either may fire.
func TestAuthSkipper_ClientIP_StringPredicatesAndSubnet(t *testing.T) {
	skipper, err := NewAuthSkipper(SkipRules{ClientIP: rule(SkipRule{
		IsExactly: []string{"203.0.113.9"},
		InSubnet:  []string{"10.0.0.0/8"},
	})})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}

	for _, tt := range []struct {
		ip        string
		predicate string
	}{
		{"203.0.113.9", predicateIsExactly},
		{"10.4.5.6", predicateInSubnet},
		{"192.0.2.1", ""},
	} {
		args := benchArgs()
		args.ClientIp = tt.ip

		m, ok := matchRules(skipper, args)
		if ok != (tt.predicate != "") {
			t.Errorf("%s: match = %v, want %v", tt.ip, ok, tt.predicate != "")
			continue
		}
		if ok && m.predicate != tt.predicate {
			t.Errorf("%s: predicate = %q, want %q", tt.ip, m.predicate, tt.predicate)
		}
	}
}

func TestAuthSkipper_ShouldSkip_Custom(t *testing.T) {
	args := benchArgs()
	args.Scheme = "https"
	args.UserAgent = "curl/8"
	args.ClientIp = "192.0.2.1"

	tests := []struct {
		name string
		rule SkipRule
		want bool
	}{
		{"composite expression", SkipRule{
			Expression: "{ .Method } { .Scheme }://{ .Host }{ .Path }",
			IsExactly:  []string{"GET https://api.example.com/v1/users"},
		}, true},
		{"method substitution", SkipRule{Expression: "{ .Method }", IsExactly: []string{"GET"}}, true},
		{"scheme substitution", SkipRule{Expression: "{ .Scheme }", IsExactly: []string{"https"}}, true},
		{"host substitution", SkipRule{Expression: "{ .Host }", IsExactly: []string{"api.example.com"}}, true},
		{"path substitution", SkipRule{Expression: "{ .Path }", StartsWith: []string{"/v1/"}}, true},
		{"userAgent substitution", SkipRule{Expression: "{ .UserAgent }", StartsWith: []string{"curl/"}}, true},
		{"clientIp substitution", SkipRule{Expression: "{ .ClientIp }", IsExactly: []string{"192.0.2.1"}}, true},
		{"regex on composite", SkipRule{Expression: "{ .Host }{ .Path }", MatchesRegex: []string{`^api\.example\.com/v[0-9]+/users$`}}, true},
		{"literal expression with no substitution", SkipRule{Expression: "constant", IsExactly: []string{"constant"}}, true},
		{"miss", SkipRule{Expression: "{ .Method } { .Path }", IsExactly: []string{"POST /v1/users"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipper, err := NewAuthSkipper(SkipRules{Custom: []SkipRule{tt.rule}})
			if err != nil {
				t.Fatalf("NewAuthSkipper: %v", err)
			}
			if got := skipper.ShouldSkip(args); got != tt.want {
				t.Errorf("ShouldSkip() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Custom rules are OR-ed in configuration order: any one of them is enough.
func TestAuthSkipper_ShouldSkip_AnyCustomRuleMatches(t *testing.T) {
	skipper, err := NewAuthSkipper(SkipRules{Custom: []SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"nope.example.com"}},
		{Expression: "{ .Path }", StartsWith: []string{"/nope"}},
		{Expression: "{ .Method }", IsExactly: []string{"GET"}},
	}})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}

	m, ok := matchRules(skipper, benchArgs())
	if !ok {
		t.Fatal("match() = false, want true (third rule matches)")
	}
	if m.rule != "custom[2]" {
		t.Errorf("matched %q, want custom[2]", m.rule)
	}
}

// Predefined keys are evaluated before custom rules, in a fixed order, so the
// reported match (and the debug line) is deterministic when several would hit.
func TestAuthSkipper_EvaluationOrder(t *testing.T) {
	all := SkipRules{
		Host:      rule(SkipRule{IsExactly: []string{"api.example.com"}}),
		Path:      rule(SkipRule{IsExactly: []string{"/v1/users"}}),
		URL:       rule(SkipRule{IsExactly: []string{"api.example.com/v1/users"}}),
		ClientIP:  rule(SkipRule{IsExactly: []string{"192.0.2.10"}}),
		UserAgent: rule(SkipRule{IsExactly: []string{"Mozilla/5.0"}}),
		Custom:    []SkipRule{{Expression: "{ .Method }", IsExactly: []string{"GET"}}},
	}

	// Remove the keys one by one, front to back; the next one must take over.
	want := []string{"host", "path", "url", "clientIp", "userAgent", "custom[0]"}
	remove := []func(*SkipRules){
		func(r *SkipRules) { r.Host = nil },
		func(r *SkipRules) { r.Path = nil },
		func(r *SkipRules) { r.URL = nil },
		func(r *SkipRules) { r.ClientIP = nil },
		func(r *SkipRules) { r.UserAgent = nil },
	}

	for i, name := range want {
		skipper, err := NewAuthSkipper(all)
		if err != nil {
			t.Fatalf("NewAuthSkipper: %v", err)
		}

		m, ok := matchRules(skipper, benchArgs())
		if !ok {
			t.Fatalf("step %d: match() = false, want %s", i, name)
		}
		if m.rule != name {
			t.Errorf("step %d: matched %q, want %q", i, m.rule, name)
		}

		if i < len(remove) {
			remove[i](&all)
		}
	}
}

// The match must identify what fired precisely enough for a debug line to be
// traced back to the configuration.
func TestAuthSkipper_MatchDetails(t *testing.T) {
	skipper, err := NewAuthSkipper(SkipRules{
		URL: rule(SkipRule{StartsWith: []string{"nope", "api.example.com/v1/"}}),
	})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}

	m, ok := matchRules(skipper, benchArgs())
	if !ok {
		t.Fatal("match() = false, want true")
	}

	want := ruleMatch{rule: "url", predicate: predicateStartsWith, pattern: "api.example.com/v1/", value: "api.example.com/v1/users"}
	if m != want {
		t.Errorf("match = %+v, want %+v", m, want)
	}
}

// A template that fails at request time must not match: failing closed means
// the request gets authenticated rather than silently exempted.
//
// NewAuthSkipper rejects such an expression at startup, so the rule is built by
// hand here to exercise the request-time guard.
func TestMatchRule_CustomFailsClosedOnRenderError(t *testing.T) {
	// Same delimiters as NewAuthSkipper, or { .Nope } would be inert literal
	// text that renders without error.
	tmpl, err := template.New("bad").Delims(leftDelim, rightDelim).Parse("{ .Nope }")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	r := &compiledSkipRule{
		name: "custom[0]",
		kind: kindCustom,
		source: SkipRule{
			Expression: "{ .Nope }",
			Contains:   []string{""}, // would match anything that rendered
		},
		tmpl:      tmpl,
		isExactly: map[string]struct{}{"": {}},
	}

	if _, ok := matchRule(r, benchArgs()); ok {
		t.Error("matchRule() = true on render error, want false (fail closed)")
	}
}

// ---------------------------------------------------------------------------
// describeRules
// ---------------------------------------------------------------------------

func TestAuthSkipper_DescribeRules(t *testing.T) {
	skipper, err := NewAuthSkipper(SkipRules{
		Host:     rule(SkipRule{IsExactly: []string{"a.example.com", "b.example.com"}, EndsWith: []string{".internal"}}),
		ClientIP: rule(SkipRule{IsExactly: []string{"203.0.113.9"}, InSubnet: []string{"10.0.0.0/8", "127.0.0.1"}}),
		Custom: []SkipRule{
			{Expression: "{ .Method } { .Host }{ .Path }", IsExactly: []string{"GET example.com/health"}},
			{Expression: "{ .Path }", StartsWith: []string{"/v1/"}, Contains: []string{"/public/"}, MatchesRegex: []string{`^/v[0-9]+/ping$`}},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthSkipper: %v", err)
	}

	want := []string{
		`host isExactly ["a.example.com" "b.example.com"] endsWith [".internal"]`,
		`clientIp isExactly ["203.0.113.9"] inSubnet ["10.0.0.0/8" "127.0.0.1"]`,
		`custom[0] "{ .Method } { .Host }{ .Path }" isExactly ["GET example.com/health"]`,
		`custom[1] "{ .Path }" startsWith ["/v1/"] contains ["/public/"] matchesRegex ["^/v[0-9]+/ping$"]`,
	}

	got := skipper.describeRules()
	if len(got) != len(want) {
		t.Fatalf("describeRules() = %d lines, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q\nwant       %q", i, got[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
//
// The matcher runs on every request that reaches the middleware, so the cost
// of attribute lookup, template rendering and predicate evaluation is on the
// hot path. Each predefined-key benchmark has a _Custom twin expressing the
// same rule as a template, so the two paths can be compared directly.
// ---------------------------------------------------------------------------

func benchMatcher(b *testing.B, rules SkipRules) {
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

func BenchmarkMatch_Host_IsExactly_Hit(b *testing.B) {
	benchMatcher(b, SkipRules{Host: rule(SkipRule{IsExactly: []string{"api.example.com"}})})
}

func BenchmarkMatch_Host_IsExactly_Hit_Custom(b *testing.B) {
	benchMatcher(b, SkipRules{Custom: []SkipRule{{Expression: "{ .Host }", IsExactly: []string{"api.example.com"}}}})
}

func BenchmarkMatch_Host_IsExactly_Miss(b *testing.B) {
	benchMatcher(b, SkipRules{Host: rule(SkipRule{IsExactly: []string{"nope.example.com"}})})
}

func BenchmarkMatch_Host_IsExactly_Miss_Custom(b *testing.B) {
	benchMatcher(b, SkipRules{Custom: []SkipRule{{Expression: "{ .Host }", IsExactly: []string{"nope.example.com"}}}})
}

// The lookup map should make a large isExactly list cost roughly the same as a
// single-entry one. Compare against BenchmarkMatch_Host_IsExactly_Miss.
func BenchmarkMatch_Host_IsExactly_1000Values_Miss(b *testing.B) {
	values := make([]string, 1000)
	for i := range values {
		values[i] = fmt.Sprintf("host-%d.example.com", i)
	}
	benchMatcher(b, SkipRules{Host: rule(SkipRule{IsExactly: values})})
}

func BenchmarkMatch_Path_StartsWith(b *testing.B) {
	benchMatcher(b, SkipRules{Path: rule(SkipRule{StartsWith: []string{"/v1/"}})})
}

func BenchmarkMatch_Path_StartsWith_Custom(b *testing.B) {
	benchMatcher(b, SkipRules{Custom: []SkipRule{{Expression: "{ .Path }", StartsWith: []string{"/v1/"}}}})
}

func BenchmarkMatch_Host_EndsWith(b *testing.B) {
	benchMatcher(b, SkipRules{Host: rule(SkipRule{EndsWith: []string{".example.com"}})})
}

func BenchmarkMatch_Path_Contains(b *testing.B) {
	benchMatcher(b, SkipRules{Path: rule(SkipRule{Contains: []string{"/users"}})})
}

func BenchmarkMatch_Path_Regex(b *testing.B) {
	benchMatcher(b, SkipRules{Path: rule(SkipRule{MatchesRegex: []string{`^/v[0-9]+/users$`}})})
}

func BenchmarkMatch_Path_Regex_Custom(b *testing.B) {
	benchMatcher(b, SkipRules{Custom: []SkipRule{{Expression: "{ .Path }", MatchesRegex: []string{`^/v[0-9]+/users$`}}}})
}

// url concatenates host and path per request; the template does the same work
// through text/template.
func BenchmarkMatch_URL_StartsWith(b *testing.B) {
	benchMatcher(b, SkipRules{URL: rule(SkipRule{StartsWith: []string{"api.example.com/v1/"}})})
}

func BenchmarkMatch_URL_StartsWith_Custom(b *testing.B) {
	benchMatcher(b, SkipRules{Custom: []SkipRule{{Expression: "{ .Host }{ .Path }", StartsWith: []string{"api.example.com/v1/"}}}})
}

func BenchmarkMatch_ClientIP_InSubnet_Hit(b *testing.B) {
	benchMatcher(b, SkipRules{ClientIP: rule(SkipRule{InSubnet: []string{"10.0.0.0/8", "192.0.2.0/24"}})})
}

func BenchmarkMatch_ClientIP_InSubnet_Miss(b *testing.B) {
	benchMatcher(b, SkipRules{ClientIP: rule(SkipRule{InSubnet: []string{"10.0.0.0/8", "172.16.0.0/12"}})})
}

func BenchmarkMatch_ClientIP_IsExactly(b *testing.B) {
	benchMatcher(b, SkipRules{ClientIP: rule(SkipRule{IsExactly: []string{"192.0.2.10"}})})
}

// Cost of a composite template, which has no predefined equivalent.
func BenchmarkMatch_Custom_CompositeExpression(b *testing.B) {
	benchMatcher(b, SkipRules{Custom: []SkipRule{{
		Expression: "{ .Method } { .Scheme }://{ .Host }{ .Path }",
		IsExactly:  []string{"GET http://api.example.com/v1/users"},
	}}})
}

// Worst case for the predefined keys: every key is configured and none match.
func BenchmarkMatch_AllKeys_AllMiss(b *testing.B) {
	benchMatcher(b, SkipRules{
		Host:      rule(SkipRule{IsExactly: []string{"nope.example.com"}, EndsWith: []string{".internal"}}),
		Path:      rule(SkipRule{StartsWith: []string{"/nope/"}, MatchesRegex: []string{`^/v[0-9]+/ping$`}}),
		URL:       rule(SkipRule{StartsWith: []string{"cdn.example.com/assets/"}, Contains: []string{"/public/"}}),
		ClientIP:  rule(SkipRule{InSubnet: []string{"10.0.0.0/8", "172.16.0.0/12"}}),
		UserAgent: rule(SkipRule{StartsWith: []string{"kube-probe/"}}),
	})
}

// Worst case for custom rules: every rule must be rendered because none match.
func BenchmarkMatch_20Custom_AllMiss(b *testing.B) {
	rules := make([]SkipRule, 20)
	for i := range rules {
		rules[i] = SkipRule{
			Expression: "{ .Host }{ .Path }",
			IsExactly:  []string{fmt.Sprintf("miss-%d.example.com/x", i)},
		}
	}
	benchMatcher(b, SkipRules{Custom: rules})
}

// Realistic configuration: a handful of mixed predefined rules, last one
// matching, and the same configuration written entirely as custom rules.
func BenchmarkMatch_RealisticConfig(b *testing.B) {
	benchMatcher(b, SkipRules{
		Host:   rule(SkipRule{IsExactly: []string{"public.example.com", "status.example.com"}}),
		URL:    rule(SkipRule{IsExactly: []string{"example.com/health"}, StartsWith: []string{"cdn.example.com/assets/"}}),
		Path:   rule(SkipRule{MatchesRegex: []string{`^/v[0-9]+/users$`}}),
		Custom: nil,
	})
}

func BenchmarkMatch_RealisticConfig_Custom(b *testing.B) {
	benchMatcher(b, SkipRules{Custom: []SkipRule{
		{Expression: "{ .Host }", IsExactly: []string{"public.example.com", "status.example.com"}},
		{Expression: "{ .Host }{ .Path }", IsExactly: []string{"example.com/health"}, StartsWith: []string{"cdn.example.com/assets/"}},
		{Expression: "{ .Path }", MatchesRegex: []string{`^/v[0-9]+/users$`}},
	}})
}

// Startup cost, for configurations with many rules.
func BenchmarkNewAuthSkipper(b *testing.B) {
	rules := SkipRules{
		Host:     rule(SkipRule{IsExactly: []string{"a.example.com", "b.example.com"}}),
		URL:      rule(SkipRule{StartsWith: []string{"cdn.example.com/assets/"}, Contains: []string{"/public/"}}),
		Path:     rule(SkipRule{MatchesRegex: []string{`^/v[0-9]+/ping$`, `^/healthz$`}}),
		ClientIP: rule(SkipRule{InSubnet: []string{"10.0.0.0/8", "127.0.0.1", "2001:db8::/32"}}),
		Custom: []SkipRule{
			{Expression: "{ .Method } { .Host }{ .Path }", IsExactly: []string{"GET example.com/health"}},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := NewAuthSkipper(rules); err != nil {
			b.Fatal(err)
		}
	}
}
