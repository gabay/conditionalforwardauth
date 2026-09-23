package conditionalforwardauth

// This file owns the skipAuthWhen rule engine: compiling the configured rules
// at startup and testing a request's RequestArgs against them. It knows nothing
// about *http.Request — building RequestArgs is conditionalforwardauth.go's
// job — and it declares no configuration types, which live in config.go.

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"text/template"
)

// Expression templates use single braces, { .Host }, rather than text/template's
// default {{ }}.
//
// Traefik uses {{ }} itself — in file-provider configuration templates and in
// the label/tag values the Docker, Consul and Kubernetes providers read — so a
// {{ }} expression risks being consumed or mangled before the plugin ever sees
// it. Single braces sidestep that entirely.
//
// Two consequences, both deliberate:
//   - An expression written in the old {{ }} form is a parse error, reported at
//     startup. It cannot silently do the wrong thing.
//   - A literal { in an expression is no longer possible; it starts an action.
//     Nothing in the substitution set produces one.
const (
	leftDelim  = "{"
	rightDelim = "}"
)

// Predicate names, spelled exactly as the configuration keys so that a debug
// line can be traced straight back to the YAML that produced it.
const (
	predicateIsExactly    = "isExactly"
	predicateStartsWith   = "startsWith"
	predicateEndsWith     = "endsWith"
	predicateContains     = "contains"
	predicateMatchesRegex = "matchesRegex"
)

// AuthSkipper decides whether a request is exempt from authentication.
//
// It is created once at startup by NewAuthSkipper, which compiles and probes
// every rule, and is then read-only and safe for concurrent use.
type AuthSkipper struct {
	rules []*compiledSkipRule
}

// compiledSkipRule is the preprocessed form of a SkipRule: the template is
// parsed, the regexes compiled and the exact matches loaded into a lookup map,
// all once at startup rather than per request.
type compiledSkipRule struct {
	// source is the rule as configured. The string predicates are matched
	// straight off it; it also backs the startup debug dump, which must print
	// isExactly in configuration order rather than the map's random one.
	source SkipRule

	tmpl      *template.Template
	isExactly map[string]struct{}
	regexes   []*regexp.Regexp
}

// ruleMatch identifies the rule and predicate that exempted a request.
//
// It is built on every match, but read only when debug logging is on. That
// costs nothing measurable: every field is already in hand at the point of the
// match, the struct never escapes, and a miss returns the zero value.
type ruleMatch struct {
	index     int
	predicate string
	pattern   string
	rendered  string
}

// probeArgs is used at load time to execute every template once, so that a
// typo such as { .Hsot } fails fast at startup instead of silently never
// matching (which would leave a route authenticated that the operator believed
// was exempt, or worse, mask an intended exemption).
var probeArgs = RequestArgs{
	Host:      "probe.example.com",
	Path:      "/probe",
	Method:    http.MethodGet,
	Scheme:    "https",
	UserAgent: "probe-agent",
	ClientIp:  "192.0.2.1",
}

// NewAuthSkipper validates and preprocesses the skipAuthWhen configuration.
//
// Every error here is a startup error: an unusable skip rule must never be
// silently ignored, because the operator's intent (exempting a route) would be
// lost without any signal.
func NewAuthSkipper(rules []SkipRule) (*AuthSkipper, error) {
	skipper := &AuthSkipper{}

	for i, rule := range rules {
		if strings.TrimSpace(rule.Expression) == "" {
			return nil, fmt.Errorf("skipAuthWhen[%d]: expression is required", i)
		}

		tmpl, err := template.New(fmt.Sprintf("skipAuthWhen[%d]", i)).
			Delims(leftDelim, rightDelim).
			Parse(rule.Expression)
		if err != nil {
			return nil, fmt.Errorf("skipAuthWhen[%d]: invalid expression %q (substitutions are written %s .Host %s, with single braces): %w",
				i, rule.Expression, leftDelim, rightDelim, err)
		}

		// Rendering the probe rejects unknown substitutions: RequestArgs is a
		// struct, so { .Typo } is an execution error rather than the string
		// "<no value>" a map would have yielded.
		if _, err := renderTemplate(tmpl, probeArgs); err != nil {
			return nil, fmt.Errorf("skipAuthWhen[%d]: expression %q cannot be evaluated (available: .Host .Path .Method .Scheme .UserAgent .ClientIp): %w",
				i, rule.Expression, err)
		}

		c := &compiledSkipRule{
			source: rule,
			tmpl:   tmpl,
		}

		if len(rule.IsExactly) > 0 {
			c.isExactly = make(map[string]struct{}, len(rule.IsExactly))
			for _, v := range rule.IsExactly {
				c.isExactly[v] = struct{}{}
			}
		}

		for _, pattern := range rule.MatchesRegex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("skipAuthWhen[%d]: invalid matchesRegex %q: %w", i, pattern, err)
			}
			c.regexes = append(c.regexes, re)
		}

		if len(c.isExactly) == 0 && len(rule.StartsWith) == 0 && len(rule.EndsWith) == 0 &&
			len(rule.Contains) == 0 && len(c.regexes) == 0 {
			return nil, fmt.Errorf("skipAuthWhen[%d]: at least one of isExactly, startsWith, endsWith, contains or matchesRegex is required", i)
		}

		skipper.rules = append(skipper.rules, c)
	}

	return skipper, nil
}

// ShouldSkip reports whether any rule exempts the request from authentication.
func (s *AuthSkipper) ShouldSkip(args RequestArgs) bool {
	_, ok := s.matches(args)
	return ok
}

// match returns the first rule that exempts the request, if any. Rules are
// evaluated in configuration order.
func (s *AuthSkipper) matches(args RequestArgs) (ruleMatch, bool) {
	for i, rule := range s.rules {
		if m, ok := rule.matches(args); ok {
			m.index = i
			return m, true
		}
	}

	return ruleMatch{}, false
}

// empty reports whether no rule is configured, which lets the caller avoid
// building RequestArgs at all for the common no-exemptions deployment.
func (s *AuthSkipper) empty() bool {
	return len(s.rules) == 0
}

// describeRules renders the rules for the startup debug dump, one line each, in
// configuration order.
func (s *AuthSkipper) describeRules() []string {
	lines := make([]string, 0, len(s.rules))

	for i, rule := range s.rules {
		var b strings.Builder

		fmt.Fprintf(&b, "rule[%d] %q", i, rule.source.Expression)
		appendPredicate(&b, predicateIsExactly, rule.source.IsExactly)
		appendPredicate(&b, predicateStartsWith, rule.source.StartsWith)
		appendPredicate(&b, predicateEndsWith, rule.source.EndsWith)
		appendPredicate(&b, predicateContains, rule.source.Contains)
		appendPredicate(&b, predicateMatchesRegex, rule.source.MatchesRegex)

		lines = append(lines, b.String())
	}

	return lines
}

func appendPredicate(b *strings.Builder, name string, values []string) {
	if len(values) == 0 {
		return
	}

	b.WriteString(" ")
	b.WriteString(name)
	b.WriteString(" [")

	for i, v := range values {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(b, "%q", v)
	}

	b.WriteString("]")
}

func renderTemplate(tmpl *template.Template, args RequestArgs) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, args); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// matches reports whether the rule matches the request, and if so which
// predicate did it.
//
// A template that fails to render at request time is treated as NOT matching,
// i.e. the request is authenticated. Failing closed is the only safe choice for
// a predicate that decides whether to bypass authentication.
func (c *compiledSkipRule) matches(args RequestArgs) (ruleMatch, bool) {
	value, err := renderTemplate(c.tmpl, args)
	if err != nil {
		return ruleMatch{}, false
	}

	if c.isExactly != nil {
		if _, ok := c.isExactly[value]; ok {
			return ruleMatch{predicate: predicateIsExactly, pattern: value, rendered: value}, true
		}
	}

	for _, prefix := range c.source.StartsWith {
		if strings.HasPrefix(value, prefix) {
			return ruleMatch{predicate: predicateStartsWith, pattern: prefix, rendered: value}, true
		}
	}

	for _, suffix := range c.source.EndsWith {
		if strings.HasSuffix(value, suffix) {
			return ruleMatch{predicate: predicateEndsWith, pattern: suffix, rendered: value}, true
		}
	}

	for _, substr := range c.source.Contains {
		if strings.Contains(value, substr) {
			return ruleMatch{predicate: predicateContains, pattern: substr, rendered: value}, true
		}
	}

	for _, re := range c.regexes {
		if re.MatchString(value) {
			return ruleMatch{predicate: predicateMatchesRegex, pattern: re.String(), rendered: value}, true
		}
	}

	return ruleMatch{}, false
}
