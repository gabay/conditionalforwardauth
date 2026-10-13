package conditionalforwardauth

// This file owns the skipAuthWhen rule engine: compiling the configured rules
// at startup and testing a request's RequestArgs against them. It knows nothing
// about *http.Request — building RequestArgs is conditionalforwardauth.go's
// job — and it declares no configuration types, which live in config.go.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
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
	predicateInSubnet     = "inSubnet"
)

// Rule names, spelled exactly as the skipAuthWhen keys. They label errors and
// debug lines; custom rules are named "custom[i]" (see customRuleName).
const (
	ruleHost      = "host"
	rulePath      = "path"
	ruleURL       = "url"
	ruleClientIP  = "clientIp"
	ruleUserAgent = "userAgent"
	ruleCustom    = "custom"
)

// ruleKind says which request attribute a rule tests, and therefore which
// predicates it may carry: clientIp alone takes inSubnet, custom alone takes
// (and requires) expression.
type ruleKind int

const (
	kindHost ruleKind = iota
	kindPath
	kindURL
	kindClientIP
	kindUserAgent
	kindCustom
)

// AuthSkipper decides whether a request is exempt from authentication.
//
// It is created once at startup by NewAuthSkipper, which compiles and probes
// every rule, and is then read-only and safe for concurrent use.
//
// Only configured keys produce a rule, so an unused key costs nothing at
// request time: not a comparison, and not the extraction of its request
// attribute either (see need).
type AuthSkipper struct {
	// rules in evaluation order: the predefined keys in the order of the
	// SkipRules fields, then custom rules in configuration order.
	rules []*compiledSkipRule

	// need is the union of the RequestArgs fields the rules read. It is what
	// newRequestArgs is told to extract.
	need argsNeed
}

// compiledSkipRule is the preprocessed form of a SkipRule: the template is
// parsed, the regexes and subnets compiled and the exact matches loaded into a
// lookup map, all once at startup rather than per request.
type compiledSkipRule struct {
	// name labels the rule in errors and debug lines: "host", "custom[2]", etc.
	// Precomputed so that a match never has to format it.
	name string
	kind ruleKind

	// source is the rule as configured. The string predicates are matched
	// straight off it; it also backs the startup debug dump, which must print
	// isExactly in configuration order rather than the map's random one.
	source SkipRule

	tmpl      *template.Template // custom rules only
	isExactly map[string]struct{}
	regexes   []*regexp.Regexp
	subnets   []netip.Prefix // clientIp only
}

// ruleMatch identifies the rule and predicate that exempted a request.
//
// It is built on every match, but read only when debug logging is on. That
// costs nothing measurable: every field is already in hand at the point of the
// match, the struct never escapes, and a miss returns the zero value.
type ruleMatch struct {
	rule      string
	predicate string
	pattern   string
	value     string
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
func NewAuthSkipper(rules SkipRules) (*AuthSkipper, error) {
	skipper := &AuthSkipper{}

	predefined := []struct {
		name   string
		kind   ruleKind
		need   argsNeed
		source *SkipRule
	}{
		{ruleHost, kindHost, needHost, rules.Host},
		{rulePath, kindPath, needPath, rules.Path},
		{ruleURL, kindURL, needHost | needPath, rules.URL},
		{ruleClientIP, kindClientIP, needClientIP, rules.ClientIP},
		{ruleUserAgent, kindUserAgent, needUserAgent, rules.UserAgent},
	}

	for _, p := range predefined {
		if p.source == nil {
			continue
		}

		compiled, err := compileSkipRule(p.name, p.kind, *p.source)
		if err != nil {
			return nil, err
		}

		skipper.rules = append(skipper.rules, compiled)
		skipper.need |= p.need
	}

	for i, rule := range rules.Custom {
		compiled, err := compileSkipRule(customRuleName(i), kindCustom, rule)
		if err != nil {
			return nil, err
		}

		skipper.rules = append(skipper.rules, compiled)
		// A template may reference any field, so all of them are extracted.
		skipper.need = needAll
	}

	return skipper, nil
}

func customRuleName(i int) string {
	return fmt.Sprintf("%s[%d]", ruleCustom, i)
}

// compileSkipRule preprocesses one rule and rejects predicates that do not
// belong under its key.
func compileSkipRule(name string, kind ruleKind, rule SkipRule) (*compiledSkipRule, error) {
	if err := checkRulePlacement(name, kind, rule); err != nil {
		return nil, err
	}

	c := &compiledSkipRule{name: name, kind: kind, source: rule}

	if kind == kindCustom {
		tmpl, err := compileExpression(name, rule.Expression)
		if err != nil {
			return nil, err
		}
		c.tmpl = tmpl
	}

	if err := c.compilePredicates(); err != nil {
		return nil, err
	}

	if !c.hasPredicate() {
		predicates := "isExactly, startsWith, endsWith, contains or matchesRegex"
		if kind == kindClientIP {
			predicates = "isExactly, startsWith, endsWith, contains, matchesRegex or inSubnet"
		}
		return nil, fmt.Errorf("skipAuthWhen.%s: at least one of %s is required", name, predicates)
	}

	return c, nil
}

// checkRulePlacement rejects expression outside custom and inSubnet outside
// clientIp. Because SkipRule is one flat type (see its doc), a misplaced key
// decodes fine and would otherwise be silently ignored — the one thing a rule
// that bypasses authentication must never be.
func checkRulePlacement(name string, kind ruleKind, rule SkipRule) error {
	if kind != kindCustom && rule.Expression != "" {
		return fmt.Errorf("skipAuthWhen.%s: expression is only valid under %s; the %s key already names what is tested",
			name, ruleCustom, name)
	}

	if kind != kindClientIP && len(rule.InSubnet) > 0 {
		return fmt.Errorf("skipAuthWhen.%s: inSubnet is only valid under %s", name, ruleClientIP)
	}

	return nil
}

// compilePredicates builds the lookup map, regexes and subnets from source.
//
// An empty value is rejected everywhere. "" is a prefix, suffix and substring
// of every string and an empty regex matches everything, so a single empty
// entry would exempt the whole route — and it is easy to produce by accident:
// a trailing comma in a Traefik label ("/health," decodes to ["/health", ""])
// or a bare "-" in a YAML list.
func (c *compiledSkipRule) compilePredicates() error {
	for _, p := range []struct {
		name   string
		values []string
	}{
		{predicateIsExactly, c.source.IsExactly},
		{predicateStartsWith, c.source.StartsWith},
		{predicateEndsWith, c.source.EndsWith},
		{predicateContains, c.source.Contains},
		{predicateMatchesRegex, c.source.MatchesRegex},
		{predicateInSubnet, c.source.InSubnet},
	} {
		for _, v := range p.values {
			if v == "" {
				return fmt.Errorf("skipAuthWhen.%s: %s has an empty value, which would match every request", c.name, p.name)
			}
		}
	}

	if len(c.source.IsExactly) > 0 {
		c.isExactly = make(map[string]struct{}, len(c.source.IsExactly))
		for _, v := range c.source.IsExactly {
			c.isExactly[v] = struct{}{}
		}
	}

	for _, pattern := range c.source.MatchesRegex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("skipAuthWhen.%s: invalid matchesRegex %q: %w", c.name, pattern, err)
		}
		c.regexes = append(c.regexes, re)
	}

	for _, cidr := range c.source.InSubnet {
		prefix, err := parseSubnet(cidr)
		if err != nil {
			return fmt.Errorf("skipAuthWhen.%s: invalid inSubnet %q (want CIDR such as 10.0.0.0/8 or a bare address): %w", c.name, cidr, err)
		}
		c.subnets = append(c.subnets, prefix)
	}

	return nil
}

// hasPredicate reports whether the rule could ever match.
func (c *compiledSkipRule) hasPredicate() bool {
	return len(c.isExactly) > 0 || len(c.source.StartsWith) > 0 || len(c.source.EndsWith) > 0 ||
		len(c.source.Contains) > 0 || len(c.regexes) > 0 || len(c.subnets) > 0
}

// compileExpression parses a custom rule's template and renders it once
// against probeArgs so that an unknown substitution is a startup error.
func compileExpression(name, expression string) (*template.Template, error) {
	if strings.TrimSpace(expression) == "" {
		return nil, fmt.Errorf("skipAuthWhen.%s: expression is required", name)
	}

	tmpl, err := template.New("skipAuthWhen."+name).
		Delims(leftDelim, rightDelim).
		Parse(expression)
	if err != nil {
		return nil, fmt.Errorf("skipAuthWhen.%s: invalid expression %q (substitutions are written %s .Host %s, with single braces): %w",
			name, expression, leftDelim, rightDelim, err)
	}

	// Rendering the probe rejects unknown substitutions: RequestArgs is a
	// struct, so { .Typo } is an execution error rather than the string
	// "<no value>" a map would have yielded.
	if _, err := renderTemplate(tmpl, probeArgs); err != nil {
		return nil, fmt.Errorf("skipAuthWhen.%s: expression %q cannot be evaluated (available: .Host .Path .Method .Scheme .UserAgent .ClientIp): %w",
			name, expression, err)
	}

	return tmpl, nil
}

// parseSubnet accepts CIDR notation or a bare address, which is treated as a
// single-host network.
//
// IPv4-mapped IPv6 input ("::ffff:10.0.0.0/104", "::ffff:10.0.0.7") is
// converted to its IPv4 form, because matchSubnets unmaps the client address
// and netip.Prefix.Contains never matches across families: left as written,
// such a network would compile and then never match anything.
func parseSubnet(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		addr = addr.Unmap().WithZone("")
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}

	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}

	if prefix.Addr().Is4In6() {
		if prefix.Bits() < ipv4MappedPrefixBits {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix %q is shorter than /%d; write it as an IPv4 network", s, ipv4MappedPrefixBits)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-ipv4MappedPrefixBits)
	}

	// Masked so that "10.0.0.7/24" means the network 10.0.0.0/24, as every
	// other tool reads it, rather than failing a Contains check because the
	// host bits differ.
	return prefix.Masked(), nil
}

// ipv4MappedPrefixBits is the length of the ::ffff:0:0/96 prefix under which
// IPv4 addresses are embedded in IPv6.
const ipv4MappedPrefixBits = 96

// ShouldSkip reports whether any rule exempts the request from authentication.
func (s *AuthSkipper) ShouldSkip(args RequestArgs) bool {
	_, ok := matchRules(s, args)
	return ok
}

// empty reports whether no rule is configured, which lets the caller avoid
// building RequestArgs at all for the common no-exemptions deployment.
func (s *AuthSkipper) empty() bool {
	return s.need == needNone
}

// describeRules renders the rules for the startup debug dump, one line each, in
// evaluation order.
func (s *AuthSkipper) describeRules() []string {
	lines := make([]string, 0, len(s.rules))

	for _, rule := range s.rules {
		var b strings.Builder

		b.WriteString(rule.name)
		if rule.tmpl != nil {
			fmt.Fprintf(&b, " %q", rule.source.Expression)
		}
		appendPredicate(&b, predicateIsExactly, rule.source.IsExactly)
		appendPredicate(&b, predicateStartsWith, rule.source.StartsWith)
		appendPredicate(&b, predicateEndsWith, rule.source.EndsWith)
		appendPredicate(&b, predicateContains, rule.source.Contains)
		appendPredicate(&b, predicateMatchesRegex, rule.source.MatchesRegex)
		appendPredicate(&b, predicateInSubnet, rule.source.InSubnet)

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

// The request-time path below is written for the Yaegi interpreter, which is
// where Traefik runs this plugin and where costs look nothing like compiled
// Go's. Measured with `make bench_yaegi` (see readme.md, "Performance"):
//
//   - A method call costs about four times a plain function call, so the two
//     calls made per request, matchRules and matchRule, are functions.
//   - A call's cost grows with the size of the callee, whichever branch runs,
//     so matchRule keeps the predicates every key shares inline and pushes the
//     clientIp-only subnet scan into matchSubnets.
//   - Calling a method on a nil receiver is a full call; ServeHTTP therefore
//     guards the debug logger with a nil check instead of relying on the nil
//     receiver being a no-op.
//
// None of this changes the result of a match; a plain port back to methods
// would be correct, just slower where it runs.

// matchRules returns the first rule that exempts the request, if any. Rules
// are evaluated in configuration order: the predefined keys first, in the
// order of the SkipRules fields, then custom rules.
func matchRules(s *AuthSkipper, args RequestArgs) (ruleMatch, bool) {
	for _, rule := range s.rules {
		if m, ok := matchRule(rule, args); ok {
			return m, true
		}
	}

	return ruleMatch{}, false
}

// matchRule picks the attribute the rule tests and runs its predicates over it.
//
// A custom template that fails to render at request time is treated as NOT
// matching, i.e. the request is authenticated. Failing closed is the only safe
// choice for a predicate that decides whether to bypass authentication.
//
//nolint:gocyclo // deliberately one flat function; see the note above matchRules.
func matchRule(c *compiledSkipRule, args RequestArgs) (ruleMatch, bool) {
	var value string

	switch c.kind {
	case kindHost:
		value = args.Host
	case kindPath:
		value = args.Path
	case kindURL:
		// Unambiguous without a separator: Go's server rejects a Host
		// containing "/" (400), and a cleaned path always starts with one.
		value = args.Host + args.Path
	case kindClientIP:
		value = args.ClientIp
	case kindUserAgent:
		value = args.UserAgent
	case kindCustom:
		rendered, err := renderTemplate(c.tmpl, args)
		if err != nil {
			return ruleMatch{}, false
		}
		value = rendered
	}

	if c.isExactly != nil {
		if _, ok := c.isExactly[value]; ok {
			return ruleMatch{rule: c.name, predicate: predicateIsExactly, pattern: value, value: value}, true
		}
	}

	for _, prefix := range c.source.StartsWith {
		if strings.HasPrefix(value, prefix) {
			return ruleMatch{rule: c.name, predicate: predicateStartsWith, pattern: prefix, value: value}, true
		}
	}

	for _, suffix := range c.source.EndsWith {
		if strings.HasSuffix(value, suffix) {
			return ruleMatch{rule: c.name, predicate: predicateEndsWith, pattern: suffix, value: value}, true
		}
	}

	for _, substr := range c.source.Contains {
		if strings.Contains(value, substr) {
			return ruleMatch{rule: c.name, predicate: predicateContains, pattern: substr, value: value}, true
		}
	}

	for _, re := range c.regexes {
		if re.MatchString(value) {
			return ruleMatch{rule: c.name, predicate: predicateMatchesRegex, pattern: re.String(), value: value}, true
		}
	}

	// subnets is only ever populated for clientIp, so this is also the kind
	// check.
	if len(c.subnets) > 0 {
		return matchSubnets(c, value)
	}

	return ruleMatch{}, false
}

// matchSubnets tests inSubnet.
//
// An address that does not parse cannot be in any subnet, so it fails closed:
// the string predicates may still have matched it, inSubnet never does.
func matchSubnets(c *compiledSkipRule, ip string) (ruleMatch, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ruleMatch{}, false
	}

	// Unmap so that an IPv4 client seen through a dual-stack listener as
	// ::ffff:10.0.0.7 still lands in 10.0.0.0/8; drop the zone because a
	// prefix never carries one and Contains would otherwise reject the address.
	addr = addr.Unmap().WithZone("")

	for _, subnet := range c.subnets {
		if subnet.Contains(addr) {
			return ruleMatch{rule: c.name, predicate: predicateInSubnet, pattern: subnet.String(), value: ip}, true
		}
	}

	return ruleMatch{}, false
}
