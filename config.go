package conditionalforwardauth

// This file holds every configuration type of the plugin, plus RequestArgs,
// the single representation of a request that rules are evaluated against.
// Request handling lives in conditionalforwardauth.go and rule
// compilation/matching lives in authskipper.go.

// ClientTLS mirrors Traefik's types.ClientTLS. CA/Cert/Key accept either a
// filesystem path or inline PEM content.
type ClientTLS struct {
	CA string `json:"ca,omitempty" mapstructure:"ca"`
	// CAOptional is accepted for compatibility with Traefik's ForwardAuth
	// configuration but ignored: it is deprecated upstream and TLS client
	// authentication is a server-side concern.
	CAOptional         bool   `json:"caOptional,omitempty" mapstructure:"caOptional"`
	Cert               string `json:"cert,omitempty" mapstructure:"cert"`
	Key                string `json:"key,omitempty" mapstructure:"key"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty" mapstructure:"insecureSkipVerify"`
}

// Config is Traefik's ForwardAuth configuration plus the skipAuthWhen rules
// that decide which requests bypass authentication entirely.
//
// NOTE: Traefik decodes plugin configuration with mapstructure, not
// encoding/json, so the mapstructure tags below are what actually bind the
// YAML keys. The json tags are documentation only.
type Config struct {
	Address                  string     `json:"address,omitempty" mapstructure:"address"`
	TrustForwardHeader       *bool      `json:"trustForwardHeader,omitempty" mapstructure:"trustForwardHeader"`
	AuthResponseHeaders      []string   `json:"authResponseHeaders,omitempty" mapstructure:"authResponseHeaders"`
	AuthResponseHeadersRegex string     `json:"authResponseHeadersRegex,omitempty" mapstructure:"authResponseHeadersRegex"`
	AuthRequestHeaders       []string   `json:"authRequestHeaders,omitempty" mapstructure:"authRequestHeaders"`
	AddAuthCookiesToResponse []string   `json:"addAuthCookiesToResponse,omitempty" mapstructure:"addAuthCookiesToResponse"`
	HeaderField              string     `json:"headerField,omitempty" mapstructure:"headerField"`
	ForwardBody              bool       `json:"forwardBody,omitempty" mapstructure:"forwardBody"`
	MaxBodySize              *int64     `json:"maxBodySize,omitempty" mapstructure:"maxBodySize"`
	MaxResponseBodySize      *int64     `json:"maxResponseBodySize,omitempty" mapstructure:"maxResponseBodySize"`
	PreserveLocationHeader   bool       `json:"preserveLocationHeader,omitempty" mapstructure:"preserveLocationHeader"`
	PreserveRequestMethod    bool       `json:"preserveRequestMethod,omitempty" mapstructure:"preserveRequestMethod"`
	AuthSigninURL            string     `json:"authSigninURL,omitempty" mapstructure:"authSigninURL"`
	TLS                      *ClientTLS `json:"tls,omitempty" mapstructure:"tls"`

	// SkipAuthWhen holds the rules that exempt a request from authentication.
	// A request is exempt when ANY rule matches.
	SkipAuthWhen SkipRules `json:"skipAuthWhen,omitempty" mapstructure:"skipAuthWhen"`

	// Debug logs the compiled rules at startup and the outcome of every
	// request to stdout. Off by default, and costs nothing per request while
	// off (see debugLog).
	//
	// Not for production: it writes a line per request, and those lines
	// contain the host, path and client IP.
	Debug bool `json:"debug,omitempty" mapstructure:"debug"`
}

// SkipRules is the skipAuthWhen section: a closed set of request attributes,
// each with its own predicates, plus an escape hatch of template-driven
// custom rules.
//
// Every key is optional and is only evaluated — and only has its request
// attribute computed — when present. Rules are tested in the order of the
// fields below; authentication is skipped as soon as one matches.
//
// A predefined key beats an equivalent custom rule on every request: there is
// no template to render, and only the attributes that some rule actually needs
// are extracted from the request (see argsNeed).
type SkipRules struct {
	// Host tests the request's Host header; equivalent to the custom
	// expression "{ .Host }".
	Host *SkipRule `json:"host,omitempty" mapstructure:"host"`

	// Path tests the cleaned URL path; equivalent to "{ .Path }".
	Path *SkipRule `json:"path,omitempty" mapstructure:"path"`

	// URL tests host and path joined with no separator, e.g.
	// "api.example.com/v1/users"; equivalent to "{ .Host }{ .Path }".
	URL *SkipRule `json:"url,omitempty" mapstructure:"url"`

	// ClientIP tests the peer IP; equivalent to "{ .ClientIp }". This is the
	// only key that accepts inSubnet.
	ClientIP *SkipRule `json:"clientIp,omitempty" mapstructure:"clientIp"`

	// UserAgent tests the User-Agent header; equivalent to "{ .UserAgent }".
	UserAgent *SkipRule `json:"userAgent,omitempty" mapstructure:"userAgent"`

	// Custom holds template-driven rules for anything the keys above cannot
	// express (method, scheme, or any combination). Each entry requires an
	// Expression. Slower than the predefined keys: the template is rendered on
	// every request and every RequestArgs field has to be populated for it.
	Custom []SkipRule `json:"custom,omitempty" mapstructure:"custom"`
}

// SkipRule is the set of predicates attached to one key of SkipRules.
//
// The value under test — the host, the path, the rendered expression, … — is
// matched against every predicate. A rule matches when ANY value of ANY
// predicate matches (logical OR).
//
// A rule with no predicates is rejected at load time: it could never match and
// is therefore always a configuration mistake.
//
// NOTE: one flat type serves every key on purpose. Expression is only valid
// under custom and InSubnet only under clientIp, and NewAuthSkipper rejects
// them anywhere else. The alternative — separate types sharing an embedded
// struct — does not survive Yaegi, which does not mark embedded fields as
// Anonymous, so mapstructure's `squash` would silently decode nothing. A flat
// type also means a key in the wrong place is an error rather than silently
// ignored, which is what mapstructure does with unknown keys.
type SkipRule struct {
	// Expression is the Go template evaluated against RequestArgs, e.g.
	// "{ .Method } { .Host }{ .Path }". Required under custom, rejected
	// everywhere else.
	Expression string `json:"expression,omitempty" mapstructure:"expression"`

	// IsExactly matches the value by exact equality. Backed by a lookup map, so
	// the cost is constant regardless of how many values there are.
	IsExactly []string `json:"isExactly,omitempty" mapstructure:"isExactly"`

	// StartsWith matches when the value has any of these prefixes.
	StartsWith []string `json:"startsWith,omitempty" mapstructure:"startsWith"`

	// EndsWith matches when the value has any of these suffixes.
	EndsWith []string `json:"endsWith,omitempty" mapstructure:"endsWith"`

	// Contains matches when the value contains any of these substrings.
	Contains []string `json:"contains,omitempty" mapstructure:"contains"`

	// MatchesRegex matches when the value matches any of these RE2 patterns.
	// Matching is partial; anchor with ^ and $ for a full match.
	MatchesRegex []string `json:"matchesRegex,omitempty" mapstructure:"matchesRegex"`

	// InSubnet matches when the client IP lies within any of these networks,
	// written in CIDR notation ("10.0.0.0/8", "2001:db8::/32") or as a bare
	// address ("127.0.0.1"), which stands for itself. Only valid under
	// clientIp, rejected everywhere else.
	InSubnet []string `json:"inSubnet,omitempty" mapstructure:"inSubnet"`
}

// RequestArgs is the per-request data rules are evaluated against: the
// predefined keys read their field directly, and custom expressions are
// rendered against the whole struct. It is the complete set of substitutions a
// custom rule may use.
//
// There is exactly one spelling per field ({ .Host }, never { .host }); an
// unknown field is an error rather than a silently empty value, both at startup
// (see NewAuthSkipper) and at request time (see compiledSkipRule.matches).
//
// Only the fields some configured rule needs are populated (see argsNeed and
// newRequestArgs); the rest are left empty.
//
// SECURITY: every field is populated from the request line, the Host /
// User-Agent headers or the connection itself — never from a client-supplied
// X-Forwarded-* header. These values gate an authentication bypass, so they
// must not be spoofable, and they are deliberately independent of
// trustForwardHeader. See newRequestArgs.
type RequestArgs struct {
	// Host is the request's Host header (may include a port), e.g.
	// "api.example.com".
	Host string
	// Path is the decoded URL path, normalized with path.Clean. It never
	// contains the query string or fragment. See cleanPath.
	Path string
	// Method is the HTTP method, e.g. "GET".
	Method string
	// Scheme is the scheme of the accepted connection: "https" when TLS was
	// terminated by Traefik, "http" otherwise.
	Scheme string
	// UserAgent is the User-Agent header. Client-supplied, and therefore
	// trivially spoofable: do not use it as the sole predicate of an exemption.
	UserAgent string
	// ClientIp is the peer address of the connection without its port, always
	// derived from RemoteAddr. See clientIP.
	ClientIp string
}

// argsNeed is a bit set of RequestArgs fields.
//
// Each configured rule needs some fields of RequestArgs and no others; the
// union over all rules is computed once at startup and tells newRequestArgs
// which fields to extract. Extraction is skipped entirely when nothing needs
// anything (no rules, debug off), and the cheapest configurations — a host or
// path rule — extract exactly one field.
type argsNeed uint8

const (
	needHost argsNeed = 1 << iota
	needPath
	needMethod
	needScheme
	needUserAgent
	needClientIP

	needNone argsNeed = 0
	// needAll is what a custom template and the debug logger require: an
	// expression may reference any field, and a debug line prints most of them.
	needAll = needHost | needPath | needMethod | needScheme | needUserAgent | needClientIP
)

// CreateConfig creates the default plugin configuration.
//
// NOTE: maxBodySize deliberately DIVERGES from upstream Traefik, whose
// dynamic.ForwardAuthDefaultMaxBodySize is -1 (unlimited). Traefik's own
// documentation warns that unlimited body forwarding is a DoS/memory-exhaustion
// risk and "strongly recommends" setting a limit, so this plugin defaults to
// 4 MiB. Set maxBodySize: -1 explicitly to restore upstream behaviour.
func CreateConfig() *Config {
	defaultMaxBodySize := int64(4194304) // 4 MiB; upstream default is -1 (unlimited)
	defaultMaxResponseBodySize := int64(-1)

	return &Config{
		MaxBodySize:         &defaultMaxBodySize,
		MaxResponseBodySize: &defaultMaxResponseBodySize,
	}
}
