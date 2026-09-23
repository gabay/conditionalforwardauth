package conditionalforwardauth

// This file holds every configuration type of the plugin, plus RequestArgs,
// the single representation of a request that expressions are rendered
// against. Request handling lives in conditionalforwardauth.go and rule
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

	// SkipAuthWhen lists the rules that exempt a request from authentication.
	// A request is exempt when ANY rule matches.
	SkipAuthWhen []SkipRule `json:"skipAuthWhen,omitempty" mapstructure:"skipAuthWhen"`

	// Debug logs the compiled rules at startup and the outcome of every
	// request to stdout. Off by default, and costs nothing per request while
	// off (see debugLog).
	//
	// Not for production: it writes a line per request, and those lines
	// contain the host, path and client IP.
	Debug bool `json:"debug,omitempty" mapstructure:"debug"`
}

// SkipRule is a single entry of the skipAuthWhen list.
//
// Expression is a Go template rendered against RequestArgs. The rendered
// string is then tested against every predicate below. A rule matches when ANY
// value of ANY predicate matches (logical OR), and auth is skipped when ANY
// rule matches.
//
// A rule with no predicates is rejected at load time: it could never match and
// is therefore always a configuration mistake.
type SkipRule struct {
	// Expression is the Go template evaluated against RequestArgs, e.g.
	// "{ .Host }" or "{ .Method } { .Host }{ .Path }". Required.
	Expression string `json:"expression,omitempty" mapstructure:"expression"`

	// IsExactly matches the rendered expression by exact equality. Backed by a
	// lookup map, so the cost is constant regardless of how many values there are.
	IsExactly []string `json:"isExactly,omitempty" mapstructure:"isExactly"`

	// StartsWith matches when the rendered expression has any of these prefixes.
	StartsWith []string `json:"startsWith,omitempty" mapstructure:"startsWith"`

	// EndsWith matches when the rendered expression has any of these suffixes.
	EndsWith []string `json:"endsWith,omitempty" mapstructure:"endsWith"`

	// Contains matches when the rendered expression contains any of these substrings.
	Contains []string `json:"contains,omitempty" mapstructure:"contains"`

	// MatchesRegex matches when the rendered expression matches any of these RE2
	// patterns. Matching is partial; anchor with ^ and $ for a full match.
	MatchesRegex []string `json:"matchesRegex,omitempty" mapstructure:"matchesRegex"`
}

// RequestArgs is the data an expression template is rendered against: it is the
// complete set of substitutions a skip rule may use.
//
// There is exactly one spelling per field ({ .Host }, never { .host }); an
// unknown field is an error rather than a silently empty value, both at startup
// (see NewAuthSkipper) and at request time (see compiledSkipRule.matches).
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
