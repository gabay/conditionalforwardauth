package conditionalforwardauth

// This file owns the plugin entry points and everything that touches an
// *http.Request: turning a request into RequestArgs and dispatching it to
// either `next` or the internal ForwardAuth handler. Configuration types live
// in config.go and the rule engine lives in authskipper.go.

import (
	"context"
	"net"
	"net/http"
	"path"
)

// ConditionalForwardAuth wraps a ForwardAuth handler with skip rules.
type ConditionalForwardAuth struct {
	skipper     AuthSkipper
	forwardAuth http.Handler
	next        http.Handler
	debug       *debugLog // nil unless config.Debug is set; see debuglog.go.
}

// New creates a new ConditionalForwardAuth plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	skipper, err := NewAuthSkipper(config.SkipAuthWhen)
	if err != nil {
		return nil, err
	}

	// Dumped only once the rules are known to be good: a misconfiguration is
	// reported as a startup error, not as a debug line.
	debug := newDebugLog(config.Debug, name)
	debug.logStartup(skipper)

	fa, err := NewForwardAuth(ctx, next, config)
	if err != nil {
		return nil, err
	}

	// Note: trustForwardHeader intentionally plays no part in skip matching.
	// It still configures the ForwardAuth handler itself; the skip inputs are
	// taken only from the request line, Host/User-Agent and the connection.
	return &ConditionalForwardAuth{
		skipper:     *skipper,
		forwardAuth: fa,
		next:        next,
		debug:       debug,
	}, nil
}

func (cfa *ConditionalForwardAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Building RequestArgs is skipped entirely when there is nothing to match
	// and nothing to log, which is the common production configuration.
	if !cfa.skipper.empty() || cfa.debug != nil {
		args := newRequestArgs(req)

		if match, ok := cfa.skipper.matches(args); ok {
			cfa.debug.logSkip(args, match)
			cfa.next.ServeHTTP(rw, req)
			return
		}

		cfa.debug.logAuth(args)
	}

	// The ForwardAuth handler was constructed with `next`, so it calls it
	// itself on success. Nothing else happens here by design.
	cfa.forwardAuth.ServeHTTP(rw, req)
}

// newRequestArgs extracts the expression substitutions from a request.
//
// No value here is derived from a client-supplied X-Forwarded-* header. These
// substitutions gate an authentication bypass, so they are taken only from the
// request line, the Host header and the connection itself. That keeps the
// exemption rules independent of trustForwardHeader.
func newRequestArgs(req *http.Request) RequestArgs {
	return RequestArgs{
		Host:      req.Host,
		Path:      cleanPath(req.URL.Path),
		Method:    req.Method,
		Scheme:    requestScheme(req),
		UserAgent: req.UserAgent(),
		ClientIp:  clientIP(req),
	}
}

// cleanPath normalizes the request path before matching.
//
// Deliberate divergence from the raw request: path.Clean resolves "." and ".."
// segments, so "/public/../admin" is matched as "/admin" and cannot slip past a
// `startsWith: /public` exemption while the backend serves /admin.
//
// Note this also strips a trailing slash ("/health/" matches as "/health"), and
// that the path is the decoded URL path, never including query or fragment.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	return path.Clean(p)
}

// requestScheme reports the scheme of the connection Traefik accepted.
//
// X-Forwarded-Proto is deliberately NOT consulted: it is client-supplied, and
// honouring it would let a client flip { .Scheme } to satisfy an exemption
// rule. If Traefik itself sits behind another proxy, prefer expressing such
// rules with { .Host } / { .Path }.
func requestScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	if req.URL != nil && req.URL.Scheme != "" {
		return req.URL.Scheme
	}
	return "http"
}

// clientIP returns the peer address of the connection, without its port.
//
// This is ALWAYS req.RemoteAddr — the address Traefik actually accepted the
// connection from. X-Forwarded-For is never consulted, regardless of
// trustForwardHeader, because it is client-supplied and this value can exempt a
// request from authentication. A rule such as
//
//	expression: "{ .ClientIp }"
//	isExactly: ["10.0.0.5"]
//
// therefore matches only a direct peer. Note that when Traefik sits behind
// another proxy or load balancer, RemoteAddr is that intermediary's address,
// not the end user's, so such a rule would exempt everything arriving through
// it. Prefer { .Host } / { .Path } rules in that topology.
func clientIP(req *http.Request) string {
	// SplitHostPort keeps IPv6 literals such as "[2001:db8::1]:54321" intact.
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}
