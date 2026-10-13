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

	// need is which RequestArgs fields to extract per request: whatever the
	// rules read, plus everything when debug is on because a debug line prints
	// the request. needNone means the request is not inspected at all.
	need argsNeed
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

	need := skipper.need
	if debug != nil {
		need = needAll
	}

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
		need:        need,
	}, nil
}

func (cfa *ConditionalForwardAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// The request is not inspected at all when there is nothing to match and
	// nothing to log, which is the common production configuration.
	if cfa.need != needNone {
		args := newRequestArgs(req, cfa.need)
		match, ok := matchRules(&cfa.skipper, args)

		// A nil *debugLog absorbs every call, but under Yaegi the call itself
		// is what costs (see the note above matchRules), so it is guarded.
		if cfa.debug != nil {
			cfa.debug.logDecision(args, match, ok)
		}

		if ok {
			cfa.next.ServeHTTP(rw, req)
			return
		}
	}

	// The ForwardAuth handler was constructed with `next`, so it calls it
	// itself on success. Nothing else happens here by design.
	cfa.forwardAuth.ServeHTTP(rw, req)
}

// newRequestArgs extracts the requested fields from a request; the others are
// left empty. Extracting only what the configured rules read is part of what
// makes a predefined rule cheaper than a custom template, which needs every
// field.
//
// No value here is derived from a client-supplied X-Forwarded-* header. These
// substitutions gate an authentication bypass, so they are taken only from the
// request line, the Host header and the connection itself. That keeps the
// exemption rules independent of trustForwardHeader.
func newRequestArgs(req *http.Request, need argsNeed) RequestArgs {
	var args RequestArgs

	if need&needHost != 0 {
		args.Host = req.Host
	}
	if need&needPath != 0 {
		args.Path = cleanPath(req.URL.Path)
	}
	if need&needMethod != 0 {
		args.Method = req.Method
	}
	if need&needScheme != 0 {
		args.Scheme = requestScheme(req)
	}
	if need&needUserAgent != 0 {
		args.UserAgent = req.UserAgent()
	}
	if need&needClientIP != 0 {
		args.ClientIp = clientIP(req)
	}

	return args
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
// rules with host / path.
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
//	clientIp:
//	  inSubnet: ["10.0.0.0/8"]
//
// therefore matches only a direct peer. Note that when Traefik sits behind
// another proxy or load balancer, RemoteAddr is that intermediary's address,
// not the end user's, so such a rule would exempt everything arriving through
// it. Prefer host / path rules in that topology.
func clientIP(req *http.Request) string {
	// SplitHostPort keeps IPv6 literals such as "[2001:db8::1]:54321" intact.
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}
