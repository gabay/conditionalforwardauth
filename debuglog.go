package conditionalforwardauth

// This file owns debug output: what a line looks like and where it goes.
// Nothing else in the plugin touches os.Stdout.

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Traefik gives plugins no logger. Per its plugin documentation, the only way
// to emit anything is to write to os.Stdout or os.Stderr, so debug lines go to
// stdout with a prefix that makes them greppable out of Traefik's own output.
//
// This is a variable solely so that tests can capture what is written.
//
//nolint:gochecknoglobals // no logger is reachable from a plugin; see above.
var debugOutput io.Writer = os.Stdout

// debugLog writes the plugin's debug lines.
//
// A nil *debugLog is valid and discards everything: that is how `debug: false`
// is implemented. Call sites stay unconditional and pay only an inlined nil
// check, so disabling debug costs nothing per request beyond that.
type debugLog struct {
	// prefix is precomputed because it starts every line.
	prefix string
}

// newDebugLog returns nil when debug is disabled.
func newDebugLog(enabled bool, middlewareName string) *debugLog {
	if !enabled {
		return nil
	}

	return &debugLog{prefix: "[conditionalforwardauth:" + middlewareName + "] "}
}

func (d *debugLog) printf(format string, args ...interface{}) {
	if d == nil {
		return
	}

	// One Write per line: stdout is shared with Traefik's own output and with
	// concurrently handled requests, and a single write keeps a line whole.
	_, _ = io.WriteString(debugOutput, d.prefix+fmt.Sprintf(format, args...)+"\n")
}

// logStartup dumps the compiled configuration once, at plugin creation.
func (d *debugLog) logStartup(skipper *AuthSkipper) {
	if d == nil {
		return
	}

	rules := skipper.describeRules()
	if len(rules) == 0 {
		d.printf("debug on, no skip rules: every request goes to forward auth")
		return
	}

	d.printf("debug on, %d skip rule(s):", len(rules))
	for _, rule := range rules {
		d.printf("%s", rule)
	}
}

// logSkip records a request that was exempted from authentication.
func (d *debugLog) logSkip(args RequestArgs, m ruleMatch) {
	if d == nil {
		return
	}

	// The rendered expression is only worth showing when it differs from the
	// pattern, which it always does except for isExactly.
	var rendered string
	if m.rendered != m.pattern {
		rendered = fmt.Sprintf(" in %q", m.rendered)
	}

	d.printf("skip %s -> rule[%d] %s %q%s", requestLine(args), m.index, m.predicate, m.pattern, rendered)
}

// logAuth records a request that is being handed to the auth server.
func (d *debugLog) logAuth(args RequestArgs) {
	if d == nil {
		return
	}

	d.printf("auth %s", requestLine(args))
}

// requestLine is the request identity shared by every request-scoped line.
//
// UserAgent is deliberately left out: it is long, rarely the discriminator, and
// when a rule does match on it the rendered expression already shows it.
func requestLine(args RequestArgs) string {
	var b strings.Builder

	b.WriteString(args.Method)
	b.WriteString(" ")
	b.WriteString(args.Scheme)
	b.WriteString("://")
	b.WriteString(args.Host)
	b.WriteString(args.Path)
	b.WriteString(" from ")
	b.WriteString(args.ClientIp)

	return b.String()
}
