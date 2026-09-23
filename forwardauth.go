// Based on https://github.com/traefik/traefik/blob/cb4e823598ad4cfb5fad006d48a8bf140055673c/pkg/middlewares/auth/forward.go
// Traefik is MIT licensed.
// The following code is fundamentally from traefik/traefik, heavily stripped to rely only on standard libraries.
// STRIPPED: logging, tracing, specific dependency imports.

package conditionalforwardauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const typeNameForward = "ForwardAuth"

var errResponseBodyTooLarge = errors.New("response body too large")

// hopHeaders Hop-by-hop headers to be removed in the authentication request.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
// Proxy-Authorization header is forwarded to the authentication server (see https://tools.ietf.org/html/rfc7235#section-4.4).
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

var userAgentHeader = http.CanonicalHeaderKey("User-Agent")

type forwardAuth struct {
	address                  string
	authResponseHeaders      []string
	authResponseHeadersRegex *regexp.Regexp
	next                     http.Handler
	name                     string
	client                   http.Client
	trustForwardHeader       *bool
	authRequestHeaders       []string
	maxResponseBodySize      int64
	addAuthCookiesToResponse map[string]struct{}
	headerField              string
	forwardBody              bool
	maxBodySize              int64
	preserveLocationHeader   bool
	preserveRequestMethod    bool
	authSigninURL            string
}

// NewForward creates a forward auth middleware.
func NewForwardAuth(ctx context.Context, next http.Handler, config *Config) (http.Handler, error) {

	addAuthCookiesToResponse := make(map[string]struct{})
	for _, cookieName := range config.AddAuthCookiesToResponse {
		addAuthCookiesToResponse[cookieName] = struct{}{}
	}

	fa := &forwardAuth{
		address:                  config.Address,
		authResponseHeaders:      config.AuthResponseHeaders,
		next:                     next,
		trustForwardHeader:       config.TrustForwardHeader,
		authRequestHeaders:       config.AuthRequestHeaders,
		addAuthCookiesToResponse: addAuthCookiesToResponse,
		headerField:              config.HeaderField,
		forwardBody:              config.ForwardBody,
		maxBodySize:              -1,
		preserveLocationHeader:   config.PreserveLocationHeader,
		preserveRequestMethod:    config.PreserveRequestMethod,
		authSigninURL:            config.AuthSigninURL,
	}

	// CHANGED: *int64 like upstream's dynamic.ForwardAuth, so that an explicit
	// 0 is distinguishable from "unset". The previous non-pointer sentinel
	// (!= 0) silently turned `maxBodySize: 0` into unlimited.
	// STRIPPED: upstream logs a warning here when no limit is configured.
	if config.MaxBodySize != nil {
		fa.maxBodySize = *config.MaxBodySize
	}

	if config.MaxResponseBodySize != nil {
		fa.maxResponseBodySize = *config.MaxResponseBodySize
	} else {
		fa.maxResponseBodySize = -1
	}

	// Ensure our request client does not follow redirects
	fa.client = http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	if config.TLS != nil {
		// STRIPPED: upstream warns here that tls.CAOptional is deprecated.
		// The field is accepted and ignored; see ClientTLS.CAOptional.

		// CHANGED: local ClientTLS instead of types.ClientTLS
		clientTLS := config.TLS

		tr, err := createTransport(clientTLS)
		if err != nil {
			return nil, fmt.Errorf("unable to create client TLS configuration: %w", err)
		}
		fa.client.Transport = tr
	}

	if config.AuthResponseHeadersRegex != "" {
		re, err := regexp.Compile(config.AuthResponseHeadersRegex)
		if err != nil {
			return nil, fmt.Errorf("error compiling regular expression %s: %w", config.AuthResponseHeadersRegex, err)
		}
		fa.authResponseHeadersRegex = re
	}

	if config.TrustForwardHeader == nil {
	} else if *config.TrustForwardHeader && len(fa.authRequestHeaders) > 0 {
		fa.authRequestHeaders = append(fa.authRequestHeaders, xHeaders...)
	}

	return fa, nil
}

func (fa *forwardAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	forwardReqMethod := http.MethodGet
	if fa.preserveRequestMethod {
		forwardReqMethod = req.Method
	}

	forwardReq, err := http.NewRequestWithContext(req.Context(), forwardReqMethod, fa.address, nil)
	if err != nil {

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	forwardBody := fa.forwardBody
	// When a CONNECT method has a body with an unknown length we consider the bytes as tunnel data.
	// Therefore, we do not want to forward them to the auth server.
	if req.Method == http.MethodConnect && req.ContentLength < 0 {
		forwardBody = false
	}

	if forwardBody {
		forwardReq.ContentLength = req.ContentLength
		forwardReq.TransferEncoding = req.TransferEncoding

		bodyBytes, err := fa.readBodyBytes(req)
		if errors.Is(err, errBodyTooLarge) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		// bodyBytes is nil when the request has no body.
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			forwardReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	if fa.trustForwardHeader != nil {
		writeHeader(req, forwardReq, *fa.trustForwardHeader, fa.authRequestHeaders)
	} else {
		oldWriteHeader(req, forwardReq, fa.authRequestHeaders)
	}

	forwardResponse, forwardErr := fa.client.Do(forwardReq)
	if forwardErr != nil {

		statusCode := http.StatusInternalServerError
		if errors.Is(forwardErr, context.Canceled) {
			statusCode = 499 /* StatusClientClosedRequest */
		}

		rw.WriteHeader(statusCode)
		return
	}
	defer forwardResponse.Body.Close()

	body, readError := fa.readResponseBodyBytes(forwardResponse)
	if readError != nil {
		if errors.Is(readError, errResponseBodyTooLarge) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Ending the forward request span as soon as the response is handled.
	// If any errors happen earlier, this span will be close by the defer instruction.

	if fa.headerField != "" {
		// STRIPPED: accesslog
		if elems := forwardResponse.Header[http.CanonicalHeaderKey(fa.headerField)]; len(elems) > 0 {
		}
	}

	// If auth server returns 401 and AuthSigninURL is configured, redirect to signin URL.
	if fa.authSigninURL != "" && forwardResponse.StatusCode == http.StatusUnauthorized {
		http.Redirect(rw, req, fa.authSigninURL, http.StatusFound)
		return
	}

	// Pass the forward response's body and selected headers if it
	// didn't return a response within the range of [200, 300).
	if forwardResponse.StatusCode < http.StatusOK || forwardResponse.StatusCode >= http.StatusMultipleChoices {

		copyHeaders(rw.Header(), forwardResponse.Header)
		removeHeaders(rw.Header(), hopHeaders...)

		redirectURL, err := fa.redirectURL(forwardResponse)
		if err != nil {
			if !errors.Is(err, http.ErrNoLocation) {

				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
		} else if redirectURL.String() != "" {
			// Set the location in our response if one was sent back.
			rw.Header().Set("Location", redirectURL.String())
		}
		rw.WriteHeader(forwardResponse.StatusCode)

		if _, err = rw.Write(body); err != nil {
		}
		return
	}

	// Only the operator-listed authResponseHeaders are stripped and replaced with
	// the auth server's verified values. Any other header the client sends is
	// forwarded to the backend unchanged, mirroring ingress-nginx's
	// auth-response-headers semantics. By design, Traefik asserts no identity the
	// operator did not opt into: trusting unlisted client headers downstream is a
	// backend misconfiguration, not a spoofing flaw here.
	// Note: the header names aliasing the authResponseHeaders (e.g. X_Auth_User or X.Auth.User) are not handled here,
	// as the aliasHeadersStrategy entry point option is expected to be enabled to prevent header spoofing.
	for _, headerName := range fa.authResponseHeaders {
		headerKey := http.CanonicalHeaderKey(headerName)
		req.Header.Del(headerKey)
		if len(forwardResponse.Header[headerKey]) > 0 {
			req.Header[headerKey] = append([]string(nil), forwardResponse.Header[headerKey]...)
		}
	}

	if fa.authResponseHeadersRegex != nil {
		for headerKey := range req.Header {
			if fa.authResponseHeadersRegex.MatchString(headerKey) {
				req.Header.Del(headerKey)
			}
		}

		for headerKey, headerValues := range forwardResponse.Header {
			if fa.authResponseHeadersRegex.MatchString(headerKey) {
				req.Header[headerKey] = append([]string(nil), headerValues...)
			}
		}
	}

	req.RequestURI = req.URL.RequestURI()

	authCookies := forwardResponse.Cookies()
	if len(authCookies) == 0 {
		fa.next.ServeHTTP(rw, req)
		return
	}

	fa.next.ServeHTTP(newResponseModifier(rw, req, fa.buildModifier(authCookies)), req)
}

func (fa *forwardAuth) redirectURL(forwardResponse *http.Response) (*url.URL, error) {
	if !fa.preserveLocationHeader {
		return forwardResponse.Location()
	}

	// Preserve the Location header if it exists.
	if lv := forwardResponse.Header.Get("Location"); lv != "" {
		return url.Parse(lv)
	}
	return nil, http.ErrNoLocation
}

func (fa *forwardAuth) buildModifier(authCookies []*http.Cookie) func(res *http.Response) error {
	return func(res *http.Response) error {
		cookies := res.Cookies()
		res.Header.Del("Set-Cookie")

		for _, cookie := range cookies {
			if _, found := fa.addAuthCookiesToResponse[cookie.Name]; !found {
				res.Header.Add("Set-Cookie", cookie.String())
			}
		}

		for _, cookie := range authCookies {
			if _, found := fa.addAuthCookiesToResponse[cookie.Name]; found {
				res.Header.Add("Set-Cookie", cookie.String())
			}
		}

		return nil
	}
}

var errBodyTooLarge = errors.New("request body too large")

func (fa *forwardAuth) readBodyBytes(req *http.Request) ([]byte, error) {
	if fa.maxBodySize < 0 {
		return io.ReadAll(req.Body)
	}

	body := make([]byte, fa.maxBodySize+1)
	n, err := io.ReadFull(req.Body, body)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("reading body bytes: %w", err)
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return body[:n], nil
	}
	return nil, errBodyTooLarge
}

func (fa *forwardAuth) readResponseBodyBytes(res *http.Response) ([]byte, error) {
	if fa.maxResponseBodySize < 0 {
		return io.ReadAll(res.Body)
	}

	body := make([]byte, fa.maxResponseBodySize+1)
	n, err := io.ReadFull(res.Body, body)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("reading response body bytes: %w", err)
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return body[:n], nil
	}
	return nil, errResponseBodyTooLarge
}

func writeHeader(req, forwardReq *http.Request, trustForwardHeader bool, allowedHeaders []string) {
	copyHeaders(forwardReq.Header, req.Header)

	removeConnectionHeaders(forwardReq)
	removeHeaders(forwardReq.Header, hopHeaders...)

	if !trustForwardHeader {
		deleteXForwardedHeaders(forwardReq.Header)
	}

	if _, ok := req.Header[userAgentHeader]; !ok {
		// If the incoming request doesn't have a User-Agent header set,
		// don't send the default Go HTTP client User-Agent for the forwarded request.
		forwardReq.Header.Set(userAgentHeader, "")
	}

	forwardReq.Header = filterForwardRequestHeaders(forwardReq.Header, allowedHeaders)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if prior, ok := forwardReq.Header[xForwardedFor]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		forwardReq.Header.Set(xForwardedFor, clientIP)
	}

	if _, ok := forwardReq.Header[xForwardedMethod]; !ok {
		forwardReq.Header.Set(xForwardedMethod, req.Method)
	}

	if _, ok := forwardReq.Header[xForwardedProto]; !ok {
		forwardReq.Header.Set(xForwardedProto, "http")
		if req.TLS != nil {
			forwardReq.Header.Set(xForwardedProto, "https")
		}
	}

	if _, ok := forwardReq.Header[xForwardedPort]; !ok {
		forwardReq.Header.Set(xForwardedPort, forwardedPort(req, forwardReq))
	}

	if _, ok := forwardReq.Header[xForwardedHost]; !ok {
		forwardReq.Header.Set(xForwardedHost, req.Host)
	}

	if _, ok := forwardReq.Header[xForwardedURI]; !ok {
		forwardReq.Header.Set(xForwardedURI, req.URL.RequestURI())
	}
}

// oldWriteHeader is the legacy implementation of writeHeader, which is used when TrustForwardHeader is not set (old false behavior).
// It is kept to avoid breaking existing configurations that rely on the previous behavior.
func oldWriteHeader(req, forwardReq *http.Request, allowedHeaders []string) {
	copyHeaders(forwardReq.Header, req.Header)

	removeConnectionHeaders(forwardReq)
	removeHeaders(forwardReq.Header, hopHeaders...)

	forwardReq.Header = filterForwardRequestHeaders(forwardReq.Header, allowedHeaders)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		forwardReq.Header.Set(xForwardedFor, clientIP)
	}

	proto := "http"
	if req.TLS != nil {
		proto = "https"
	}
	forwardReq.Header.Set(xForwardedProto, proto)

	forwardReq.Header.Set(xForwardedMethod, req.Method)
	forwardReq.Header.Set(xForwardedHost, req.Host)
	forwardReq.Header.Set(xForwardedURI, req.URL.RequestURI())
}

func filterForwardRequestHeaders(forwardRequestHeaders http.Header, allowedHeaders []string) http.Header {
	if len(allowedHeaders) == 0 {
		return forwardRequestHeaders
	}

	filteredHeaders := http.Header{}
	for _, headerName := range allowedHeaders {
		if values := forwardRequestHeaders.Values(headerName); len(values) > 0 {
			filteredHeaders[http.CanonicalHeaderKey(headerName)] = values
		}
	}

	return filteredHeaders
}

func forwardedPort(req, forwardReq *http.Request) string {
	if req == nil {
		return ""
	}

	if _, port, err := net.SplitHostPort(req.Host); err == nil && port != "" {
		return port
	}

	if forwardReq.Header.Get(xForwardedProto) == "https" || forwardReq.Header.Get(xForwardedProto) == "wss" {
		return "443"
	}

	if req.TLS != nil {
		return "443"
	}

	return "80"
}

// STRIPPED: oxy and forwardedheaders constants and helpers inlined here
const (
	xForwardedProto             = "X-Forwarded-Proto"
	xForwardedFor               = "X-Forwarded-For"
	xForwardedHost              = "X-Forwarded-Host"
	xForwardedPort              = "X-Forwarded-Port"
	xForwardedServer            = "X-Forwarded-Server"
	xForwardedURI               = "X-Forwarded-Uri"
	xForwardedMethod            = "X-Forwarded-Method"
	xForwardedTLSClientCert     = "X-Forwarded-Tls-Client-Cert"
	xForwardedTLSClientCertInfo = "X-Forwarded-Tls-Client-Cert-Info"
)

var xHeaders = []string{
	xForwardedProto,
	xForwardedFor,
	xForwardedHost,
	xForwardedPort,
	xForwardedServer,
	xForwardedURI,
	xForwardedMethod,
	xForwardedTLSClientCert,
	xForwardedTLSClientCertInfo,
}

var xHeadersSet map[string]struct{}

func init() {
	xHeadersSet = make(map[string]struct{})
	for _, k := range xHeaders {
		xHeadersSet[http.CanonicalHeaderKey(k)] = struct{}{}
	}
}

func deleteXForwardedHeaders(h http.Header) {
	for _, name := range xHeaders {
		h.Del(name)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		dst[k] = append(dst[k], vv...)
	}
}

func removeHeaders(h http.Header, names ...string) {
	for _, n := range names {
		h.Del(n)
	}
}

func removeConnectionHeaders(req *http.Request) {
	if req.Header == nil {
		return
	}
	if c := req.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				req.Header.Del(f)
			}
		}
	}
	req.Header.Del("Connection")
}

func getCertPool(ca string) (*x509.CertPool, error) {
	if ca == "" {
		return nil, fmt.Errorf("empty CA")
	}
	caPool := x509.NewCertPool()
	var caBytes []byte
	caBytes, err := os.ReadFile(ca)
	if err != nil {
		caBytes = []byte(ca)
	}
	if !caPool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}
	return caPool, nil
}

func createTransport(clientTLS *ClientTLS) (*http.Transport, error) {
	if clientTLS == nil {
		return DefaultTransport(), nil
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: clientTLS.InsecureSkipVerify,
	}
	if clientTLS.CA != "" {
		caPool, err := getCertPool(clientTLS.CA)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = caPool
	}
	if clientTLS.Cert != "" && clientTLS.Key != "" {
		certBytes, err := os.ReadFile(clientTLS.Cert)
		if err != nil {
			certBytes = []byte(clientTLS.Cert)
		}
		keyBytes, err := os.ReadFile(clientTLS.Key)
		if err != nil {
			keyBytes = []byte(clientTLS.Key)
		}
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate/key: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	transport := DefaultTransport()
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

// CHANGED: method-value expressions like `(&net.Dialer{...}).DialContext` broke under Yaegi and had to be wrapped in a closure.
func DefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return d.DialContext(ctx, network, addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// responseModifier implements http.ResponseWriter to capture response modifications.
type responseModifier struct {
	http.ResponseWriter
	req      *http.Request
	modifyFn func(*http.Response) error
}

// STRIPPED: using local middlewares.NewResponseModifier mock
func newResponseModifier(rw http.ResponseWriter, req *http.Request, modifyFn func(*http.Response) error) http.ResponseWriter {
	return &responseModifier{
		ResponseWriter: rw,
		req:            req,
		modifyFn:       modifyFn,
	}
}

func (rm *responseModifier) WriteHeader(statusCode int) {
	fakeResp := &http.Response{
		Header: rm.ResponseWriter.Header(),
	}
	if err := rm.modifyFn(fakeResp); err != nil {
		fmt.Printf("modifyFn error: %v", err)
	}
	rm.ResponseWriter.WriteHeader(statusCode)
}
