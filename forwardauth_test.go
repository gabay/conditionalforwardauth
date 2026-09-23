package conditionalforwardauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForwardAuth_2xx(t *testing.T) {
	authStarted := false
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authStarted = true
		w.Header().Set("X-Auth-User", "test-user")
		w.Header().Set("X-Auth-Filtered", "ignored")
		w.Header().Set("X-Regex-Allow", "allowed")
		w.WriteHeader(200)
	}))
	defer authServer.Close()

	nextCalled := false
	var finalReq *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		finalReq = r
	})

	cfg := &Config{
		Address:                  authServer.URL,
		AuthResponseHeaders:      []string{"X-Auth-User"},
		AuthResponseHeadersRegex: "^X-Regex-.*",
	}

	fa, err := NewForwardAuth(context.Background(), next, cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rw := httptest.NewRecorder()

	fa.ServeHTTP(rw, req)

	if !authStarted {
		t.Fatal("expected auth server to be called")
	}
	if !nextCalled {
		t.Fatal("expected next to be called")
	}
	if finalReq.Header.Get("X-Auth-User") != "test-user" {
		t.Errorf("expected X-Auth-User=test-user, got %v", finalReq.Header.Get("X-Auth-User"))
	}
	if finalReq.Header.Get("X-Auth-Filtered") != "" {
		t.Errorf("expected X-Auth-Filtered to be stripped")
	}
	if finalReq.Header.Get("X-Regex-Allow") != "allowed" {
		t.Errorf("expected regex allowed header, got %q", finalReq.Header.Get("X-Regex-Allow"))
	}
}

func TestForwardAuth_Non2xx(t *testing.T) {
	authStarted := false
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authStarted = true
		w.WriteHeader(401)
		w.Write([]byte("unauthorized"))
	}))
	defer authServer.Close()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	cfg := &Config{
		Address: authServer.URL,
	}

	fa, err := NewForwardAuth(context.Background(), next, cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rw := httptest.NewRecorder()

	fa.ServeHTTP(rw, req)

	if !authStarted {
		t.Fatal("expected auth server to be called")
	}
	if nextCalled {
		t.Fatal("expected next to NOT be called")
	}
	if rw.Code != 401 {
		t.Errorf("expected 401, got %v", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), "unauthorized") {
		t.Errorf("expected body to contain unauthorized, got %v", rw.Body.String())
	}
}

func TestForwardAuth_302Location(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(302)
	}))
	defer authServer.Close()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	tests := []struct {
		preserve         bool
		expectedLocation string
	}{
		{true, "/login"},
		{false, authServer.URL + "/login"},
	}

	for _, tt := range tests {
		cfg := &Config{
			Address:                authServer.URL,
			PreserveLocationHeader: tt.preserve,
		}

		fa, err := NewForwardAuth(context.Background(), next, cfg)
		if err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw := httptest.NewRecorder()

		fa.ServeHTTP(rw, req)

		if nextCalled {
			t.Fatal("expected next to NOT be called")
		}
		if rw.Code != 302 {
			t.Errorf("expected 302, got %v", rw.Code)
		}
		if loc := rw.Header().Get("Location"); loc != tt.expectedLocation {
			t.Errorf("preserve %v: expected Location %v, got %v", tt.preserve, tt.expectedLocation, loc)
		}
	}
}

func TestForwardAuth_AuthRequestHeaders(t *testing.T) {
	var authReq *http.Request
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authReq = r
		w.WriteHeader(200)
	}))
	defer authServer.Close()

	cfg := &Config{
		Address:            authServer.URL,
		AuthRequestHeaders: []string{"X-Requested-Allow"},
	}
	fa, err := NewForwardAuth(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Set("X-Requested-Allow", "yes")
	req.Header.Set("X-Requested-Deny", "no")

	rw := httptest.NewRecorder()
	fa.ServeHTTP(rw, req)

	if authReq.Header.Get("X-Requested-Allow") != "yes" {
		t.Errorf("expected allowed header present")
	}
	if authReq.Header.Get("X-Requested-Deny") != "" {
		t.Errorf("expected denied header absent")
	}
}

func boolPtr(b bool) *bool { return &b }

func TestForwardAuth_XForwardedHeaders(t *testing.T) {
	var authReq *http.Request
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authReq = r
		w.WriteHeader(200)
	}))
	defer authServer.Close()

	tests := []struct {
		trust *bool
	}{
		{boolPtr(true)},
		{boolPtr(false)},
		{nil},
	}

	for _, tt := range tests {
		cfg := &Config{
			Address:            authServer.URL,
			TrustForwardHeader: tt.trust,
		}
		fa, err := NewForwardAuth(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg)
		if err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.Header.Set("X-Forwarded-Proto", "spoofed")
		req.Header.Set("X-Forwarded-Method", "SPOOF")
		req.Header.Set("X-Forwarded-Tls-Client-Cert", "spoofed-cert")
		// Set remote addr
		req.RemoteAddr = "192.168.0.1:12345"
		rw := httptest.NewRecorder()
		fa.ServeHTTP(rw, req)

		if tt.trust != nil && *tt.trust {
			if authReq.Header.Get("X-Forwarded-Proto") != "spoofed" {
				t.Errorf("trust=true: expected spoofed header to persist")
			}
			if authReq.Header.Get("X-Forwarded-Tls-Client-Cert") != "spoofed-cert" {
				t.Errorf("trust=true: expected spoofed cert header to persist")
			}
		} else if tt.trust != nil && !*tt.trust {
			if authReq.Header.Get("X-Forwarded-Proto") == "spoofed" {
				t.Errorf("trust=false: expected spoofed header to drop")
			}
			if authReq.Header.Get("X-Forwarded-Method") == "SPOOF" {
				t.Errorf("trust=false: unexpected spoof meth")
			}
			if authReq.Header.Get("X-Forwarded-Tls-Client-Cert") != "" {
				t.Errorf("trust=false: expected spoofed cert header to drop")
			}
		} else {
			// tt.trust == nil (legacy oldWriteHeader behavior)
			if authReq.Header.Get("X-Forwarded-Proto") == "spoofed" {
				t.Errorf("trust=nil: expected spoofed proto to be overwritten")
			}
			if authReq.Header.Get("X-Forwarded-Tls-Client-Cert") != "spoofed-cert" {
				// leaked header in legacy mode!
				t.Errorf("trust=nil: expected spoofed cert header to LEAK because oldWriteHeader didn't strip it")
			}
		}

		if !strings.Contains(authReq.Header.Get("X-Forwarded-For"), "192.168.0.1") {
			t.Errorf("expected real IP in X-Forwarded-For. Got: %s", authReq.Header.Get("X-Forwarded-For"))
		}
	}
}

func TestForwardAuth_IPv6(t *testing.T) {
	var authReq *http.Request
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authReq = r
		w.WriteHeader(200)
	}))
	defer authServer.Close()

	cfg := &Config{Address: authServer.URL}
	fa, err := NewForwardAuth(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.RemoteAddr = "[2001:db8::1]:1234"

	rw := httptest.NewRecorder()
	fa.ServeHTTP(rw, req)

	if authReq.Header.Get("X-Forwarded-For") != "2001:db8::1" {
		t.Errorf("expected IPv6 IP correctly extracted, got %v", authReq.Header.Get("X-Forwarded-For"))
	}
}

func TestForwardAuth_ForwardBody(t *testing.T) {
	var bodyStr string
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyStr = string(b)
		w.WriteHeader(200)
	}))
	defer authServer.Close()

	cfg := &Config{
		Address:     authServer.URL,
		ForwardBody: true,
		MaxBodySize: int64Ptr(10),
	}
	fa, err := NewForwardAuth(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "http://example.com/foo", strings.NewReader("1234567"))
	rw := httptest.NewRecorder()
	fa.ServeHTTP(rw, req)

	if bodyStr != "1234567" {
		t.Errorf("expected body to be forwarded")
	}

	// Test too large
	req2 := httptest.NewRequest("POST", "http://example.com/foo", strings.NewReader("1234567890123"))
	rw2 := httptest.NewRecorder()
	fa.ServeHTTP(rw2, req2)
	if rw2.Code != 401 {
		t.Errorf("expected 401 on too large body, got %v", rw2.Code)
	}

}

func TestForwardAuth_AuthSigninURL(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer authServer.Close()

	cfg := &Config{
		Address:       authServer.URL,
		AuthSigninURL: "/login",
	}
	fa, _ := NewForwardAuth(context.Background(), nil, cfg)
	req := httptest.NewRequest("GET", "http://ex.com/foo", nil)
	rw := httptest.NewRecorder()
	fa.ServeHTTP(rw, req)

	if rw.Code != 302 || rw.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to AuthSigninURL")
	}
}

func TestForwardAuth_AddAuthCookies(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=123; Path=/")
		w.WriteHeader(200)
	}))
	defer authServer.Close()

	cfg := &Config{
		Address:                  authServer.URL,
		AddAuthCookiesToResponse: []string{"session"},
	}
	var nextReq *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextReq = r
		w.Header().Add("Set-Cookie", "client=abc; Path=/")
		w.Header().Add("Set-Cookie", "session=old; Path=/")
		w.WriteHeader(200)
	})
	fa, _ := NewForwardAuth(context.Background(), next, cfg)

	req := httptest.NewRequest("GET", "http://ex.com/foo", nil)
	rw := httptest.NewRecorder()
	fa.ServeHTTP(rw, req)

	// we expect 'session=123' to overwrite 'session=old' and 'client=abc' to be intact.
	cookies := rw.Header().Values("Set-Cookie")
	hasClient := false
	hasNewSession := false
	hasOldSession := false
	for _, c := range cookies {
		if strings.Contains(c, "client=abc") {
			hasClient = true
		}
		if strings.Contains(c, "session=123") {
			hasNewSession = true
		}
		if strings.Contains(c, "session=old") {
			hasOldSession = true
		}
	}
	if !hasClient || !hasNewSession || hasOldSession {
		t.Errorf("cookies not correct, got %v", cookies)
	}
	if nextReq == nil {
		t.Errorf("next not called")
	}
}

func TestForwardAuth_TLS(t *testing.T) {
	cfg := &Config{
		Address: "https://invalid",
		TLS: &ClientTLS{
			InsecureSkipVerify: true,
		},
	}
	_, err := NewForwardAuth(context.Background(), nil, cfg)
	if err != nil {
		t.Errorf("expected no err, got %v", err)
	}
}

func TestForwardAuth_TLS_ClientTLS(t *testing.T) {
	// A basic self signed cert
	certPEM := `-----BEGIN CERTIFICATE-----
MIICWTCCAeKgAwIBAgIUXPpt8X55g93UqEw+lqN1sM++VbMwCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNTAxMDIyMDQ4MDhaFw0yNjAxMDIy
MDQ4MDhaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATuW56iK3mQh+x0s1D+/c6S3+sF64A8J35P+/z6P8/z6P8/z6P8/z6P8/z6
P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6
P8/z6KNTMFEwHQYDVR0OBBYEFFx6bfF+eYPd1KhMPpajdbDPvlWzMB8GA1UdIwQY
MBaAFFx6bfF+eYPd1KhMPpajdbDPvlWzMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDaAAwZQIwe+f/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8
/z6P8/z6P8/z6P8/AhQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAA==
-----END CERTIFICATE-----`
	keyPEM := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAKjAQBgcqhkjOPQIBBgUrgQQAIgNiAATuW56i
K3mQh+x0s1D+/c6S3+sF64A8J35P+/z6P8/z6P8/z6P8/z6P8/z6P8/z6P8/
-----END PRIVATE KEY-----`

	// Create with certs (even if fake, parsing might fail or succeed depending on logic. we just use random so it fails or mock good ones. Let's just pass empty valid strings)
	cfg := &Config{
		Address: "https://invalid",
		TLS: &ClientTLS{
			CA: certPEM,
		},
	}
	_, err := NewForwardAuth(context.Background(), nil, cfg)
	if err == nil {
		t.Errorf("expected err due to invalid cert, but got none")
	}

	cfg2 := &Config{
		Address: "https://invalid",
		TLS: &ClientTLS{
			Cert: certPEM,
			Key:  keyPEM,
		},
	}
	_, err2 := NewForwardAuth(context.Background(), nil, cfg2)
	if err2 == nil {
		t.Errorf("expected err due to invalid key, but got none")
	}
}

func TestForwardAuth_MaxResponseBodySize(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("1234567890"))
	}))
	defer authServer.Close()

	cfg := &Config{
		Address:             authServer.URL,
		MaxResponseBodySize: int64Ptr(5),
	}

	fa, _ := NewForwardAuth(context.Background(), nil, cfg)
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rw := httptest.NewRecorder()

	fa.ServeHTTP(rw, req)

	if rw.Code != 401 {
		t.Errorf("expected 401 on response body too large, got %v", rw.Code)
	}
}

func TestForwardedPort(t *testing.T) {
	req := httptest.NewRequest("GET", "https://ex.com:8443/foo", nil) // parses to Host: ex.com:8443
	authReq, _ := http.NewRequest("GET", "/", nil)

	port := forwardedPort(req, authReq)
	if port != "8443" {
		t.Errorf("expected 8443, got %v", port)
	}

	req2 := httptest.NewRequest("GET", "http://ex.com/foo", nil)
	authReq2, _ := http.NewRequest("GET", "/", nil)
	authReq2.Header.Set("X-Forwarded-Proto", "https")
	port2 := forwardedPort(req2, authReq2)
	if port2 != "443" {
		t.Errorf("expected 443, got %v", port2)
	}

	port3 := forwardedPort(nil, nil)
	if port3 != "" {
		t.Errorf("expected empty string, got %v", port3)
	}
}

func TestRemoveConnectionHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "http://ex.com/foo", nil)
	req.Header.Set("Connection", "upgrade, keep-alive")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Keep-Alive", "timeout=5")
	removeConnectionHeaders(req)

	if req.Header.Get("Connection") != "" {
		t.Errorf("expected Connection header dropped")
	}
	if req.Header.Get("Upgrade") != "" {
		t.Errorf("expected Upgrade header dropped")
	}
}

func TestGetCertPoolEmpty(t *testing.T) {
	_, err := getCertPool("")
	if err == nil {
		t.Errorf("expected error for empty CA string")
	}
}

func TestForwardAuth_ConnectMethod(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer authServer.Close()

	cfg := &Config{
		Address: authServer.URL,
	}

	fa, _ := NewForwardAuth(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg)
	req := httptest.NewRequest("CONNECT", "http://example.com/foo", nil)
	// fake < 0
	req.ContentLength = -1
	rw := httptest.NewRecorder()

	fa.ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Errorf("expected 200")
	}
}

func int64Ptr(i int64) *int64 { return &i }
