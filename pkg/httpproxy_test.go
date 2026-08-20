package sniproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

func newTestConfig() *Config {
	return &Config{
		PublicIPv4:    "203.0.113.1",
		PublicIPv6:    "",
		Dialer:        proxy.Direct,
		ReceivedHTTP:  metrics.NewCounter(),
		ProxiedHTTP:   metrics.NewCounter(),
		ReceivedHTTPS: metrics.NewCounter(),
		ProxiedHTTPS:  metrics.NewCounter(),
		ReceivedDNS:   metrics.NewCounter(),
		ProxiedDNS:    metrics.NewCounter(),
	}
}

func TestHandle80_HeaderFiltering(t *testing.T) {
	// Create an origin server that captures received headers
	var receivedHeaders http.Header
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Custom-Response", "should-be-filtered")
		w.Header().Set("Server", "test-origin")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	// Parse origin URL to get host:port
	originHost := strings.TrimPrefix(origin.URL, "http://")

	c := newTestConfig()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Redirect all dials to our test origin
			return net.Dial("tcp", originHost)
		},
	}

	logger := testLogger()
	handler := handle80(c, logger, transport)

	// Create request with extra headers
	req := httptest.NewRequest("GET", "http://test.example.com/path", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Custom-Request", "should-be-filtered")
	req.Header.Set("Authorization", "Bearer secret")

	w := httptest.NewRecorder()
	handler(w, req)

	// Verify whitelisted request headers arrived
	if receivedHeaders.Get("User-Agent") != "test-agent" {
		t.Error("User-Agent header should be passed through")
	}
	if receivedHeaders.Get("Accept") != "text/html" {
		t.Error("Accept header should be passed through")
	}
	// Verify non-whitelisted headers were filtered
	if receivedHeaders.Get("X-Custom-Request") != "" {
		t.Error("X-Custom-Request header should have been filtered")
	}
	if receivedHeaders.Get("Authorization") != "" {
		t.Error("Authorization header should have been filtered")
	}

	// Verify response
	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	// Verify whitelisted response headers
	if resp.Header.Get("Server") != "test-origin" {
		t.Error("Server response header should be passed through")
	}
	// Verify non-whitelisted response headers were filtered
	if resp.Header.Get("X-Custom-Response") != "" {
		t.Error("X-Custom-Response header should have been filtered from response")
	}
}

func TestHandle80_LoopPrevention(t *testing.T) {
	c := newTestConfig()
	transport := &http.Transport{}
	logger := testLogger()
	handler := handle80(c, logger, transport)

	// Request to proxy's own public IP
	req := httptest.NewRequest("GET", "http://203.0.113.1/path", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 404 {
		t.Errorf("expected 404 for self-request, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Could not reach origin server") {
		t.Error("expected loop prevention error message")
	}
}

func testLogger() zerolog.Logger {
	return zerolog.Nop()
}

// testPprofBind is the diagnostic listener address used across these tests.
const testPprofBind = "127.0.0.1:6060"

// recordingTransport reports whether the proxy ever tried to dial out. A
// blocked request must never reach the dial stage.
func recordingTransport(dialed *bool) *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			*dialed = true
			return nil, io.EOF
		},
	}
}

// TestHandle80_RejectsSelfDestinations covers the case where a client points
// the Host header back at sniproxy itself. Before this check the HTTP proxy
// would happily fetch sniproxy's own loopback-bound listeners, so binding the
// pprof endpoint to 127.0.0.1 gave no protection at all.
func TestHandle80_RejectsSelfDestinations(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
	}{
		{"loopback with port", testPprofBind},
		{"loopback bare", "127.0.0.1"},
		{"ipv6 loopback", "[::1]:6060"},
		{"localhost by name", "localhost:6060"},
		{"private rfc1918", "192.168.1.10:8080"},
		{"private 10/8", "10.0.0.5"},
		{"unspecified", "0.0.0.0:6060"},
		{"own public ip", "203.0.113.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestConfig()
			c.BindPprof = testPprofBind

			dialed := false
			handler := handle80(c, testLogger(), recordingTransport(&dialed))

			req := httptest.NewRequest("GET", "http://"+tc.host+"/debug/pprof/cmdline", nil)
			req.Host = tc.host
			w := httptest.NewRecorder()
			handler(w, req)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != 404 {
				t.Errorf("Host %q: expected 404, got %d", tc.host, resp.StatusCode)
			}
			if dialed {
				t.Errorf("Host %q: proxy dialed the destination; it should have been refused first", tc.host)
			}
		})
	}
}

// TestHandle80_AllowConnToLocalStillBlocksManagementPorts checks that opting
// into proxying private destinations does not also expose sniproxy's own
// diagnostic listeners, which have no authentication of their own.
func TestHandle80_AllowConnToLocalStillBlocksManagementPorts(t *testing.T) {
	c := newTestConfig()
	c.AllowConnToLocal = true
	c.BindPprof = testPprofBind
	c.BindPrometheus = "127.0.0.1:8080"

	for _, tc := range []struct {
		name       string
		host       string
		wantDialed bool
	}{
		{"pprof port is refused", testPprofBind, false},
		{"prometheus port is refused", "127.0.0.1:8080", false},
		{"other local port is allowed", "192.168.1.10:9999", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialed := false
			handler := handle80(c, testLogger(), recordingTransport(&dialed))

			req := httptest.NewRequest("GET", "http://"+tc.host+"/", nil)
			req.Host = tc.host
			w := httptest.NewRecorder()
			handler(w, req)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()
			if dialed != tc.wantDialed {
				t.Errorf("Host %q: dialed=%v, want %v", tc.host, dialed, tc.wantDialed)
			}
			if !tc.wantDialed && resp.StatusCode != 404 {
				t.Errorf("Host %q: expected 404, got %d", tc.host, resp.StatusCode)
			}
		})
	}
}

func TestIsManagementPort(t *testing.T) {
	c := &Config{BindPprof: testPprofBind, BindPrometheus: "0.0.0.0:9090"}
	for port, want := range map[string]bool{
		"6060": true,
		"9090": true,
		"80":   false,
		"443":  false,
		"":     false,
	} {
		if got := c.isManagementPort(port); got != want {
			t.Errorf("isManagementPort(%q) = %v, want %v", port, got, want)
		}
	}

	// nothing configured means nothing to protect
	empty := &Config{}
	if empty.isManagementPort("6060") {
		t.Error("isManagementPort should be false when no diagnostic listeners are configured")
	}
}
