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
