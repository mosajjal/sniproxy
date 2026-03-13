package sniproxy

import (
	"bytes"
	"io"
	"net"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
)

// checkGoroutineLeaks looks up the goroutineleak profile (available when built
// with GOEXPERIMENT=goroutineleakprofile) and fails the test if any leaked
// goroutines are detected. Skips gracefully when the experiment is not enabled.
func checkGoroutineLeaks(t *testing.T) {
	t.Helper()

	// Give the GC a chance to identify unreachable primitives.
	for range 5 {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}

	p := pprof.Lookup("goroutineleak")
	if p == nil {
		t.Skip("goroutineleak profile not available (build with GOEXPERIMENT=goroutineleakprofile)")
	}

	if p.Count() > 0 {
		var buf bytes.Buffer
		if err := p.WriteTo(&buf, 1); err != nil {
			t.Fatalf("failed to write goroutineleak profile: %v", err)
		}
		t.Errorf("goroutine leaks detected:\n%s", buf.String())
	}
}

func testConfig() *Config {
	return &Config{
		ReceivedHTTPS: metrics.NilCounter{},
		ProxiedHTTPS:  metrics.NilCounter{},
		ReceivedHTTP:  metrics.NilCounter{},
		ProxiedHTTP:   metrics.NilCounter{},
		ReceivedDNS:   metrics.NilCounter{},
		ProxiedDNS:    metrics.NilCounter{},
	}
}

func discardLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}

// TestHandleTLS_NoGoroutineLeaks verifies that handleTLS doesn't leak
// goroutines when the client sends invalid data and the connection closes.
func TestHandleTLS_NoGoroutineLeaks(t *testing.T) {
	clientConn, serverSide := net.Pipe()

	go func() {
		_, _ = clientConn.Write([]byte("not a TLS handshake"))
		_ = clientConn.Close()
	}()

	_ = handleTLS(testConfig(), serverSide, discardLogger())
	checkGoroutineLeaks(t)
}

// TestHandleTLS_ConcurrentNoGoroutineLeaks runs many concurrent TLS
// connections that all fail (bad data), checking that the proxyCopy
// goroutines and error channels don't leak.
func TestHandleTLS_ConcurrentNoGoroutineLeaks(t *testing.T) {
	cfg := testConfig()
	l := discardLogger()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clientConn, serverSide := net.Pipe()
			go func() {
				_, _ = clientConn.Write([]byte("garbage"))
				_ = clientConn.Close()
			}()
			_ = handleTLS(cfg, serverSide, l)
		}()
	}
	wg.Wait()

	checkGoroutineLeaks(t)
}

// TestHandleTLS_SlowClientNoGoroutineLeaks simulates a client that
// connects but sends nothing, triggering the read deadline timeout.
// This checks that the timeout path cleans up properly.
func TestHandleTLS_SlowClientNoGoroutineLeaks(t *testing.T) {
	clientConn, serverSide := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = handleTLS(testConfig(), serverSide, discardLogger())
	}()

	// Don't write anything — let the read deadline expire.
	// handleTLS sets a 10s read deadline, but net.Pipe doesn't support
	// deadlines, so it will block. Close client side to unblock it.
	time.Sleep(50 * time.Millisecond)
	_ = clientConn.Close()
	<-done

	checkGoroutineLeaks(t)
}

// TestHandleTLS_ValidSNI_NoUpstream tests the path where SNI extraction
// succeeds but the upstream connection fails (unreachable destination).
// This exercises the full handleTLS path up to the dial failure.
func TestHandleTLS_ValidSNI_NoUpstream(t *testing.T) {
	cfg := testConfig()
	cfg.PublicIPv4 = "203.0.113.1"

	// Set up a DNS client that will resolve to an unreachable address
	dnsc, err := NewDNSClient(cfg, "udp://127.0.0.1:0", true, "")
	if err != nil {
		t.Skipf("could not create DNS client: %v", err)
	}
	cfg.DNSClient = *dnsc

	// Build a valid TLS ClientHello with SNI
	clientHello := buildClientHello("example.com")

	clientConn, serverSide := net.Pipe()
	go func() {
		_, _ = clientConn.Write(clientHello)
		_ = clientConn.Close()
	}()

	_ = handleTLS(cfg, serverSide, discardLogger())
	checkGoroutineLeaks(t)
}

// TestDNSClient_NoGoroutineLeaks verifies that DNS client operations
// don't leak goroutines after lookups complete or fail.
func TestDNSClient_NoGoroutineLeaks(t *testing.T) {
	c := Config{
		UpstreamDNS: "udp://127.0.0.1:0", // intentionally unreachable
	}
	dnsc, err := NewDNSClient(&c, c.UpstreamDNS, true, "")
	if err != nil {
		t.Skipf("could not create DNS client: %v", err)
	}

	_, _ = dnsc.lookupDomain4("example.com")
	checkGoroutineLeaks(t)
}

// TestDNSClient_ConcurrentNoGoroutineLeaks runs many concurrent DNS
// lookups that all fail, checking for leaked goroutines from the
// underlying DNS pipeline.
func TestDNSClient_ConcurrentNoGoroutineLeaks(t *testing.T) {
	c := Config{
		UpstreamDNS: "udp://127.0.0.1:0",
	}
	dnsc, err := NewDNSClient(&c, c.UpstreamDNS, true, "")
	if err != nil {
		t.Skipf("could not create DNS client: %v", err)
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = dnsc.lookupDomain4("example.com")
		}()
	}
	wg.Wait()

	checkGoroutineLeaks(t)
}

// TestProxyCopy_NoGoroutineLeaks tests the proxyCopy function directly.
// Two goroutines copy between two net.Pipe pairs. When connections close,
// both goroutines should exit.
func TestProxyCopy_NoGoroutineLeaks(t *testing.T) {
	for range 10 {
		a1, a2 := net.Pipe()
		b1, b2 := net.Pipe()

		errc := make(chan error, 2)
		go proxyCopy(errc, a1, b2)
		go proxyCopy(errc, b1, a2)

		// Write some data through
		go func() {
			_, _ = a2.Write([]byte("hello"))
			_ = a2.Close()
		}()
		go func() {
			_, _ = b2.Write([]byte("world"))
			_ = b2.Close()
		}()

		// Drain both sides
		_, _ = io.ReadAll(a1)
		_, _ = io.ReadAll(b1)
		_ = a1.Close()
		_ = b1.Close()

		// Wait for proxyCopy goroutines
		<-errc
		<-errc
	}

	checkGoroutineLeaks(t)
}
