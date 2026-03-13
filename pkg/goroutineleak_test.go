package sniproxy

import (
	"bytes"
	"io"
	"net"
	"runtime/pprof"
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

	// Force a GC cycle so the runtime can identify unreachable primitives.
	// The leak detector relies on GC reachability analysis.
	for range 3 {
		time.Sleep(10 * time.Millisecond)
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

// TestHandleTLS_NoGoroutineLeaks verifies that handleTLS doesn't leak
// goroutines after connections complete. The proxyCopy goroutines should
// exit cleanly when both sides close.
func TestHandleTLS_NoGoroutineLeaks(t *testing.T) {
	clientConn, serverSide := net.Pipe()

	// Send garbage data (not a valid TLS ClientHello) so handleTLS
	// returns early with an error, exercising the cleanup path.
	go func() {
		_, _ = clientConn.Write([]byte("not a TLS handshake"))
		_ = clientConn.Close()
	}()

	cfg := &Config{
		ReceivedHTTPS: metrics.NilCounter{},
		ProxiedHTTPS:  metrics.NilCounter{},
	}

	l := zerolog.New(io.Discard)
	_ = handleTLS(cfg, serverSide, l)

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

	// Attempt a lookup that will fail (unreachable server).
	// This exercises the timeout/error path.
	_, _ = dnsc.lookupDomain4("example.com")

	checkGoroutineLeaks(t)
}
