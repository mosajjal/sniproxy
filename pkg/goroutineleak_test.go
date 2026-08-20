package sniproxy

import (
	"bytes"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
)

// requireLeakProfile skips the test unless the binary was built with
// GOEXPERIMENT=goroutineleakprofile. A plain `go test ./...` does not set it,
// so these checks only really run in the dedicated CI step.
func requireLeakProfile(t *testing.T) {
	t.Helper()
	if !GoroutineLeakProfileAvailable() {
		t.Skip("goroutineleak profile not compiled in; rebuild with GOEXPERIMENT=goroutineleakprofile")
	}
}

// checkGoroutineLeaks fails the test if the runtime can prove any goroutine is
// permanently blocked.
//
// Order matters here: writing the profile is what runs the leak-detecting GC
// cycle. Profile.Count only reports the result of the most recent detection
// run, so calling it first would read a stale count (zero, if nothing has ever
// triggered detection) and quietly pass on a real leak.
func checkGoroutineLeaks(t *testing.T) {
	t.Helper()
	requireLeakProfile(t)

	var buf bytes.Buffer
	if _, err := WriteGoroutineLeakProfile(&buf, 1); err != nil {
		t.Fatalf("goroutine leak detection failed: %v", err)
	}
	if n, stacks := unexpectedLeaks(buf.String()); n > 0 {
		t.Errorf("%d leaked goroutine(s) detected:\n%s", n, stacks)
	}
}

// knownLeaks are leak sites these tests deliberately tolerate. Leaked
// goroutines are never reclaimed, so anything listed here would otherwise fail
// every check that runs after the leak is created.
var knownLeaks = []string{
	// routedns starts a Pipeline goroutine per DNS client which ranges over a
	// request channel it never closes, and exposes no way to shut it down. So
	// every rdns.NewDNSClient parks one goroutine for the life of the process.
	// sniproxy builds its DNS client once at startup, which bounds this at one
	// in production, but each NewDNSClient in a test adds another.
	"routedns.(*Pipeline).start",
	// planted on purpose by TestGoroutineLeakProfile_DetectsKnownLeak
	"leakOneGoroutine",
}

// unexpectedLeaks parses a debug=1 goroutineleak profile and returns how many
// leaked goroutines are not attributable to knownLeaks, along with their
// stacks. The format is one record per distinct stack, separated by a blank
// line, each starting with "<count> @ <pcs>".
func unexpectedLeaks(profile string) (int, string) {
	var (
		total  int
		stacks []string
	)
	for _, record := range strings.Split(profile, "\n\n") {
		record = strings.TrimSpace(record)
		if record == "" || strings.HasPrefix(record, "goroutineleak profile:") {
			continue
		}
		if slices.ContainsFunc(knownLeaks, func(known string) bool {
			return strings.Contains(record, known)
		}) {
			continue
		}
		count, _, ok := strings.Cut(record, " @ ")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(count)
		if err != nil {
			continue
		}
		total += n
		stacks = append(stacks, record)
	}
	return total, strings.Join(stacks, "\n\n")
}

// leakOneGoroutine parks a goroutine on a channel nothing else can ever
// reference, which is exactly the shape the runtime is able to prove leaked.
//
//go:noinline
func leakOneGoroutine() {
	go func() {
		<-make(chan struct{})
	}()
}

// TestGoroutineLeakProfile_DetectsKnownLeak is the negative control for the
// rest of this file: it plants a leak the runtime must be able to find. Without
// it every other test here would still pass if detection silently stopped
// working.
func TestGoroutineLeakProfile_DetectsKnownLeak(t *testing.T) {
	requireLeakProfile(t)

	before, err := CountGoroutineLeaks()
	if err != nil {
		t.Fatalf("goroutine leak detection failed: %v", err)
	}

	leakOneGoroutine()

	// The goroutine has to actually reach the blocked state before the runtime
	// can classify it, and it is not scheduled synchronously, so retry rather
	// than racing it on the first sample.
	deadline := time.Now().Add(10 * time.Second)
	for {
		after, err := CountGoroutineLeaks()
		if err != nil {
			t.Fatalf("goroutine leak detection failed: %v", err)
		}
		if after > before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("deliberate leak went undetected: leak count stayed at %d", before)
		}
		time.Sleep(20 * time.Millisecond)
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

// TestUnexpectedLeaks covers the profile parsing itself. If this filter ever
// silently returned zero, every leak check in this file would pass vacuously.
func TestUnexpectedLeaks(t *testing.T) {
	const profile = `goroutineleak profile: total 4

2 @ 0x49370a 0x41e94e
#	0xadc675	github.com/folbricht/routedns.(*Pipeline).start+0x115	/pipeline.go:87

1 @ 0x49370a 0x41e94e
#	0xbd13a4	github.com/mosajjal/sniproxy/v2/pkg.leakOneGoroutine.func1+0x24	/goroutineleak_test.go:49

1 @ 0x49370a 0x41e94e
#	0xbd13a4	github.com/mosajjal/sniproxy/v2/pkg.handleTLS.func2+0x24	/https.go:120
`

	n, stacks := unexpectedLeaks(profile)
	if n != 1 {
		t.Errorf("unexpected leak count: got %d, want 1", n)
	}
	if !strings.Contains(stacks, "handleTLS") {
		t.Errorf("expected the handleTLS stack to be reported, got:\n%s", stacks)
	}
	if strings.Contains(stacks, "Pipeline") || strings.Contains(stacks, "leakOneGoroutine") {
		t.Errorf("known leaks should have been filtered out, got:\n%s", stacks)
	}

	if n, _ := unexpectedLeaks("goroutineleak profile: total 0\n"); n != 0 {
		t.Errorf("empty profile should report no leaks, got %d", n)
	}
}
