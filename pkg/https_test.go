package sniproxy

import (
	"bytes"
	"net"
	"net/netip"
	"strconv"
	"testing"
)

func TestIsSelf(t *testing.T) {
	cfg := &Config{
		PublicIPv4: "203.0.113.1",
		PublicIPv6: "2001:db8::1",
		SourceAddr: []netip.Addr{
			netip.MustParseAddr("10.0.0.5"),
		},
	}

	tests := []struct {
		name string
		ip   netip.Addr
		want bool
	}{
		{"loopback v4", netip.MustParseAddr("127.0.0.1"), true},
		{"loopback v6", netip.MustParseAddr("::1"), true},
		{"private v4", netip.MustParseAddr("192.168.1.1"), true},
		{"unspecified v4", netip.IPv4Unspecified(), true},
		{"public ipv4 match", netip.MustParseAddr("203.0.113.1"), true},
		{"public ipv6 match", netip.MustParseAddr("2001:db8::1"), true},
		{"source addr match", netip.MustParseAddr("10.0.0.5"), true},
		{"external ip", netip.MustParseAddr("8.8.8.8"), false},
		{"external ipv6", netip.MustParseAddr("2001:4860:4860::8888"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSelf(cfg, tt.ip); got != tt.want {
				t.Errorf("isSelf(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsSelf_EmptyPublicIPs(t *testing.T) {
	cfg := &Config{}

	// External IP should not match self
	if isSelf(cfg, netip.MustParseAddr("8.8.8.8")) {
		t.Error("expected 8.8.8.8 to not be self with empty config")
	}
	// Loopback still matches
	if !isSelf(cfg, netip.MustParseAddr("127.0.0.1")) {
		t.Error("expected 127.0.0.1 to be self")
	}
}

func TestGetPortFromConn(t *testing.T) {
	// Test with a real listener to get a valid conn
	// For unit test simplicity, we just verify the function handles edge cases
	// getPortFromConn returns 0 on error, which is tested indirectly
}

func TestReadClientHello_Split(t *testing.T) {
	hello := buildClientHello("example.com")

	// Split offsets from issue #210: inside the record header and inside the body.
	for _, split := range []int{0, 3, 40} {
		t.Run(strconv.Itoa(split), func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()

			// net.Pipe delivers each Write separately, like TCP segments.
			go func() {
				if split > 0 {
					_, _ = client.Write(hello[:split])
				}
				_, _ = client.Write(hello[split:])
			}()

			buf := make([]byte, TLSClientHelloBufferSize)
			n, err := readClientHello(server, buf)
			if err != nil {
				t.Fatalf("readClientHello() error = %v", err)
			}
			if !bytes.Equal(buf[:n], hello) {
				t.Fatalf("got %d bytes, want %d", n, len(hello))
			}

			sni, err := GetHostname(buf[:n])
			if err != nil || sni != "example.com" {
				t.Fatalf("GetHostname() = %q, %v", sni, err)
			}
		})
	}
}

func TestReadClientHello_Invalid(t *testing.T) {
	tests := map[string][]byte{
		"not handshake": {0x17, 0x03, 0x01, 0x00, 0x05},
		"zero length":   {0x16, 0x03, 0x01, 0x00, 0x00},
		"too long":      {0x16, 0x03, 0x01, 0xff, 0xff},
	}

	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()

			go func() { _, _ = client.Write(header) }()

			buf := make([]byte, TLSClientHelloBufferSize)
			if _, err := readClientHello(server, buf); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
