package sniproxy

import (
	"testing"
)

// buildClientHello constructs a minimal TLS ClientHello packet with the given SNI
func buildClientHello(sni string) []byte {
	// SNI extension
	serverName := []byte(sni)
	// Server Name list entry: type(1) + length(2) + name
	snEntry := []byte{0x00} // host_name type
	snEntry = append(snEntry, byte(len(serverName)>>8), byte(len(serverName)))
	snEntry = append(snEntry, serverName...)
	// Server Name list: length(2) + entries
	snList := []byte{byte(len(snEntry) >> 8), byte(len(snEntry))}
	snList = append(snList, snEntry...)

	// SNI extension header: type(2) + length(2) + data
	sniExt := []byte{0x00, 0x00} // Extension type: server_name
	sniExt = append(sniExt, byte(len(snList)>>8), byte(len(snList)))
	sniExt = append(sniExt, snList...)

	// Extensions block: length(2) + extensions
	extensions := []byte{byte(len(sniExt) >> 8), byte(len(sniExt))}
	extensions = append(extensions, sniExt...)

	// Client Hello body
	clientHello := []byte{
		0x03, 0x03, // Version TLS 1.2
	}
	// 32 bytes random
	clientHello = append(clientHello, make([]byte, 32)...)
	// Session ID (empty)
	clientHello = append(clientHello, 0x00)
	// Cipher suites: length(2) + one suite
	clientHello = append(clientHello, 0x00, 0x02, 0x00, 0x2f)
	// Compression: length(1) + null
	clientHello = append(clientHello, 0x01, 0x00)
	// Extensions
	clientHello = append(clientHello, extensions...)

	// Handshake header: type(1) + length(3)
	handshake := []byte{0x01} // ClientHello
	handshake = append(handshake, 0x00, byte(len(clientHello)>>8), byte(len(clientHello)))
	handshake = append(handshake, clientHello...)

	// TLS record: type(1) + version(2) + length(2)
	record := []byte{
		0x16,       // Handshake
		0x03, 0x01, // TLS 1.0 record layer
	}
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

func TestGetHostname(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name: "valid ClientHello with example.com",
			data: buildClientHello("example.com"),
			want: "example.com",
		},
		{
			name: "valid ClientHello with subdomain",
			data: buildClientHello("sub.example.com"),
			want: "sub.example.com",
		},
		{
			name: "valid ClientHello with long domain",
			data: buildClientHello("very.deep.subdomain.example.co.uk"),
			want: "very.deep.subdomain.example.co.uk",
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "non-TLS data",
			data:    []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00},
			wantErr: true,
		},
		{
			name:    "truncated TLS record",
			data:    []byte{0x16, 0x03, 0x01},
			wantErr: true,
		},
		{
			name:    "single byte",
			data:    []byte{0x16},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetHostname(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHostname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetHostname() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsValidFQDN(t *testing.T) {
	tests := []struct {
		hostname string
		want     bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a-b.example.co.uk", true},
		{"a.bc", true},
		{"123.example.com", true},
		{"", false},
		{"localhost", false},
		{".example.com", false},
		{"example.", false},
		{"-example.com", false},
		{"1.2.3.4", false},
		{"example.c", false},
		{"example..com", false},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			if got := isValidFQDN(tt.hostname); got != tt.want {
				t.Errorf("isValidFQDN(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestLengthFromData(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		index int
		want  int
	}{
		{"zero", []byte{0x00, 0x00}, 0, 0},
		{"one", []byte{0x00, 0x01}, 0, 1},
		{"256", []byte{0x01, 0x00}, 0, 256},
		{"offset", []byte{0xFF, 0x00, 0x05}, 1, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lengthFromData(tt.data, tt.index); got != tt.want {
				t.Errorf("lengthFromData() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGetExtensionBlock_Malformed(t *testing.T) {
	// Too short to contain a Client Hello
	_, err := getExtensionBlock([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestGetSNBlock_Malformed(t *testing.T) {
	// Too short
	_, err := getSNBlock([]byte{0x00})
	if err == nil {
		t.Error("expected error for too-short data")
	}

	// Empty extensions
	_, err = getSNBlock([]byte{0x00, 0x00})
	if err == nil {
		t.Error("expected error for empty extensions")
	}
}

func TestGetSNIBlock_Empty(t *testing.T) {
	_, err := getSNIBlock([]byte{})
	if err == nil {
		t.Error("expected error for empty SNI block")
	}
}

func BenchmarkGetHostname(b *testing.B) {
	data := buildClientHello("example.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetHostname(data)
	}
}

func BenchmarkIsValidFQDN(b *testing.B) {
	for i := 0; i < b.N; i++ {
		isValidFQDN("sub.example.com")
	}
}
