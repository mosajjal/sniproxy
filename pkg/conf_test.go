package sniproxy

import (
	"testing"
)

func TestParseIPVersion(t *testing.T) {
	tests := []struct {
		input string
		want  IPVersion
	}{
		{"ipv4only", IPVersionIPv4Only},
		{"4only", IPVersionIPv4Only},
		{"ipv6only", IPVersionIPv6Only},
		{"6only", IPVersionIPv6Only},
		{"ipv4", IPVersionIPv4Preferred},
		{"4", IPVersionIPv4Preferred},
		{"ipv6", IPVersionIPv6Preferred},
		{"6", IPVersionIPv6Preferred},
		{"any", IPVersionAny},
		{"0", IPVersionAny},
		{"", IPVersionAny},
		{"garbage", IPVersionAny},
		{"  IPV4  ", IPVersionIPv4Preferred},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseIPVersion(tt.input); got != tt.want {
				t.Errorf("ParseIPVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIPVersionString(t *testing.T) {
	tests := []struct {
		v    IPVersion
		want string
	}{
		{IPVersionIPv4Only, "ipv4only"},
		{IPVersionIPv6Only, "ipv6only"},
		{IPVersionIPv4Preferred, "ipv4"},
		{IPVersionIPv6Preferred, "ipv6"},
		{IPVersionAny, "any"},
		{IPVersion(99), "any"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.v.String(); got != tt.want {
				t.Errorf("IPVersion(%d).String() = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}

func TestParseRanges(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    []int
		wantErr bool
	}{
		{
			name:  "single port",
			input: []string{"8080"},
			want:  []int{8080},
		},
		{
			name:  "port range",
			input: []string{"8080-8083"},
			want:  []int{8080, 8081, 8082, 8083},
		},
		{
			name:  "multiple mixed",
			input: []string{"80", "8080-8082"},
			want:  []int{80, 8080, 8081, 8082},
		},
		{
			name:    "invalid port",
			input:   []string{"abc"},
			wantErr: true,
		},
		{
			name:    "invalid range start",
			input:   []string{"abc-90"},
			wantErr: true,
		},
		{
			name:    "invalid range end",
			input:   []string{"80-abc"},
			wantErr: true,
		},
		{
			name:  "empty input",
			input: []string{},
			want:  nil,
		},
		{
			name:    "port zero",
			input:   []string{"0"},
			wantErr: true,
		},
		{
			name:    "port too high",
			input:   []string{"70000"},
			wantErr: true,
		},
		{
			name:    "range too high",
			input:   []string{"65530-65536"},
			wantErr: true,
		},
		{
			name:    "range inverted",
			input:   []string{"8083-8080"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRanges(tt.input...)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRanges() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("parseRanges() = %v, want %v", got, tt.want)
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("parseRanges()[%d] = %d, want %d", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestParseBinders(t *testing.T) {
	tests := []struct {
		name       string
		bind       string
		additional []string
		wantLen    int
		wantErr    bool
	}{
		{
			name:    "basic bind no additional",
			bind:    "0.0.0.0:80",
			wantLen: 1,
		},
		{
			name:       "bind with additional",
			bind:       "0.0.0.0:80",
			additional: []string{"8080", "8081-8083"},
			wantLen:    5, // 80, 8080, 8081, 8082, 8083
		},
		{
			name:    "invalid bind",
			bind:    "not-an-address",
			wantErr: true,
		},
		{
			name:       "invalid additional",
			bind:       "0.0.0.0:80",
			additional: []string{"abc"},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBinders(tt.bind, tt.additional)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBinders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("parseBinders() returned %d addresses, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	validConfig := Config{
		BindDNSOverUDP: "0.0.0.0:53",
		UpstreamDNS:    "udp://1.1.1.1:53",
		BindHTTP:       "0.0.0.0:80",
		PublicIPv4:     "1.2.3.4",
	}

	tests := []struct {
		name    string
		modify  func(c *Config)
		wantErr bool
	}{
		{
			name:   "valid config",
			modify: func(_ *Config) {},
		},
		{
			name: "no DNS binding",
			modify: func(c *Config) {
				c.BindDNSOverUDP = ""
			},
			wantErr: true,
		},
		{
			name: "no upstream DNS",
			modify: func(c *Config) {
				c.UpstreamDNS = ""
			},
			wantErr: true,
		},
		{
			name: "no HTTP or HTTPS binding",
			modify: func(c *Config) {
				c.BindHTTP = ""
				c.BindHTTPS = ""
			},
			wantErr: true,
		},
		{
			name: "no public IP",
			modify: func(c *Config) {
				c.PublicIPv4 = ""
				c.PublicIPv6 = ""
			},
			wantErr: true,
		},
		{
			name: "TLS DNS without cert",
			modify: func(c *Config) {
				c.BindDNSOverTLS = "0.0.0.0:853"
			},
			wantErr: true,
		},
		{
			name: "TLS DNS with cert",
			modify: func(c *Config) {
				c.BindDNSOverTLS = "0.0.0.0:853"
				c.TLSCert = "/path/to/cert"
				c.TLSKey = "/path/to/key"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig // copy
			tt.modify(&c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
