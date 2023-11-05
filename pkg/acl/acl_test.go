package acl

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/rs/zerolog"
)

var logger = zerolog.New(os.Stderr).With().Timestamp().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339, NoColor: true})

var configs = map[string]string{
	"acl_domain.yaml": `
acl:
  domain:
    enabled: true
    priority: 20
    path: ../../domains.csv
    refresh_interval: 1h0m0s`,
	"acl_cidr.yaml": `
acl:
  cidr:
    enabled: true
    priority: 30
    path: ../../cidr.csv
    refresh_interval: 1h0m0s`,
	"acl_domain_cidr.yaml": `
acl:
  domain:
    enabled: true
    priority: 20
    path: ../../domains.csv
    refresh_interval: 1h0m0s
  cidr:
    enabled: true
    priority: 30
    path: ../../cidr.csv
    refresh_interval: 1h0m0s`,
	"acl_cidr_domain.yaml": `
acl:
  domain:
    enabled: true
    priority: 20
    path: ../../domains.csv
    refresh_interval: 1h0m0s
  cidr:
    enabled: true
    priority: 19
    path: ../../cidr.csv
    refresh_interval: 1h0m0s`,
}

func TestMakeDecision(t *testing.T) {
	// Test cases
	cases := []struct {
		connInfo *ConnInfo
		config   string
		expected Decision
	}{
		{
			// domain in domains.csv
			connInfo: mockConnInfo("1.1.1.1", "ipinfo.io"),
			config:   configs["acl_domain.yaml"],
			expected: ProxyIP,
		},
		{
			// domain NOT in domains.csv
			connInfo: mockConnInfo("2.2.2.2", "google.de"),
			config:   configs["acl_domain.yaml"],
			expected: OriginIP,
		},
		{
			// ip REJECT in cidr.csv
			// if you want to whitelist IPs then you must include "0.0.0.0/0,reject" otherwise always accepted!!
			connInfo: mockConnInfo("1.1.1.1", "google.de"),
			config:   configs["acl_cidr.yaml"],
			expected: Reject,
		},
		{
			// ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "google.de"),
			config:   configs["acl_cidr.yaml"],
			expected: Accept,
		},
		{
			// ip ACCEPT in cidr.csv, still no ProxyIP (acl.domain not enabled)
			connInfo: mockConnInfo("77.77.1.1", "ipinfo.io"),
			config:   configs["acl_cidr.yaml"],
			expected: Accept,
		},
		{
			// domain in domains.csv, ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "ipinfo.io"),
			config:   configs["acl_domain_cidr.yaml"],
			expected: ProxyIP,
		},
		{
			// domain NOT in domains.csv, ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "google.de"),
			config:   configs["acl_domain_cidr.yaml"],
			expected: OriginIP,
		},
		{
			// domain in domains.csv, ip REJECT in cidr.csv
			connInfo: mockConnInfo("1.1.1.1", "ipinfo.io"),
			config:   configs["acl_domain_cidr.yaml"],
			expected: Reject, // still returns OriginIP in DNS !!!
		},
		{
			// domain NOT in domains.csv, ip REJECT in cidr.csv
			connInfo: mockConnInfo("1.1.1.1", "google.de"),
			config:   configs["acl_domain_cidr.yaml"],
			expected: Reject, // still returns OriginIP in DNS !!!
		},
		{
			// domain NOT in domains.csv, ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "google.de"),
			config:   configs["acl_cidr_domain.yaml"],
			expected: OriginIP,
		},
		{
			// domain in domains.csv, ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "ipinfo.io"),
			config:   configs["acl_cidr_domain.yaml"],
			expected: ProxyIP,
		},
		{
			// domain in domains.csv, ip REJECT in cidr.csv
			connInfo: mockConnInfo("1.1.1.1", "google.de"),
			config:   configs["acl_cidr_domain.yaml"],
			expected: Reject,
		},
		{
			// domain NOT in domains.csv, ip REJECT in cidr.csv
			connInfo: mockConnInfo("1.1.1.1", "google.de"),
			config:   configs["acl_cidr_domain.yaml"],
			expected: Reject,
		},
	}

	// Run the test cases
	for _, tc := range cases {
		t.Run(tc.config, func(t *testing.T) {
			MakeDecision(tc.connInfo, getAcls(&logger, tc.config))
			if tc.expected != tc.connInfo.Decision {
				t.Errorf("MakeDecision (domain=%v,ip=%v,config=%v) decided %v, expected %v", tc.connInfo.Domain, tc.connInfo.SrcIP, tc.config, tc.connInfo.Decision, tc.expected)
			}
		})
	}
}

// TestReverse tests the reverse function
func TestReverse(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{name: "test1", s: "abc", want: "cba"},
		{name: "test2", s: "a", want: "a"},
		{name: "test3", s: "aab", want: "baa"},
		{name: "test4", s: "zzZ", want: "Zzz"},
		{name: "test5", s: "ab2", want: "2ba"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverse(tt.s); got != tt.want {
				t.Errorf("reverse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getAcls(log *zerolog.Logger, config string) []ACL {
	var k = koanf.New(".")
	if err := k.Load(rawbytes.Provider([]byte(config)), yaml.Parser()); err != nil {
		log.Fatal().Msgf("error loading config file: %v", err)
	}
	a, err := StartACLs(&logger, k)
	if err != nil {
		panic(err)
	}
	// we need this to give acl time to (re)load
	time.Sleep(1 * time.Second)
	return a
}

func mockConnInfo(srcIP string, domain string) *ConnInfo {
	addr, err := net.ResolveTCPAddr("tcp", srcIP+":80")

	if err != nil {
		logger.Fatal().Msgf("error parsing ip from string: %v", err)
	}

	return &ConnInfo{
		SrcIP:  addr,
		Domain: domain,
	}
}
