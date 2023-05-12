package acl

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/rs/zerolog"
)

var logger = zerolog.New(os.Stderr).With().Timestamp().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339, NoColor: true})

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
			config:   "../test_resources/acl_domain.yaml",
			expected: ProxyIP,
		},
		{
			// domain NOT in domains.csv
			connInfo: mockConnInfo("2.2.2.2", "google.de"),
			config:   "../test_resources/acl_domain.yaml",
			expected: OriginIP,
		},
		{
			// ip REJECT in cidr.csv
			// if you want to whitelist IPs then you must include "0.0.0.0/0,reject" otherwise always accepted!!
			connInfo: mockConnInfo("1.1.1.1", "google.de"),
			config:   "../test_resources/acl_cidr.yaml",
			expected: Reject,
		},
		{
			// ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "google.de"),
			config:   "../test_resources/acl_cidr.yaml",
			expected: Accept,
		},
		{
			// ip ACCEPT in cidr.csv, still no ProxyIP (acl.domain not enabled)
			connInfo: mockConnInfo("77.77.1.1", "ipinfo.io"),
			config:   "../test_resources/acl_cidr.yaml",
			expected: Accept,
		},
		{
			// domain in domains.csv, ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "ipinfo.io"),
			config:   "../test_resources/acl_domain_cidr.yaml",
			expected: ProxyIP,
		},
		{
			// domain NOT in domains.csv, ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "google.de"),
			config:   "../test_resources/acl_domain_cidr.yaml",
			expected: OriginIP,
		},
		{
			// domain in domains.csv, ip REJECT in cidr.csv
			connInfo: mockConnInfo("1.1.1.1", "ipinfo.io"),
			config:   "../test_resources/acl_domain_cidr.yaml",
			expected: Reject, // still returns OriginIP in DNS !!!
		},
		{
			// domain NOT in domains.csv, ip REJECT in cidr.csv
			connInfo: mockConnInfo("1.1.1.1", "google.de"),
			config:   "../test_resources/acl_domain_cidr.yaml",
			expected: Reject, // still returns OriginIP in DNS !!!
		},
		{
			// domain NOT in domains.csv, ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "google.de"),
			config:   "../test_resources/acl_cidr_domain.yaml",
			expected: OriginIP,
		},
		{
			// domain in domains.csv, ip ACCEPT in cidr.csv
			connInfo: mockConnInfo("77.77.1.1", "ipinfo.io"),
			config:   "../test_resources/acl_cidr_domain.yaml",
			expected: ProxyIP,
		},
		{
			// domain in domains.csv, ip REJECT in cidr.csv
			connInfo: mockConnInfo("1.1.1.1", "google.de"),
			config:   "../test_resources/acl_cidr_domain.yaml",
			expected: Reject, // still returns OriginIP in DNS !!!
		},
		{
			// domain NOT in domains.csv, ip REJECT in cidr.csv
			connInfo: mockConnInfo("1.1.1.1", "google.de"),
			config:   "../test_resources/acl_cidr_domain.yaml",
			expected: Reject, // still returns OriginIP in DNS !!!
		},
	}

	// Run the test cases
	for _, tc := range cases {
		MakeDecision(tc.connInfo, getAcls(&logger, tc.config))
		if tc.expected != tc.connInfo.Decision {
			t.Errorf("MakeDecision (domain=%v,ip=%v,config=%v) decided %v, expected %v", tc.connInfo.Domain, tc.connInfo.SrcIP, tc.config, tc.connInfo.Decision, tc.expected)
		}
	}
}

func getAcls(log *zerolog.Logger, config string) []ACL {
	var k = koanf.New(".")
	if err := k.Load(file.Provider(config), yaml.Parser()); err != nil {
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

func mockConnInfo(srcIp string, domain string) *ConnInfo {
	addr, err := net.ResolveTCPAddr("tcp", srcIp+":80")

	if err != nil {
		logger.Fatal().Msgf("error parsing ip from string: %v", err)
	}

	return &ConnInfo{
		SrcIP:  addr,
		Domain: domain,
	}
}
