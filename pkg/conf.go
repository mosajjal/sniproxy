package sniproxy

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"
)

// IPVersion represents the preferred IP version for connections
type IPVersion int

const (
	// IPVersionAny allows both IPv4 and IPv6 with no preference
	IPVersionAny IPVersion = iota
	// IPVersionIPv4Preferred prefers IPv4 but falls back to IPv6
	IPVersionIPv4Preferred
	// IPVersionIPv6Preferred prefers IPv6 but falls back to IPv4
	IPVersionIPv6Preferred
	// IPVersionIPv4Only only allows IPv4 connections
	IPVersionIPv4Only
	// IPVersionIPv6Only only allows IPv6 connections
	IPVersionIPv6Only
)

// ParseIPVersion converts a string to IPVersion type
func ParseIPVersion(s string) IPVersion {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "ipv4only", "4only":
		return IPVersionIPv4Only
	case "ipv6only", "6only":
		return IPVersionIPv6Only
	case "ipv4", "4":
		return IPVersionIPv4Preferred
	case "ipv6", "6":
		return IPVersionIPv6Preferred
	case "any", "0", "":
		return IPVersionAny
	default:
		return IPVersionAny
	}
}

// String returns the string representation of IPVersion
func (v IPVersion) String() string {
	switch v {
	case IPVersionIPv4Only:
		return "ipv4only"
	case IPVersionIPv6Only:
		return "ipv6only"
	case IPVersionIPv4Preferred:
		return "ipv4"
	case IPVersionIPv6Preferred:
		return "ipv6"
	case IPVersionAny:
		return "any"
	default:
		return "any"
	}
}

// Config is the main runtime configuration for the proxy
type Config struct {
	PublicIPv4            string   `yaml:"public_ipv4"`
	PublicIPv6            string   `yaml:"public_ipv6"`
	UpstreamDNS           string   `yaml:"upstream_dns"`
	UpstreamDNSOverSocks5 bool     `yaml:"upstream_dns_over_socks5"`
	UpstreamSOCKS5        string   `yaml:"upstream_socks5"`
	BindDNSOverUDP        string   `yaml:"bind_dns_over_udp"`
	BindDNSOverTCP        string   `yaml:"bind_dns_over_tcp"`
	BindDNSOverTLS        string   `yaml:"bind_dns_over_tls"`
	BindDNSOverQuic       string   `yaml:"bind_dns_over_quic"`
	TLSCert               string   `yaml:"tls_cert"`
	TLSKey                string   `yaml:"tls_key"`
	BindHTTP              string   `yaml:"bind_http"`
	BindHTTPAdditional    []string `yaml:"bind_http_additional"`
	BindHTTPListeners     []string `yaml:"-"` // compiled list of bind_http and bind_http_additional listen addresses
	BindHTTPS             string   `yaml:"bind_https"`
	BindHTTPSAdditional   []string `yaml:"bind_https_additional"`
	BindHTTPSListeners    []string `yaml:"-"` // compiled list of bind_https and bind_https_additional listen addresses
	Interface             string   `yaml:"interface"`
	BindPrometheus        string   `yaml:"bind_prometheus"`
	AllowConnToLocal      bool     `yaml:"allow_conn_to_local"`

	ACL []acl.ACL `yaml:"-"`

	DNSClient DNSClient    `yaml:"-"`
	Dialer    proxy.Dialer `yaml:"-"`
	// list of interface source IPs; used to rotate source IPs when initializing connections
	SourceAddr       []netip.Addr `yaml:"-"`
	PreferredVersion string       `yaml:"preferred_version"` // ipv4 (or 4), ipv6 (or 6), ipv4only, ipv6only, any. empty (or 0) means any.

	// metrics
	ReceivedHTTP  metrics.Counter `yaml:"-"`
	ProxiedHTTP   metrics.Counter `yaml:"-"`
	ReceivedHTTPS metrics.Counter `yaml:"-"`
	ProxiedHTTPS  metrics.Counter `yaml:"-"`
	ReceivedDNS   metrics.Counter `yaml:"-"`
	ProxiedDNS    metrics.Counter `yaml:"-"`
}

const (
	// DNSTimeout is the default timeout for DNS queries
	DNSTimeout = 10 * time.Second
	// HTTPReadTimeout is the default timeout for HTTP requests
	HTTPReadTimeout = 10 * time.Second
	// HTTPWriteTimeout is the default timeout for HTTP responses
	HTTPWriteTimeout = 10 * time.Second
	// DNSUDPSize is the EDNS0 UDP size for DNS queries
	DNSUDPSize = 1232
	// DNSClientUDPSize is the UDP size for DNS client options
	DNSClientUDPSize = 1300
	// SOCKS5TCPTimeout is the timeout for SOCKS5 TCP connections
	SOCKS5TCPTimeout = 60
	// SOCKS5UDPTimeout is the timeout for SOCKS5 UDP connections
	SOCKS5UDPTimeout = 60
)

// Validate checks if the configuration is valid and returns an error if it's not.
// It ensures that at least one DNS binding is configured and other critical settings are valid.
func (c *Config) Validate() error {
	if c.BindDNSOverUDP == "" && c.BindDNSOverTCP == "" && c.BindDNSOverTLS == "" && c.BindDNSOverQuic == "" {
		return fmt.Errorf("at least one DNS binding (UDP, TCP, TLS, or QUIC) is required")
	}

	if c.UpstreamDNS == "" {
		return fmt.Errorf("upstream DNS server is required")
	}

	if c.BindHTTP == "" && c.BindHTTPS == "" {
		return fmt.Errorf("at least one HTTP or HTTPS binding is required")
	}

	if c.PublicIPv4 == "" && c.PublicIPv6 == "" {
		return fmt.Errorf("at least one public IP (IPv4 or IPv6) is required")
	}

	// Validate TLS configuration if TLS/QUIC DNS is enabled
	if (c.BindDNSOverTLS != "" || c.BindDNSOverQuic != "") && (c.TLSCert == "" || c.TLSKey == "") {
		return fmt.Errorf("TLS certificate and key are required for DNS over TLS/QUIC")
	}

	return nil
}

// below are some functions to help populating some config fields based on other config fields

// SetDialer sets up a TCP/UDP Dialer based on the proxy settings provided
// an error in this function means the application cannot continue
func (c *Config) SetDialer(logger zerolog.Logger) error {
	// sniproxy has the ability to use a SOCKS5 proxy for upstream connections
	// optionally, it can use the same SOCKS5 proxy for DNS queries
	if c.UpstreamSOCKS5 != "" {
		uri, err := url.Parse(c.UpstreamSOCKS5)
		if err != nil {
			// non-fatal error message
			logger.Error().Msg(err.Error())
		}
		if uri.Scheme != "socks5" {
			return fmt.Errorf("only SOCKS5 is supported")
		}

		logger.Info().Msgf("Using an upstream SOCKS5 proxy: %s", uri.Host)
		socksAuth := new(proxy.Auth)
		socksAuth.User = uri.User.Username()
		socksAuth.Password, _ = uri.User.Password()
		c.Dialer, err = socks5.NewClient(uri.Host, socksAuth.User, socksAuth.Password, SOCKS5TCPTimeout, SOCKS5UDPTimeout)
		if err != nil {
			// non-fatal error message
			logger.Error().Msg(err.Error())
		}
	} else {
		c.Dialer = proxy.Direct
	}
	return nil
}

// SetDNSClient sets up a DNS client based on the proxy settings provided
// an error in this function means the application cannot continue
func (c *Config) SetDNSClient(logger zerolog.Logger) error {

	// dnsProxy is a proxy used for upstream DNS connection.
	var dnsProxy string
	var dnsClient *DNSClient
	// if upstream socks5 is not provided or upstream dns over socks5 is disabled, disable socks5 for dns
	if c.UpstreamSOCKS5 != "" && !c.UpstreamDNSOverSocks5 {
		logger.Debug().Msg("disabling socks5 for dns because either upstream socks5 is not provided or upstream dns over socks5 is disabled")
		dnsProxy = ""
	} else {
		dnsProxy = c.UpstreamSOCKS5
	}
	var err error
	dnsClient, err = NewDNSClient(c, c.UpstreamDNS, true, dnsProxy)
	if err != nil {
		logger.Error().Msgf("error setting up dns client with socks5 proxy, falling back to direct DNS client: %v", err)
		dnsClient, err = NewDNSClient(c, c.UpstreamDNS, false, "")
		if err != nil {
			return fmt.Errorf("error setting up dns client: %v", err)
		}
	}
	c.DNSClient = *dnsClient
	return nil
}

// parseRanges parses a range of ports or a single port. It returns a list of ports
func parseRanges(portRange ...string) ([]int, error) {
	var ports []int

	for _, portRange := range portRange {

		if strings.Index(portRange, "-") == -1 {
			port, err := strconv.Atoi(portRange)
			if err != nil {
				return nil, fmt.Errorf("error parsing port: %w", err)
			}
			ports = append(ports, port)
		} else {
			num1Str := strings.Split(portRange, "-")[0]
			num2Str := strings.Split(portRange, "-")[1]
			// convert both numbers to integers

			num1, err := strconv.Atoi(num1Str)
			if err != nil {
				return nil, fmt.Errorf("error parsing port range start %q: %w", num1Str, err)
			}
			num2, err := strconv.Atoi(num2Str)
			if err != nil {
				return nil, fmt.Errorf("error parsing port range end %q: %w", num2Str, err)
			}
			for i := num1; i <= num2; i++ {
				ports = append(ports, i)
			}
		}
	}
	return ports, nil
}

// parseBinders parses a bind address and a list of additional ports or port ranges
func parseBinders(bind string, additional []string) ([]string, error) {
	// get the bind address from bind
	bindAddPort, err := netip.ParseAddrPort(bind)
	if err != nil {
		return nil, fmt.Errorf("error parsing bind address %q: %w", bind, err)
	}
	bindAddresses := []string{bindAddPort.String()}

	// now all the ranges must be parsed, and each of them converted into a bind address and added to the list
	portRange, err := parseRanges(additional...)
	if err != nil {
		return nil, fmt.Errorf("error parsing bind address range: %w", err)
	}
	for _, port := range portRange {
		bindAddresses = append(bindAddresses, fmt.Sprintf("%s:%d", bindAddPort.Addr(), port))
	}
	return bindAddresses, nil
}

// SetBindHTTPListeners sets up a list of bind addresses for HTTP
// it gets the bind address from bind_http as 0.0.0.0:80 format
// and the additional bind addresses from bind_http_additional as a list of ports or port ranges
// such as 8080, 8081-8083, 8085
// when this function is called, it will compile the list of bind addresses and store it in BindHTTPListeners
func (c *Config) SetBindHTTPListeners(_ zerolog.Logger) error {
	bindAddresses, err := parseBinders(c.BindHTTP, c.BindHTTPAdditional)
	if err != nil {
		return fmt.Errorf("error parsing bind addresses for HTTP: %w", err)
	}
	c.BindHTTPListeners = bindAddresses
	return nil
}

// SetBindHTTPSListeners sets up a list of bind addresses for HTTPS
func (c *Config) SetBindHTTPSListeners(_ zerolog.Logger) error {
	bindAddresses, err := parseBinders(c.BindHTTPS, c.BindHTTPSAdditional)
	if err != nil {
		return fmt.Errorf("error parsing bind addresses for HTTPS: %w", err)
	}
	c.BindHTTPSListeners = bindAddresses
	return nil
}
