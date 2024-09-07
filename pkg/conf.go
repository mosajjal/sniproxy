package sniproxy

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"
)

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

	Acl []acl.ACL `yaml:"-"`

	DnsClient DNSClient    `yaml:"-"`
	Dialer    proxy.Dialer `yaml:"-"`
	// list of interface source IPs; used to rotate source IPs when initializing connections
	SourceAddr       []netip.Addr `yaml:"-"`
	PreferredVersion string       `yaml:"preferred_version"` // ipv4 (or 4), ipv6 (or 6), ipv4only, ipv6only, any. empty (or 0) means any.

	// metrics
	RecievedHTTP  metrics.Counter `yaml:"-"`
	ProxiedHTTP   metrics.Counter `yaml:"-"`
	RecievedHTTPS metrics.Counter `yaml:"-"`
	ProxiedHTTPS  metrics.Counter `yaml:"-"`
	RecievedDNS   metrics.Counter `yaml:"-"`
	ProxiedDNS    metrics.Counter `yaml:"-"`
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
		c.Dialer, err = socks5.NewClient(uri.Host, socksAuth.User, socksAuth.Password, 60, 60)
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
	c.DnsClient = *dnsClient
	return nil
}

// parseRanges parses a range of ports or a single port. It returns a list of ports
func parseRanges(portRange ...string) ([]int, error) {
	var ports []int

	for _, portRange := range portRange {

		if strings.Index(portRange, "-") == -1 {
			port, err := strconv.Atoi(portRange)
			if err != nil {
				return nil, fmt.Errorf("error parsing port: %v", err)
			}
			ports = append(ports, port)
		} else {
			num1Str := strings.Split(portRange, "-")[0]
			num2Str := strings.Split(portRange, "-")[1]
			// convert both numbers to integers

			num1, err := strconv.Atoi(num1Str)
			if err != nil {
				return nil, fmt.Errorf("error parsing port range: %v", err)
			}
			num2, err := strconv.Atoi(num2Str)
			if err != nil {
				return nil, fmt.Errorf("error parsing port range: %v", err)
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
		return nil, fmt.Errorf("error parsing bind address: %v", err)
	}
	bindAddresses := []string{bindAddPort.String()}

	// now all the ranges must be parsed, and each of them converted into a bind address and added to the list
	portRange, err := parseRanges(additional...)
	if err != nil {
		return nil, fmt.Errorf("error parsing bind address range: %v", err)
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
func (c *Config) SetBindHTTPListeners(logger zerolog.Logger) error {
	bindAddresses, err := parseBinders(c.BindHTTP, c.BindHTTPAdditional)
	if err != nil {
		return fmt.Errorf("error parsing bind addresses for HTTP: %v", err)
	}
	c.BindHTTPListeners = bindAddresses
	return nil
}

// SetBindHTTPSListeners sets up a list of bind addresses for HTTPS
func (c *Config) SetBindHTTPSListeners(logger zerolog.Logger) error {
	bindAddresses, err := parseBinders(c.BindHTTPS, c.BindHTTPSAdditional)
	if err != nil {
		return fmt.Errorf("error parsing bind addresses for HTTPS: %v", err)
	}
	c.BindHTTPSListeners = bindAddresses
	return nil
}
