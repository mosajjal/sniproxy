package sniproxy

import (
	"net/netip"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rcrowley/go-metrics"
	"golang.org/x/net/proxy"
)

type Config struct {
	PublicIPv4            string `yaml:"public_ipv4"`
	PublicIPv6            string `yaml:"public_ipv6"`
	UpstreamDNS           string `yaml:"upstream_dns"`
	UpstreamDNSOverSocks5 bool   `yaml:"upstream_dns_over_socks5"`
	UpstreamSOCKS5        string `yaml:"upstream_socks5"`
	BindDNSOverUDP        string `yaml:"bind_dns_over_udp"`
	BindDNSOverTCP        string `yaml:"bind_dns_over_tcp"`
	BindDNSOverTLS        string `yaml:"bind_dns_over_tls"`
	BindDNSOverQuic       string `yaml:"bind_dns_over_quic"`
	TLSCert               string `yaml:"tls_cert"`
	TLSKey                string `yaml:"tls_key"`
	BindHTTP              string `yaml:"bind_http"`
	BindHTTPS             string `yaml:"bind_https"`
	Interface             string `yaml:"interface"`
	BindPrometheus        string `yaml:"bind_prometheus"`
	AllowConnToLocal      bool   `yaml:"allow_conn_to_local"`

	Acl []acl.ACL `yaml:"-"`

	DnsClient DNSClient    `yaml:"-"`
	Dialer    proxy.Dialer `yaml:"-"`
	// list of interface source IPs; used to rotate source IPs when initializing connections
	SourceAddr       []netip.Addr `yaml:"-"`
	PreferredVersion uint         `yaml:"preferred_version"` // "4" or "6" for outbound connections

	// metrics
	RecievedHTTP  metrics.Counter `yaml:"-"`
	ProxiedHTTP   metrics.Counter `yaml:"-"`
	RecievedHTTPS metrics.Counter `yaml:"-"`
	ProxiedHTTPS  metrics.Counter `yaml:"-"`
	RecievedDNS   metrics.Counter `yaml:"-"`
	ProxiedDNS    metrics.Counter `yaml:"-"`
}
