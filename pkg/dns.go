package sniproxy

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"strings"

	rdns "github.com/folbricht/routedns"

	doqserver "github.com/mosajjal/doqd/pkg/server"
	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rs/zerolog"
	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"

	"github.com/miekg/dns"
)

// DNSClient is a wrapper around the DNS client
type DNSClient struct {
	rdns.Resolver
	C *Config
}

// findBootstrapIP tries to resolve well-known DNS resolvers
// to their IP addresses
//
// dns.quad9.net -> 9.9.9.9, 2620:fe::9
// one.one.one.one -> 1.1.1.1, 2606:4700:4700::1111
// dns.google -> 8.8.8.8, 2001:4860:4860::8888
func findBootstrapIP(fqdn string, version int) string {
	wellKnownDomains := map[string]map[int]string{
		"dns.quad9.net":   {4: "9.9.9.9", 6: "2620:fe::9"},
		"one.one.one.one": {4: "1.1.1.1", 6: "2606:4700:4700::1111"},
		"dns.google":      {4: "8.8.8.8", 6: "2001:4860:4860::8888"},
	}
	if version != 4 && version != 6 {
		return ""
	}
	if ips, ok := wellKnownDomains[fqdn]; !ok {
		return ""
	} else {
		return ips[version]
	}
}

// pickSrcAddr picks a random source address from the list of configured source addresses.
// version specifies the IP version to pick. It returns nil if no suitable address is found.
func (c *Config) pickSrcAddr(version string) net.IP {
	if len(c.SourceAddr) == 0 {
		return nil
	}

	ipVersion := ParseIPVersion(version)

	// Filter addresses based on version preference
	var candidates []netip.Addr
	for _, addr := range c.SourceAddr {
		switch ipVersion {
		case IPVersionIPv4Only:
			if addr.Is4() {
				candidates = append(candidates, addr)
			}
		case IPVersionIPv6Only:
			if addr.Is6() {
				candidates = append(candidates, addr)
			}
		case IPVersionIPv4Preferred:
			candidates = append(candidates, addr)
		case IPVersionIPv6Preferred:
			candidates = append(candidates, addr)
		case IPVersionAny:
			candidates = append(candidates, addr)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Sort candidates by preference
	switch ipVersion {
	case IPVersionIPv4Preferred:
		// Put IPv4 addresses first
		var ipv4, ipv6 []netip.Addr
		for _, addr := range candidates {
			if addr.Is4() {
				ipv4 = append(ipv4, addr)
			} else {
				ipv6 = append(ipv6, addr)
			}
		}
		candidates = append(ipv4, ipv6...)
	case IPVersionIPv6Preferred:
		// Put IPv6 addresses first
		var ipv4, ipv6 []netip.Addr
		for _, addr := range candidates {
			if addr.Is6() {
				ipv6 = append(ipv6, addr)
			} else {
				ipv4 = append(ipv4, addr)
			}
		}
		candidates = append(ipv6, ipv4...)
	}

	// Pick a random candidate
	if len(candidates) > 0 {
		return candidates[rand.Intn(len(candidates))].AsSlice()
	}

	return nil
}

// PerformExternalAQuery performs an external DNS query for the given domain name.
func (dnsc *DNSClient) PerformExternalAQuery(fqdn string, QType uint16) ([]dns.RR, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion(fqdn, QType)
	msg.SetEdns0(DNSUDPSize, true)

	if dnsc == nil {
		return nil, fmt.Errorf("dns client is not initialised")
	}
	res, err := dnsc.Resolve(&msg, rdns.ClientInfo{})
	if res == nil {
		return nil, err
	}
	return res.Answer, err
}

func processQuestion(c *Config, l zerolog.Logger, q dns.Question, decision acl.Decision) ([]dns.RR, error) {
	c.ReceivedDNS.Inc(1)
	// Check to see if we should respond with our own IP
	switch decision {

	// Return the public IP.
	case acl.ProxyIP, acl.Override, acl.Accept:
		c.ProxiedDNS.Inc(1)
		l.Info().Msgf("returned sniproxy address for domain %s", q.Name)

		if q.Qtype == dns.TypeA {
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, c.PublicIPv4))
			return []dns.RR{rr}, err
		}
		if q.Qtype == dns.TypeAAAA {
			if c.PublicIPv6 != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, c.PublicIPv6))
				return []dns.RR{rr}, err
			}
			// return an empty response if we don't have an IPv6 address
			return []dns.RR{}, nil
		}

	// return empty response for rejected ACL
	case acl.Reject:
		// drop the request
		l.Debug().Msgf("rejected request for domain %s", q.Name)
		return []dns.RR{}, nil

	// Otherwise do an upstream query and use that answer.
	default:
		l.Debug().Msgf("perform external query for domain %s", q.Name)
		resp, err := c.DNSClient.PerformExternalAQuery(q.Name, q.Qtype)
		if err != nil {
			return nil, err
		}
		l.Info().Msgf("returned origin address for fqdn %s", q.Name)
		return resp, nil
	}
	return []dns.RR{}, nil
}

// lookupDomain looks up a domain name and returns the IP address.
// version specifies the IP version preference using the IPVersion constants.
func (dnsc DNSClient) lookupDomain(domain string, version string) (netip.Addr, error) {
	ipVersion := ParseIPVersion(version)

	switch ipVersion {
	case IPVersionIPv4Only:
		return dnsc.lookupDomain4(domain)
	case IPVersionIPv6Only:
		return dnsc.lookupDomain6(domain)
	case IPVersionIPv4Preferred, IPVersionAny:
		// Try IPv4 first, fall back to IPv6
		ip, err := dnsc.lookupDomain4(domain)
		if err != nil {
			return dnsc.lookupDomain6(domain)
		}
		return ip, nil
	case IPVersionIPv6Preferred:
		// Try IPv6 first, fall back to IPv4
		ip, err := dnsc.lookupDomain6(domain)
		if err != nil {
			return dnsc.lookupDomain4(domain)
		}
		return ip, nil
	}
	return netip.IPv4Unspecified(), fmt.Errorf("invalid IP version preference")
}

func (dnsc DNSClient) lookupDomain4(domain string) (netip.Addr, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	rAddrDNS, err := dnsc.PerformExternalAQuery(domain, dns.TypeA)
	if err != nil {
		return netip.IPv4Unspecified(), err
	}
	if len(rAddrDNS) > 0 {
		if rAddrDNS[0].Header().Rrtype == dns.TypeCNAME {
			return dnsc.lookupDomain4(rAddrDNS[0].(*dns.CNAME).Target)
		}
		if rAddrDNS[0].Header().Rrtype == dns.TypeA {
			return netip.AddrFrom4([4]byte(rAddrDNS[0].(*dns.A).A.To4())), nil
		}
	} else {
		return netip.IPv4Unspecified(), fmt.Errorf("empty DNS response for %s", domain)
	}
	return netip.IPv4Unspecified(), fmt.Errorf("unknown DNS record type %s for %s", dns.TypeToString[rAddrDNS[0].Header().Rrtype], domain)
}

func (dnsc DNSClient) lookupDomain6(domain string) (netip.Addr, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	rAddrDNS, err := dnsc.PerformExternalAQuery(domain, dns.TypeAAAA)
	if err != nil {
		return netip.IPv6Unspecified(), err
	}
	if len(rAddrDNS) > 0 {
		if rAddrDNS[0].Header().Rrtype == dns.TypeCNAME {
			return dnsc.lookupDomain6(rAddrDNS[0].(*dns.CNAME).Target)
		}
		if rAddrDNS[0].Header().Rrtype == dns.TypeAAAA {
			return netip.AddrFrom16([16]byte(rAddrDNS[0].(*dns.AAAA).AAAA.To16())), nil
		}
	} else {
		return netip.IPv6Unspecified(), fmt.Errorf("empty DNS response for %s", domain)
	}
	return netip.IPv6Unspecified(), fmt.Errorf("unknown DNS record type %s for %s", dns.TypeToString[rAddrDNS[0].Header().Rrtype], domain)
}

func handleDNS(c *Config, l zerolog.Logger) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Compress = false

		if r.Opcode != dns.OpcodeQuery {
			m.SetRcode(r, dns.RcodeNotImplemented)
			w.WriteMsg(m)
			return
		}

		for _, q := range m.Question {
			connInfo := acl.ConnInfo{
				SrcIP:  w.RemoteAddr(),
				Domain: q.Name,
			}
			acl.MakeDecision(&connInfo, c.ACL)
			answers, err := processQuestion(c, l, q, connInfo.Decision)
			if err != nil {
				continue
			}
			m.Answer = append(m.Answer, answers...)
		}

		w.WriteMsg(m)
	}
}

// RunDNS starts DNS servers based on the provided configuration.
func RunDNS(c *Config, l zerolog.Logger) {
	l = l.With().Str("service", "dns").Logger()
	dns.HandleFunc(".", handleDNS(c, l))
	// start DNS UDP serverUdp
	if c.BindDNSOverUDP != "" {
		go func() {
			serverUDP := &dns.Server{Addr: c.BindDNSOverUDP, Net: "udp"}
			defer serverUDP.Shutdown()
			l.Info().Msgf("started udp dns on %s", c.BindDNSOverUDP)
			err := serverUDP.ListenAndServe()
			if err != nil {
				l.Error().Msgf("error starting udp dns server: %s", err)
				l.Info().Msgf("failed to start server: %s\nyou can run the following command to pinpoint which process is listening on your bind\nsudo ss -pltun", c.BindDNSOverUDP)
				panic(2)
			}
		}()
	}
	// start DNS TCP serverTcp
	if c.BindDNSOverTCP != "" {
		go func() {
			serverTCP := &dns.Server{Addr: c.BindDNSOverTCP, Net: "tcp"}
			defer serverTCP.Shutdown()
			l.Info().Msgf("started tcp dns on %s", c.BindDNSOverTCP)
			err := serverTCP.ListenAndServe()
			if err != nil {
				l.Error().Msgf("failed to start server %s", err)
				l.Info().Msgf("failed to start server: %s\nyou can run the following command to pinpoint which process is listening on your bind\nsudo ss -pltun", c.BindDNSOverUDP)
			}
		}()
	}

	// start DNS TLS serverTls
	if c.BindDNSOverTLS != "" {
		go func() {
			crt, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
			if err != nil {
				l.Error().Msg(err.Error())
				panic(2)

			}
			tlsConfig := &tls.Config{}
			tlsConfig.Certificates = []tls.Certificate{crt}

			serverTLS := &dns.Server{Addr: c.BindDNSOverTLS, Net: "tcp-tls", TLSConfig: tlsConfig}
			defer serverTLS.Shutdown()
			l.Info().Msgf("started dot dns on %s", c.BindDNSOverTLS)
			err = serverTLS.ListenAndServe()
			if err != nil {
				l.Error().Msg(err.Error())
			}
		}()
	}

	if c.BindDNSOverQuic != "" {

		crt, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			l.Error().Msg(err.Error())
		}

		// Create the QUIC listener
		doqConf := doqserver.Config{
			ListenAddr: c.BindDNSOverQuic,
			Cert:       crt,
			Upstream:   c.BindDNSOverUDP,
			TLSCompat:  true,
			Debug:      l.GetLevel() == zerolog.DebugLevel,
		}
		doqServer, err := doqserver.New(doqConf)
		if err != nil {
			l.Error().Msg(err.Error())
		}

		// Accept QUIC connections
		l.Info().Msgf("starting quic listener %s", c.BindDNSOverQuic)
		go doqServer.Listen()

	}
}

func getDialerFromProxyURL(proxyURL *url.URL) (*rdns.Dialer, error) {
	var dialer rdns.Dialer
	// by default dialer is direct
	dialer = &net.Dialer{}
	if proxyURL != nil && proxyURL.Host != "" {
		// create a net dialer with proxy
		auth := new(proxy.Auth)
		if proxyURL.User != nil {
			auth.User = proxyURL.User.Username()
			if p, ok := proxyURL.User.Password(); ok {
				auth.Password = p
			} else {
				auth.Password = ""
			}
		}
		c, err := socks5.NewClient(proxyURL.Host, auth.User, auth.Password, 0, 5) // 0 and 5 are borrowed from routedns pr
		if err != nil {
			return nil, err
		}
		dialer = c
	}
	return &dialer, nil
}

/*
NewDNSClient creates a DNS Client by parsing a URI and returning the appropriate client for it.

Supported URI schemes and formats:
  - udp://1.1.1.1:53 - Plain DNS over UDP (IPv4)
  - udp6://[2606:4700:4700::1111]:53 - Plain DNS over UDP (IPv6)
  - tcp://9.9.9.9:5353 - Plain DNS over TCP (IPv4)
  - tcp6://[2606:4700:4700::1111]:53 - Plain DNS over TCP (IPv6)
  - tcp-tls://dns.adguard.com:853 - DNS over TLS (DoT)
  - tcp-tls6://[2606:4700:4700::1111]:853 - DNS over TLS IPv6
  - https://dns.adguard.com/dns-query - DNS over HTTPS (DoH)
  - quic://dns.adguard.com:8853 - DNS over QUIC (DoQ)

Parameters:
  - C: Configuration object containing network settings
  - uri: The DNS server URI to connect to
  - skipVerify: Skip TLS certificate verification (not recommended for production)
  - proxy: Optional SOCKS5 proxy URL for DNS queries

Returns a configured DNSClient or an error if the URI is invalid or connection fails.
*/
func NewDNSClient(C *Config, uri string, skipVerify bool, proxy string) (*DNSClient, error) {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	var dialer *rdns.Dialer
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}
	dialer, err = getDialerFromProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}

	switch parsedURL.Scheme {
	case "udp", "udp6":
		var host, port string
		// if port doesn't exist, use default port
		if host, port, err = net.SplitHostPort(parsedURL.Host); err != nil {
			host = parsedURL.Host
			port = "53"
		}
		Address := rdns.AddressWithDefault(host, port)

		var ldarr net.IP
		if parsedURL.Scheme == "udp6" {
			ldarr = C.pickSrcAddr("ipv6only")
		} else {
			ldarr = C.pickSrcAddr("ipv4only")
		}

		opt := rdns.DNSClientOptions{
			LocalAddr:    ldarr,
			UDPSize:      DNSClientUDPSize,
			Dialer:       *dialer,
			QueryTimeout: DNSTimeout,
		}
		id, err := rdns.NewDNSClient("id", Address, "udp", opt)
		if err != nil {
			return nil, err
		}
		return &DNSClient{id, C}, nil
	case "tcp", "tcp6":
		var host, port string
		// if port doesn't exist, use default port
		if host, port, err = net.SplitHostPort(parsedURL.Host); err != nil {
			host = parsedURL.Host
			port = "53"
		}

		var ldarr net.IP
		if parsedURL.Scheme == "tcp6" {
			ldarr = C.pickSrcAddr("ipv6only")
		} else {
			ldarr = C.pickSrcAddr("ipv4only")
		}

		Address := rdns.AddressWithDefault(host, port)
		opt := rdns.DNSClientOptions{
			LocalAddr: ldarr,
			UDPSize:   DNSClientUDPSize,
			Dialer:    *dialer,
		}
		id, err := rdns.NewDNSClient("id", Address, "tcp", opt)
		if err != nil {
			return nil, err
		}
		return &DNSClient{id, C}, nil
	case "tls", "tls6", "tcp-tls", "tcp-tls6":
		tlsConfig, err := rdns.TLSClientConfig("", "", "", parsedURL.Host)
		if err != nil {
			return nil, err
		}
		var ldarr net.IP
		bootstrapAddr := findBootstrapIP(parsedURL.Host, 4)
		if parsedURL.Scheme == "tls6" || parsedURL.Scheme == "tcp-tls6" {
			ldarr = C.pickSrcAddr("ipv6only")
			bootstrapAddr = findBootstrapIP(parsedURL.Host, 6)
		} else {
			ldarr = C.pickSrcAddr("ipv4only")
		}

		opt := rdns.DoTClientOptions{
			TLSConfig:     tlsConfig,
			BootstrapAddr: bootstrapAddr,
			LocalAddr:     ldarr,
			Dialer:        *dialer,
		}
		id, err := rdns.NewDoTClient("id", parsedURL.Host, opt)
		if err != nil {
			return nil, err
		}
		return &DNSClient{id, C}, nil
	case "https":
		tlsConfig := &tls.Config{
			InsecureSkipVerify: skipVerify,
			ServerName:         strings.Split(parsedURL.Host, ":")[0],
		}

		transport := "tcp"
		opt := rdns.DoHClientOptions{
			Method:        "POST",
			TLSConfig:     tlsConfig,
			BootstrapAddr: findBootstrapIP(parsedURL.Host, 4),
			Transport:     transport,
			LocalAddr:     C.pickSrcAddr("ipv4only"),
			Dialer:        *dialer,
		}
		id, err := rdns.NewDoHClient("id", parsedURL.String(), opt)
		if err != nil {
			return nil, err
		}
		return &DNSClient{id, C}, nil

	case "quic":
		tlsConfig := &tls.Config{
			InsecureSkipVerify: skipVerify,
			ServerName:         strings.Split(parsedURL.Host, ":")[0],
		}

		opt := rdns.DoQClientOptions{
			TLSConfig: tlsConfig,
			LocalAddr: C.pickSrcAddr("ipv4only"),
		}
		id, err := rdns.NewDoQClient("id", parsedURL.Host, opt)
		if err != nil {
			return nil, err
		}
		return &DNSClient{id, C}, nil
	}
	return nil, fmt.Errorf("failed to parse DNS upstream URI %q: unsupported scheme %q", uri, parsedURL.Scheme)
}
