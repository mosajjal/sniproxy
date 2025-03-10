package sniproxy

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"

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

var dnsLock sync.RWMutex

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
// version specifies the IP version to pick, 4 or 6. If 0, any version is picked.
func (c *Config) pickSrcAddr(version string) net.IP {
	if len(c.SourceAddr) == 0 {
		return nil
	}
	// shuffle the list of source addresses
	// TODO: potentially a better way to do this
	for i := range c.SourceAddr {
		j := rand.Intn(i + 1)
		c.SourceAddr[i], c.SourceAddr[j] = c.SourceAddr[j], c.SourceAddr[i]
	}
	switch version {
	case "ipv4only":
		for _, ip := range c.SourceAddr {
			if ip.Is4() {
				return ip.AsSlice()
			}
		}
	case "ipv6only":
		for _, ip := range c.SourceAddr {
			if ip.Is6() {
				return ip.AsSlice()
			}
		}
	case "ipv4", "4", "0":
		for _, ip := range c.SourceAddr {
			if ip.Is4() {
				return ip.AsSlice()
			}
			if ip.Is6() {
				return ip.AsSlice()
			}
		}
	case "ipv6", "6":
		for _, ip := range c.SourceAddr {
			if ip.Is6() {
				return ip.AsSlice()
			}
			if ip.Is4() {
				return ip.AsSlice()
			}
		}
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
	msg.SetEdns0(1232, true)
	dnsLock.Lock()
	if dnsc == nil {
		return nil, fmt.Errorf("dns client is not initialised")
	}
	res, err := dnsc.Resolve(&msg, rdns.ClientInfo{})
	dnsLock.Unlock()
	if res == nil {
		return nil, err
	}
	return res.Answer, err
}

func processQuestion(c *Config, l zerolog.Logger, q dns.Question, decision acl.Decision) ([]dns.RR, error) {
	c.RecievedDNS.Inc(1)
	// Check to see if we should respond with our own IP
	switch decision {

	// Return the public IP.
	case acl.ProxyIP, acl.Override, acl.Accept: // TODO: accept should be here?
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
// version specifies the IP version to lookup, 4 or 6. If 0, any version is picked. currently 0 is ipv4 with ipv6 fallback
// options are: ipv4 (or 4) and ipv6 (or 6), ipv4only and ipv6only
func (dnsc DNSClient) lookupDomain(domain string, version string) (netip.Addr, error) {

	switch version {
	case "ipv4only":
		return dnsc.lookupDomain4(domain)
	case "ipv6only":
		return dnsc.lookupDomain6(domain)
	case "ipv4", "4", "0", "":
		// try with ipv4, if there's any error, try with ipv6
		ip, err := dnsc.lookupDomain4(domain)
		if err != nil {
			return dnsc.lookupDomain6(domain)
		}
		return ip, nil
	case "ipv6", "6":
		// try with ipv6, if there's any error, try with ipv4
		ip, err := dnsc.lookupDomain6(domain)
		if err != nil {
			return dnsc.lookupDomain4(domain)
		}
		return ip, nil
	}
	return netip.IPv4Unspecified(), fmt.Errorf("invalid version")
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
		return netip.IPv4Unspecified(), fmt.Errorf("[DNS] Empty DNS response for %s", domain)
	}
	return netip.IPv4Unspecified(), fmt.Errorf("[DNS] Unknown type %s", dns.TypeToString[rAddrDNS[0].Header().Rrtype])
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
		if rAddrDNS[0].Header().Header().Rrtype == dns.TypeCNAME {
			return dnsc.lookupDomain6(rAddrDNS[0].(*dns.CNAME).Target)
		}
		if rAddrDNS[0].Header().Rrtype == dns.TypeAAAA {
			return netip.AddrFrom16([16]byte(rAddrDNS[0].(*dns.AAAA).AAAA.To16())), nil
		}
	} else {
		return netip.IPv6Unspecified(), fmt.Errorf("[DNS] Empty DNS response for %s", domain)
	}
	return netip.IPv6Unspecified(), fmt.Errorf("[DNS] Unknown type %s", dns.TypeToString[rAddrDNS[0].Header().Rrtype])
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
			l.Info().Msgf("started udp dns on %s", c.BindDNSOverUDP)
			err := serverUDP.ListenAndServe()
			defer serverUDP.Shutdown()
			if err != nil {
				l.Error().Msgf("error starting udp dns server: %s", err)
				l.Info().Msgf("failed to start server: %s\nyou can run the following command to pinpoint which process is listening on your bind\nsudo ss -pltun", c.BindDNSOverUDP)
				panic(2)
			}
		}()
	}
	// start DNS UDP serverTcp
	if c.BindDNSOverTCP != "" {
		go func() {
			serverTCP := &dns.Server{Addr: c.BindDNSOverTCP, Net: "tcp"}
			l.Info().Msgf("started tcp dns on %s", c.BindDNSOverTCP)
			err := serverTCP.ListenAndServe()
			defer serverTCP.Shutdown()
			if err != nil {
				l.Error().Msgf("failed to start server %s", err)
				l.Info().Msgf("failed to start server: %s\nyou can run the following command to pinpoint which process is listening on your bind\nsudo ss -pltun", c.BindDNSOverUDP)
			}
		}()
	}

	// start DNS UDP serverTls
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
			l.Info().Msgf("started dot dns on %s", c.BindDNSOverTLS)
			err = serverTLS.ListenAndServe()
			defer serverTLS.Shutdown()
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
NewDNSClient creates a DNS Client by parsing a URI and returning the appropriate client for it
URI string could look like below:
  - udp://1.1.1.1:53
  - udp6://[2606:4700:4700::1111]:53
  - tcp://9.9.9.9:5353
  - https://dns.adguard.com
  - quic://dns.adguard.com:8853
  - tcp-tls://dns.adguard.com:853
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
			UDPSize:      1300,
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
			UDPSize:   1300,
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
			Method:        "POST", // TODO: support anything other than POST
			TLSConfig:     tlsConfig,
			BootstrapAddr: findBootstrapIP(parsedURL.Host, 4),
			Transport:     transport,
			LocalAddr:     C.pickSrcAddr("ipv4only"), //TODO:support IPv6
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
			LocalAddr: C.pickSrcAddr("ipv4only"), //TODO:support IPv6
			// Dialer:    *dialer, // BUG: not yet supported
		}
		id, err := rdns.NewDoQClient("id", parsedURL.Host, opt)
		if err != nil {
			return nil, err
		}
		return &DNSClient{id, C}, nil
	}
	return nil, fmt.Errorf("Can't understand the URL")
}
