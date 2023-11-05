package sniproxy

import (
	"crypto/tls"
	"fmt"
	"net"
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
		resp, err := c.DnsClient.PerformExternalAQuery(q.Name, q.Qtype)
		if err != nil {
			return nil, err
		}
		l.Info().Msgf("returned origin address for fqdn %s", q.Name)
		return resp, nil
	}
	return []dns.RR{}, nil
}

func (dnsc DNSClient) lookupDomain4(domain string) (net.IP, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	rAddrDNS, err := dnsc.PerformExternalAQuery(domain, dns.TypeA)
	if err != nil {
		return nil, err
	}
	if len(rAddrDNS) > 0 {
		if rAddrDNS[0].Header().Rrtype == dns.TypeCNAME {
			return dnsc.lookupDomain4(rAddrDNS[0].(*dns.CNAME).Target)
		}
		if rAddrDNS[0].Header().Rrtype == dns.TypeA {
			return rAddrDNS[0].(*dns.A).A, nil
		}
	} else {
		return nil, fmt.Errorf("[DNS] Empty DNS response for %s", domain)
	}
	return nil, fmt.Errorf("[DNS] Unknown type %s", dns.TypeToString[rAddrDNS[0].Header().Rrtype])
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
			acl.MakeDecision(&connInfo, c.Acl)
			answers, err := processQuestion(c, l, q, connInfo.Decision)
			if err != nil {
				continue
			}
			m.Answer = append(m.Answer, answers...)
		}

		w.WriteMsg(m)
	}
}

func RunDNS(c *Config, l zerolog.Logger) {
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
		tlsConfig := &tls.Config{}
		tlsConfig.Certificates = []tls.Certificate{crt}

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
		var auth *proxy.Auth
		if proxyURL.User != nil {
			auth = new(proxy.Auth)
			auth.User = proxyURL.User.Username()
			if p, ok := proxyURL.User.Password(); ok {
				auth.Password = p
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

		opt := rdns.DNSClientOptions{
			LocalAddr: C.SourceAddr,
			UDPSize:   1300,
			Dialer:    *dialer,
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
		Address := rdns.AddressWithDefault(host, port)
		opt := rdns.DNSClientOptions{
			LocalAddr: C.SourceAddr,
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

		opt := rdns.DoTClientOptions{
			TLSConfig:     tlsConfig,
			BootstrapAddr: "1.1.1.1", //TODO: make this configurable
			LocalAddr:     C.SourceAddr,
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
			Method:        "POST", // TODO: support POST
			TLSConfig:     tlsConfig,
			BootstrapAddr: "1.1.1.1", //TODO: make this configurable
			Transport:     transport,
			LocalAddr:     C.SourceAddr,
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
			LocalAddr: C.SourceAddr,
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
