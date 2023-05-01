package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mosajjal/dnsclient"
	doqserver "github.com/mosajjal/doqd/pkg/server"
	"github.com/mosajjal/sniproxy/acl"
	slog "golang.org/x/exp/slog"

	"github.com/miekg/dns"
)

type DNSClient struct {
	C dnsclient.Client
}

var dnsLock sync.RWMutex

var dnslog = slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue("dns")}}))

func (dnsc *DNSClient) performExternalAQuery(fqdn string, QType uint16) ([]dns.RR, time.Duration, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion(fqdn, QType)
	msg.SetEdns0(1232, true)
	dnsLock.Lock()
	if dnsc.C == nil {
		return nil, 0, fmt.Errorf("DNS client is not initialised")
	}
	res, trr, err := dnsc.C.Query(context.Background(), &msg)
	if err != nil {
		if err.Error() == "EOF" {
			dnslog.Info("reconnecting DNS...")
			// dnsc.C.Close()
			// dnsc.C, err = dnsclient.New(c.UpstreamDNS, true)
			err = c.dnsClient.C.Reconnect()
		}
	}
	dnsLock.Unlock()
	return res, trr, err
}

func processQuestion(q dns.Question, decision acl.Decision) ([]dns.RR, error) {
	c.recievedDNS.Inc(1)
	// Check to see if we should respond with our own IP
	if decision == acl.ProxyIP {
		// Return the public IP.
		c.proxiedDNS.Inc(1)
		dnslog.Info("returned sniproxy address for domain", "fqdn", q.Name)

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
	}

	// Otherwise do an upstream query and use that answer.
	resp, rtt, err := c.dnsClient.performExternalAQuery(q.Name, q.Qtype)
	if err != nil {
		return nil, err
	}

	dnslog.Info("returned origin address", "fqdn", q.Name, "rtt", rtt)

	return resp, nil
}

func (dnsc DNSClient) lookupDomain4(domain string) (net.IP, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	rAddrDNS, _, err := dnsc.performExternalAQuery(domain, dns.TypeA)
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

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
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
		c.acl.MakeDecision(&connInfo)
		answers, err := processQuestion(q, connInfo.Decision)
		if err != nil {
			dnslog.Error(err.Error())
			continue
		}
		m.Answer = append(m.Answer, answers...)
	}

	w.WriteMsg(m)
}

func runDNS() {
	dns.HandleFunc(".", handleDNS)
	// start DNS UDP serverUdp
	go func() {
		serverUDP := &dns.Server{Addr: fmt.Sprintf(":%d", c.DNSPort), Net: "udp"}
		dnslog.Info("Started UDP DNS", "host", "0.0.0.0", "port", c.DNSPort)
		err := serverUDP.ListenAndServe()
		defer serverUDP.Shutdown()
		if err != nil {
			dnslog.Error("Error starting UDP DNS server", "details", err)
			dnslog.Info(fmt.Sprintf("Failed to start server: %s\nYou can run the following command to pinpoint which process is listening on port %d\nsudo ss -pltun -at '( dport = :%d or sport = :%d )'", err.Error(), c.DNSPort, c.DNSPort, c.DNSPort))
			panic(2)
		}
	}()

	// start DNS UDP serverTcp
	if c.BindDNSOverTCP {
		go func() {
			serverTCP := &dns.Server{Addr: fmt.Sprintf(":%d", c.DNSPort), Net: "tcp"}
			dnslog.Info("Started TCP DNS", "host", "0.0.0.0", "port", c.DNSPort)
			err := serverTCP.ListenAndServe()
			defer serverTCP.Shutdown()
			if err != nil {
				dnslog.Error("Failed to start server", err)
				dnslog.Info(fmt.Sprintf("You can run the following command to pinpoint which process is listening on port %d\nsudo ss -pltun -at '( dport = :%d or sport = :%d )'", c.DNSPort, c.DNSPort, c.DNSPort))
			}
		}()
	}

	// start DNS UDP serverTls
	if c.BindDNSOverTLS {
		go func() {
			crt, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
			if err != nil {
				dnslog.Error(err.Error())
				panic(2)

			}
			tlsConfig := &tls.Config{}
			tlsConfig.Certificates = []tls.Certificate{crt}

			serverTLS := &dns.Server{Addr: ":853", Net: "tcp-tls", TLSConfig: tlsConfig}
			dnslog.Info("Started DoT DNS", "host", "0.0.0.0", "port", 853)
			err = serverTLS.ListenAndServe()
			defer serverTLS.Shutdown()
			if err != nil {
				dnslog.Error(err.Error())
			}
		}()
	}

	if c.BindDNSOverQuic {

		crt, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			dnslog.Error(err.Error())
		}
		tlsConfig := &tls.Config{}
		tlsConfig.Certificates = []tls.Certificate{crt}

		// Create the QUIC listener
		doqServer, err := doqserver.New(":8853", crt, "127.0.0.1:53", true)
		if err != nil {
			dnslog.Error(err.Error())
		}

		// Accept QUIC connections
		dnslog.Info("Starting QUIC listener on :8853")
		go doqServer.Listen()

	}
}
