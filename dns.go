package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-collections/collections/tst"
	"github.com/mosajjal/dnsclient"
	doqserver "github.com/mosajjal/doqd/pkg/server"
	slog "golang.org/x/exp/slog"

	"github.com/miekg/dns"
)

type DNSClient struct {
	C dnsclient.Client
}

var (
	matchPrefix = uint8(1)
	matchSuffix = uint8(2)
	matchFQDN   = uint8(3)
)
var dnsLock sync.RWMutex

var dnslog = slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue("dns")}}))

// inDomainList returns true if the domain is meant to be SKIPPED and not go through sni proxy
func inDomainList(fqdn string) bool {
	fqdnLower := strings.ToLower(fqdn)
	// check for fqdn match
	if c.routeFQDNs[fqdnLower] == matchFQDN {
		return false
	}
	// check for prefix match
	if longestPrefix := c.routePrefixes.GetLongestPrefix(fqdnLower); longestPrefix != nil {
		// check if the longest prefix is present in the type hashtable as a prefix
		if c.routeFQDNs[longestPrefix.(string)] == matchPrefix {
			return false
		}
	}
	// check for suffix match. Note that suffix is just prefix reversed
	if longestSuffix := c.routeSuffixes.GetLongestPrefix(reverse(fqdnLower)); longestSuffix != nil {
		// check if the longest suffix is present in the type hashtable as a suffix
		if c.routeFQDNs[longestSuffix.(string)] == matchSuffix {
			return false
		}
	}
	return true
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// LoadDomainsCsv loads a domains Csv file/URL. returns 3 parameters:
// 1. a TST for all the prefixes (type 1)
// 2. a TST for all the suffixes (type 2)
// 3. a hashtable for all the full match fqdn (type 3)
func LoadDomainsCsv(Filename string) (*tst.TernarySearchTree, *tst.TernarySearchTree, map[string]uint8, error) {
	prefix := tst.New()
	suffix := tst.New()
	all := make(map[string]uint8)
	dnslog.Info("Loading the domain from file/url")
	var scanner *bufio.Scanner
	if strings.HasPrefix(Filename, "http://") || strings.HasPrefix(Filename, "https://") {
		dnslog.Info("domain list is a URL, trying to fetch")
		client := http.Client{
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				r.URL.Opaque = r.URL.Path
				return nil
			},
		}
		resp, err := client.Get(Filename)
		if err != nil {
			dnslog.Error("", err)
			return prefix, suffix, all, err
		}
		dnslog.Info("(re)fetching URL", "url", Filename)
		defer resp.Body.Close()
		scanner = bufio.NewScanner(resp.Body)

	} else {
		file, err := os.Open(Filename)
		if err != nil {
			return prefix, suffix, all, err
		}
		dnslog.Info("(re)loading File", "file", Filename)
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}

	for scanner.Scan() {
		lowerCaseLine := strings.ToLower(scanner.Text())
		// split the line by comma to understand thednslog.c
		fqdn := strings.Split(lowerCaseLine, ",")
		if len(fqdn) != 2 {
			dnslog.Info(lowerCaseLine + " is not a valid line, assuming FQDN")
			fqdn = []string{lowerCaseLine, "fqdn"}
		}
		// add the fqdn to the hashtable with its type
		switch entryType := fqdn[1]; entryType {
		case "prefix":
			all[fqdn[0]] = matchPrefix
			prefix.Insert(fqdn[0], fqdn[0])
		case "suffix":
			all[fqdn[0]] = matchSuffix
			// suffix match is much faster if we reverse the strings and match for prefix
			suffix.Insert(reverse(fqdn[0]), fqdn[0])
		case "fqdn":
			all[fqdn[0]] = matchFQDN
		default:
			//dnslog.Warnf("%s is not a valid line, assuming fqdn", lowerCaseLine)
			dnslog.Info(lowerCaseLine + " is not a valid line, assuming FQDN")
			all[fqdn[0]] = matchFQDN
		}
	}
	dnslog.Info(fmt.Sprintf("%s loaded with %d prefix, %d suffix and %d fqdn", Filename, prefix.Len(), suffix.Len(), len(all)-prefix.Len()-suffix.Len()))

	return prefix, suffix, all, nil
}

func (dnsc *DNSClient) performExternalAQuery(fqdn string) ([]dns.RR, time.Duration, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion(fqdn, dns.TypeA)
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

func processQuestion(q dns.Question) ([]dns.RR, error) {
	c.recievedDNS.Inc(1)
	if c.AllDomains || !inDomainList(q.Name) {
		// Return the public IP.
		c.proxiedDNS.Inc(1)
		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, c.PublicIP))
		if err != nil {
			return nil, err
		}

		dnslog.Info("returned sniproxy address for domain", "fqdn", q.Name)

		return []dns.RR{rr}, nil
	}

	// Otherwise do an upstream query and use that answer.
	resp, rtt, err := c.dnsClient.performExternalAQuery(q.Name)
	if err != nil {
		return nil, err
	}

	dnslog.Info("[DNS] returned origin address", "fqdn", q.Name, "rtt", rtt)

	return resp, nil
}

func (dnsc DNSClient) lookupDomain4(domain string) (net.IP, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	rAddrDNS, _, err := dnsc.performExternalAQuery(domain)
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
		answers, err := processQuestion(q)
		if err != nil {
			dnslog.Error("", err)
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
			dnslog.Error("Error starting UDP DNS server", err)
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
				dnslog.Error("", err)
				panic(2)

			}
			tlsConfig := &tls.Config{}
			tlsConfig.Certificates = []tls.Certificate{crt}

			serverTLS := &dns.Server{Addr: ":853", Net: "tcp-tls", TLSConfig: tlsConfig}
			dnslog.Info("Started DoT DNS", "host", "0.0.0.0", "port", 853)
			err = serverTLS.ListenAndServe()
			defer serverTLS.Shutdown()
			if err != nil {
				dnslog.Error("", err)
			}
		}()
	}

	if c.BindDNSOverQuic {

		crt, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			dnslog.Error("", err)
		}
		tlsConfig := &tls.Config{}
		tlsConfig.Certificates = []tls.Certificate{crt}

		// Create the QUIC listener
		doqServer, err := doqserver.New(":8853", crt, "127.0.0.1:53", true)
		if err != nil {
			dnslog.Error("", err)
		}

		// Accept QUIC connections
		dnslog.Info("Starting QUIC listener on :8853")
		go doqServer.Listen()

	}
}
