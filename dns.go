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
	"time"

	"github.com/golang-collections/collections/tst"
	"github.com/mosajjal/dnsclient"
	doqserver "github.com/mosajjal/doqd/pkg/server"
	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"
)

var (
	matchPrefix = uint8(1)
	matchSuffix = uint8(2)
	matchFQDN   = uint8(3)
)

// inDomainList returns true if the domain is meant to be SKIPPED and not go through sni proxy
// todo: this needs to be replaced by a few tst
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
func LoadDomainsCsv(Filename string) (prefix *tst.TernarySearchTree, suffix *tst.TernarySearchTree, all map[string]uint8) {
	prefix = tst.New()
	suffix = tst.New()
	all = make(map[string]uint8)
	log.Info("Loading the domain from file/url")
	var scanner *bufio.Scanner
	if strings.HasPrefix(Filename, "http://") || strings.HasPrefix(Filename, "https://") {
		log.Info("domain list is a URL, trying to fetch")
		client := http.Client{
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				r.URL.Opaque = r.URL.Path
				return nil
			},
		}
		resp, err := client.Get(Filename)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("(re)fetching URL: ", Filename)
		defer resp.Body.Close()
		scanner = bufio.NewScanner(resp.Body)

	} else {
		file, err := os.Open(Filename)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("(re)loading File: ", Filename)
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}

	for scanner.Scan() {
		lowerCaseLine := strings.ToLower(scanner.Text())
		// split the line by comma to understand the logic
		fqdn := strings.Split(lowerCaseLine, ",")
		if len(fqdn) != 2 {
			log.Warnf("%s is not a valid line, assuming fqdn", lowerCaseLine)
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
			log.Warnf("%s is not a valid line, assuming fqdn", lowerCaseLine)
			all[fqdn[0]] = matchFQDN
		}
	}
	log.Infof("%s loaded with %d prefix, %d suffix and %d fqdn", Filename, prefix.Len(), suffix.Len(), len(all)-prefix.Len()-suffix.Len())
	return prefix, suffix, all
}

func performExternalAQuery(fqdn string) ([]dns.RR, time.Duration, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion(fqdn, dns.TypeA)
	msg.SetEdns0(1232, true)
	//TODO: context and timeout here
	res, trr, err := c.dnsClient.Query(context.Background(), &msg)
	if err != nil {
		if err.Error() == "EOF" {
			log.Infof("[DNS] reconnecting DNS...") //TODO: don't like logging here
			c.dnsClient.Close()
			c.dnsClient, err = dnsclient.New(c.UpstreamDNS, true)
		}
	}
	return res, trr, err
}

func processQuestion(q dns.Question) ([]dns.RR, error) {
	if c.AllDomains || !inDomainList(q.Name) {
		// Return the public IP.
		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, c.PublicIP))
		if err != nil {
			return nil, err
		}

		log.Infof("[DNS] returned sniproxy address for domain: %s", q.Name)

		return []dns.RR{rr}, nil
	}

	// Otherwise do an upstream query and use that answer.
	resp, rtt, err := performExternalAQuery(q.Name)
	if err != nil {
		return nil, err
	}

	log.Infof("[DNS] returned origin address for domain: %s, rtt: %s", q.Name, rtt)

	return resp, nil
}

func lookupDomain4(domain string) (net.IP, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	rAddrDNS, _, err := performExternalAQuery(domain)
	// if err != nil {
	// 	return nil, err
	// }
	if len(rAddrDNS) > 0 {
		if rAddrDNS[0].Header().Rrtype == dns.TypeCNAME {
			return lookupDomain4(rAddrDNS[0].(*dns.CNAME).Target)
		}
		if rAddrDNS[0].Header().Rrtype == dns.TypeA {
			return rAddrDNS[0].(*dns.A).A, nil
		}
	} else {
		return nil, fmt.Errorf("[DNS] Empty DNS response for %s with error %s", domain, err)
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
			log.Error(err)
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
		log.Infof("Started UDP DNS on %s:%d -- listening", "0.0.0.0", c.DNSPort)
		err := serverUDP.ListenAndServe()
		defer serverUDP.Shutdown()
		if err != nil {
			log.Fatalf("Failed to start server: %s\nYou can run the following command to pinpoint which process is listening on port %d\nsudo ss -pltun -at '( dport = :%d or sport = :%d )'", err.Error(), c.DNSPort, c.DNSPort, c.DNSPort)
		}
	}()

	// start DNS UDP serverTcp
	if c.BindDNSOverTCP {
		go func() {
			serverTCP := &dns.Server{Addr: fmt.Sprintf(":%d", c.DNSPort), Net: "tcp"}
			log.Infof("Started TCP DNS on %s:%d -- listening", "0.0.0.0", c.DNSPort)
			err := serverTCP.ListenAndServe()
			defer serverTCP.Shutdown()
			if err != nil {
				log.Fatalf("Failed to start server: %s\nYou can run the following command to pinpoint which process is listening on port %d\nsudo ss -pltun -at '( dport = :%d or sport = :%d )'", err.Error(), c.DNSPort, c.DNSPort, c.DNSPort)
			}
		}()
	}

	// start DNS UDP serverTls
	if c.BindDNSOverTLS {
		go func() {
			crt, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
			if err != nil {
				log.Fatalln(err.Error())
			}
			tlsConfig := &tls.Config{}
			tlsConfig.Certificates = []tls.Certificate{crt}

			serverTLS := &dns.Server{Addr: ":853", Net: "tcp-tls", TLSConfig: tlsConfig}
			log.Infof("Started DoT on %s:%d -- listening", "0.0.0.0", 853)
			err = serverTLS.ListenAndServe()
			defer serverTLS.Shutdown()
			if err != nil {
				log.Fatalf("Failed to start server: %s\n ", err.Error())
			}
		}()
	}

	if c.BindDNSOverQuic {

		crt, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			log.Fatalln(err.Error())
		}
		tlsConfig := &tls.Config{}
		tlsConfig.Certificates = []tls.Certificate{crt}

		// Create the QUIC listener
		doqServer, err := doqserver.New(":8853", crt, "127.0.0.1:53", true)
		if err != nil {
			log.Fatalln(err.Error())
		}

		// Accept QUIC connections
		log.Infof("Starting QUIC listener on %s\n", ":8853")
		go doqServer.Listen()

	}
}
