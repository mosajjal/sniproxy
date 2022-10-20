package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-collections/collections/tst"
	doqclient "github.com/mosajjal/doqd/pkg/client"
	"github.com/mosajjal/sniproxy/doh"
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

var dnsClient struct {
	Doq        doqclient.Client
	Doh        doh.Client
	classicDNS *dns.Client
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

func performExternalQuery(question dns.Question, server string) (*dns.Msg, time.Duration, error) {
	dnsURL, err := url.Parse(server)
	if err != nil {
		log.Fatalf("[DNS] Invalid upstream DNS URL: %s", server)
	}
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{question},
	}

	if dnsURL.Scheme == "quic" {
		rmsg, err := dnsClient.Doq.SendQuery(msg)
		return &rmsg, 0, err

	}
	if dnsURL.Scheme == "https" {
		rmsg, t, err := dnsClient.Doh.SendQuery(msg)
		return &rmsg, t, err

	}
	return dnsClient.classicDNS.Exchange(&msg, dnsURL.Host)
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
	resp, rtt, err := performExternalQuery(q, c.UpstreamDNS)
	if err != nil {
		return nil, err
	}

	log.Infof("[DNS] returned origin address for domain: %s, rtt: %s", q.Name, rtt)

	return resp.Answer, nil
}
