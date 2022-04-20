package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	doqclient "github.com/natesales/doqd/pkg/client"
	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"
)

var routeDomainList [][]string

// checkSkipDomainList returns true if the domain exists in the domainList
func checkBypassDomainList(domainName string, domainList [][]string) bool {
	for _, item := range domainList {
		if len(item) == 2 {
			if item[1] == "suffix" {
				if strings.HasSuffix(domainName, item[0]) {
					return true
				}
			} else if item[1] == "fqdn" {
				if domainName == item[0] {
					return true
				}
			} else if item[1] == "prefix" {
				if strings.HasPrefix(domainName, item[0]) {
					return true
				}
			}
		}
	}
	return false
}

var DnsClient struct {
	Doq        doqclient.Client
	classicDns dns.Client
}

func loadDomainsToList(Filename string) [][]string {
	log.Info("Loading the domain from file/url to a list")
	var lines [][]string
	var scanner *bufio.Scanner
	if strings.HasPrefix(Filename, "http://") || strings.HasPrefix(Filename, "https://") {
		log.Info("domain list is a URL, trying to fetch")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
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
		lines = append(lines, strings.Split(lowerCaseLine, ","))
	}
	log.Infof("%s loaded with %d lines", Filename, len(lines))
	return lines
}

func performExternalQuery(question dns.Question, server string) (dns.Msg, error) {
	dnsUrl, err := url.Parse(server)
	if err != nil {
		log.Fatalf("Invalid upstream DNS URL: %s", server)
	}
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = question

	if dnsUrl.Scheme == "quic" {
		return DnsClient.Doq.SendQuery(*m1)

	}
	r, _, err := DnsClient.classicDns.Exchange(m1, dnsUrl.Host)
	return *r, err
}

func parseQuery(m *dns.Msg, ip string) {
	for _, q := range m.Question {

		if !checkBypassDomainList(q.Name, routeDomainList) && !c.AllDomains {
			log.Printf("Bypassing Traffic for %s\n", q.Name)
			in, err := performExternalQuery(q, c.UpstreamDNS)
			if err != nil {
				log.Println(err)
			}
			m.Answer = append(m.Answer, in.Answer...)

		} else {
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
			if err == nil {
				log.Printf("Routing Traffic for %s\n", q.Name)
				m.Answer = append(m.Answer, rr)
				return
			}
		}

	}

}
