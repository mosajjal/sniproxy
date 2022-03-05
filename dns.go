package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

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

func loadDomainsToList(Filename string) [][]string {
	file, err := os.Open(Filename)
	handleError(err)
	log.Println("(re)loading File: ", Filename)
	defer file.Close()

	var lines [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, strings.Split(scanner.Text(), ","))
	}
	return lines
}

func performExternalQuery(question dns.Question, server string) (*dns.Msg, error) {
	c := new(dns.Client)
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = question

	in, _, err := c.Exchange(m1, fmt.Sprintf("%s:53", server))
	return in, err
}

func parseQuery(m *dns.Msg, ip string) {
	for _, q := range m.Question {

		if !checkBypassDomainList(q.Name, routeDomainList) && !*allDomains {
			log.Printf("Bypassing Traffic for %s\n", q.Name)
			in, err := performExternalQuery(q, *upstreamDNS)
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
