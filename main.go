package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var bindIP = flag.String("bindIP", "0.0.0.0", "Bind to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0")
var upstreamDNS = flag.String("upstreamDNS", "1.1.1.1", "Upstream DNS IP")
var domainListPath = flag.String("domainListPath", "", "domain list path. eg: /tmp/domainlist.log")
var domainListRefreshInterval = flag.Duration("domainListRefreshInterval", 60*time.Second, "Interval to re-fetch the domain list")
var allDomains = flag.Bool("allDomains", false, "Do it for All Domains")
var publicIP = flag.String("publicIP", "", "Public IP of this server, reply address of DNS queries")

func handle80(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusFound)
}

func pipe(conn1 net.Conn, conn2 net.Conn) {
	chan1 := getChannel(conn1)
	chan2 := getChannel(conn2)
	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				return
			}
			conn2.Write(b1)
		case b2 := <-chan2:
			if b2 == nil {
				return
			}
			conn1.Write(b2)
		}
	}
}

func getChannel(conn net.Conn) chan []byte {
	c := make(chan []byte)
	go func() {
		b := make([]byte, 1024)
		for {
			n, err := conn.Read(b)
			if n > 0 {
				res := make([]byte, n)
				copy(res, b[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				break
			}
		}
	}()
	return c
}

func lookupDomain4(domain string) (net.IP, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	rAddrDns, err := performExternalQuery(dns.Question{Name: domain, Qtype: dns.TypeA, Qclass: dns.ClassINET}, *upstreamDNS)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if rAddrDns.Answer[0].Header().Rrtype == dns.TypeCNAME {
		return lookupDomain4(rAddrDns.Answer[0].(*dns.CNAME).Target)
	}
	if rAddrDns.Answer[0].Header().Rrtype == dns.TypeA {
		return rAddrDns.Answer[0].(*dns.A).A, nil
	}
	return nil, fmt.Errorf("Unknown type")
}

func handle443(conn net.Conn) error {

	incoming := make([]byte, 2048)
	n, err := conn.Read(incoming)
	if err != nil {
		log.Println(err)
		return err
	}
	sni, err := GetHostname(incoming)
	if err != nil {
		log.Println(err)
		return err
	}
	// rAddrDns, err := performExternalQuery(dns.Question{Name: sni + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET}, *upstreamDNS)
	// if err != nil {
	// 	log.Println(err)
	// 	return err
	// }
	// rAddr := rAddrDns.Answer[0].(*dns.A).A
	rAddr, err := lookupDomain4(sni)
	if err != nil {
		log.Println(err)
		return err
	}
	target, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: rAddr, Port: 443})
	if err != nil {
		log.Println("could not connect to target", err)
		conn.Close()
		return err
	}
	defer target.Close()

	target.Write(incoming[:n])

	pipe(conn, target)
	return nil
}

func handle53(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m, *publicIP)
	}

	w.WriteMsg(m)
}

func handleError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func runHttp() {
	http.HandleFunc("/", handle80)

	server := http.Server{
		Addr: ":80",
	}
	server.ListenAndServe()
}

func runHttps() {
	l, err := net.Listen("tcp", *bindIP+":443")
	handleError(err)
	defer l.Close()
	for {
		conn, err := l.Accept()
		handleError(err)
		go handle443(conn)
	}
}

func runDns() {

	dns.HandleFunc(".", handle53)

	// start server
	server := &dns.Server{Addr: ":53", Net: "udp"}
	log.Printf("Started DNS on %s:%d -- listening", "0.0.0.0", 53)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func main() {

	flag.Parse()
	if *domainListPath == "" || *publicIP == "" || *upstreamDNS == "" {
		log.Fatalln("-domainListPath and -publicIP must be set. exitting...")
	}
	go runHttp()
	go runHttps()
	go runDns()

	// fetch domain list and refresh them periodically
	routeDomainList = loadDomainsToList(*domainListPath)
	for range time.NewTicker(*domainListRefreshInterval).C {
		routeDomainList = loadDomainsToList(*domainListPath)
	}

}
