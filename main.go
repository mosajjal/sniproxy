package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

const maxLengthBytes = 5000

var bindIP = flag.String("bindIP", "0.0.0.0", "Bind to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0")
var upstreamDNS = flag.String("upstreamDNS", "1.1.1.1", "Upstream DNS IP")
var domainListPath = flag.String("domainListPath", "", "domain list path. eg: /tmp/domainlist.log")
var allDomains = flag.Bool("allDomains", false, "Do it for All Domains")
var publicIP = flag.String("publicIP", "", "Public IP of this server, reply address of DNS queries")

func handle80(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, 302)
}

func handle443(packet net.Conn) error {
	packetDataBytes := make([]byte, maxLengthBytes)
	packet.Read(packetDataBytes)
	sni, _ := GetHostname(packetDataBytes)
	dstipList, _ := net.LookupIP(sni)
	dstip := dstipList[0]
	target, err := net.Dial("tcp", dstip.String()+":443")
	if err != nil {
		log.Println("could not connect to target", err)
		packet.Close()
		return err
	}
	defer target.Close()
	go func() { io.Copy(target, packet) }()
	go func() { io.Copy(packet, target) }()
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
	l, err := net.Listen("tcp", ":443")
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
	timeticker := time.Tick(60 * time.Second)
	routeDomainList = loadDomainsToList(*domainListPath)
	for {
		select {
		case <-timeticker:
			routeDomainList = loadDomainsToList(*domainListPath)
		}
	}
}
