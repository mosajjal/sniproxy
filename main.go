package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"io/ioutil"
	"strings"
	"time"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)


var bindIP                     = "0.0.0.0"          //"Bind 443 and 80 to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0"
var bindDnsOverTcp             = true               //"enable DNS over TCP as well as UDP"
var bindDnsOverTls             = false              //"enable DNS over TLS as well as UDP"
var allDomains bool            = false              //"Route all HTTP(s) traffic through the SNI proxy"
var upstreamDNS                = "udp://1.1.1.1:53" //"Upstream DNS URI. examples: udp://1.1.1.1:53, tcp://1.1.1.1:53, tcp-tls://1.1.1.1:853"
var domainListRefreshInterval  = 60                 //"Interval to re-fetch the domain list"
var publicIP                   = ""                 //"Public IP of the server, reply address of DNS queries"
var config_dir                 = "/usr/local/sniproxy/"
var domainListPath             = config_dir+"domains.list"

var c                          = flag.String("c", config_dir+"config.json", "sniproxy default profile path")
var config                     = flag.String("config", config_dir+"config.json", "sniproxy default profile path")

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
	rAddrDns, err := performExternalQuery(dns.Question{Name: domain, Qtype: dns.TypeA, Qclass: dns.ClassINET}, upstreamDNS)
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
	// rAddrDns, err := performExternalQuery(dns.Question{Name: sni + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET}, upstreamDNS)
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
		parseQuery(m, publicIP)
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
	l, err := net.Listen("tcp", bindIP+":443")
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
	// start DNS UDP serverUdp
	go func() {
		serverUdp := &dns.Server{Addr: ":53", Net: "udp"}
		log.Printf("Started UDP DNS on %s:%d -- listening", "0.0.0.0", 53)
		err := serverUdp.ListenAndServe()
		defer serverUdp.Shutdown()
		if err != nil {
			log.Fatalf("Failed to start server: %s\n ", err.Error())
		}
	}()

	// start DNS UDP serverTcp
	if bindDnsOverTcp {
		go func() {
			serverTcp := &dns.Server{Addr: ":53", Net: "tcp"}
			log.Printf("Started TCP DNS on %s:%d -- listening", "0.0.0.0", 53)
			err := serverTcp.ListenAndServe()
			defer serverTcp.Shutdown()
			if err != nil {
				log.Fatalf("Failed to start server: %s\n ", err.Error())
			}
		}()
	}

	// start DNS UDP serverTls
	if bindDnsOverTls {
		go func() {
			_, _, err := GenerateSelfSignedCertKey(publicIP, nil, nil, config_dir)
			if err != nil {
				log.Fatal("fatal Error: ", err)
			}
			crt, err := tls.LoadX509KeyPair(config_dir+publicIP+".crt", config_dir+publicIP+".key")
			if err != nil {
				log.Fatalln(err.Error())
			}
			tlsConfig := &tls.Config{}
			tlsConfig.Certificates = []tls.Certificate{crt}

			serverTls := &dns.Server{Addr: ":853", Net: "tcp-tls", TLSConfig: tlsConfig}
			log.Printf("Started DoT on %s:%d -- listening", "0.0.0.0", 853)
			err = serverTls.ListenAndServe()
			defer serverTls.Shutdown()
			if err != nil {
				log.Fatalf("Failed to start server: %s\n ", err.Error())
			}
		}()
	}
}

func get_publicIP() string{
	conn, err := net.Dial("udp", "google.com:80")
	if err != nil {
		return err.Error()
	}
	defer conn.Close()
	var my_ip = strings.Split(conn.LocalAddr().String(), ":")[0]
	return my_ip
}

func get_publicIP2() string{
	resp, err := http.Get("https://myexternalip.com/raw")
	if err != nil {
		return err.Error()
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err.Error()
	}
	content := string(body)
	defer resp.Body.Close()
	return content
}

func main() {
	flag.Parse()

	_, err := os.Stat(config_dir)
	if err != nil {
		err := os.Mkdir(config_dir, os.ModePerm)
		if err != nil {
			log.Fatalf("mkdir %s failed: %s\n ", config_dir, err.Error())
		}
	}

	var path = *config
	if *c != "" {
		path = *c
	}else if *config != "" {
		path = *config
	}

	_, err = os.Lstat(path)
	if !os.IsNotExist(err) {
		var conf = koanf.New(".")
		if err := conf.Load(file.Provider(path), json.Parser()); err != nil {
			log.Fatalf("error loading config: %s", err.Error())
		}
		if conf.Bool("allDomains") {
			allDomains = conf.Bool("allDomains")
		}
		if conf.Bool("bindDnsOverTcp") {
			bindDnsOverTcp = conf.Bool("bindDnsOverTcp")
		}
		if conf.Bool("bindDnsOverTls") {
			bindDnsOverTls = conf.Bool("bindDnsOverTls")
		}
		if conf.String(".bindIP") != "" {
			bindIP = conf.String(".bindIP")
		}
		if conf.String("domainListPath") != "" {
			domainListPath = conf.String("domainListPath")
		}
		if conf.Int("domainListRefreshInterval") != 0 {
			domainListRefreshInterval = conf.Int("domainListRefreshInterval")
		}
		if conf.String("publicIP") != "" {
			publicIP = conf.String("publicIP")
		}else{
			publicIP = get_publicIP()
		}
		if publicIP == "" {
			publicIP = get_publicIP2()
		}
		if conf.String("upstreamDNS") != "" {
			upstreamDNS = conf.String("upstreamDNS")
		}
	}else{
		publicIP = get_publicIP()
		if publicIP == "" {
			publicIP = get_publicIP2()
		}
	}

	go runHttp()
	go runHttps()
	go runDns()

	// fetch domain list and refresh them periodically
	routeDomainList = loadDomainsToList(domainListPath)
	for range time.NewTicker(time.Duration(domainListRefreshInterval)*time.Second).C {
		routeDomainList = loadDomainsToList(domainListPath)
	}

}
