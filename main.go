package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-collections/collections/tst"
	"github.com/mosajjal/dnsclient"
	doqserver "github.com/mosajjal/doqd/pkg/server"
	flag "github.com/spf13/pflag"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type runConfig struct {
	BindIP                    string   `json:"bindIP"`
	PublicIP                  string   `json:"publicIP"`
	UpstreamDNS               string   `json:"upstreamDNS"`
	DomainListPath            string   `json:"domainListPath"`
	DomainListRefreshInterval duration `json:"domainListRefreshInterval"`
	BindDNSOverTCP            bool     `json:"bindDnsOverTcp"`
	BindDNSOverTLS            bool     `json:"bindDnsOverTls"`
	BindDNSOverQuic           bool     `json:"bindDnsOverQuic"`
	AllDomains                bool     `json:"allDomains"`
	TLSCert                   string   `json:"tlsCert"`
	TLSKey                    string   `json:"tlsKey"`
	ReverseProxy              string   `json:"reverseProxy"`
	ReverseProxyCert          string   `json:"reverseProxyCert"`
	ReverseProxyKey           string   `json:"reverseProxyKey"`
	HTTPPort                  uint     `json:"httpPort"`
	HTTPSPort                 uint     `json:"httpsPort"`
	DNSPort                   uint     `json:"dnsPort"`
	Interface                 string   `json:"interface"`

	routePrefixes *tst.TernarySearchTree
	routeSuffixes *tst.TernarySearchTree
	routeFQDNs    map[string]uint8

	dnsClient  dnsclient.Client
	sourceAddr net.IP

	reverseProxySNI  string
	reverseProxyAddr string
}

var c runConfig

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

func getPublicIP() string {
	conn, _ := net.Dial("udp", "8.8.8.8:53")
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")
	ipaddr := localAddr[0:idx]
	if !net.ParseIP(ipaddr).IsPrivate() {
		return ipaddr
	}
	externalIP := ""
	// trying to get the public IP from multiple sources to see if they match.
	resp, err := http.Get("https://myexternalip.com/raw")
	if err == nil {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			externalIP = string(body)
		}

		// backup method of getting a public IP
		if externalIP == "" {
			// dig +short myip.opendns.com @208.67.222.222
			dnsRes, _, err := performExternalAQuery("myip.opendns.com.")
			if err != nil {
				return err.Error()
			}
			externalIP = dnsRes[0].(*dns.A).A.String()
		}

		if externalIP != "" {
			return externalIP
		}
		log.Fatalf("Could not automatically find the public IP address. Please specify it in the configuration.")

	}
	return ""

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

// handle HTTPS connections coming to the reverse proxy. this will get a connction from the handle443 function
// need to grab the HTTP request from this, and pass it on to the HTTP handler.
func handleReverse(conn net.Conn) error {
	log.Infof("[Reverse] connecting to HTTP")
	// send the reverse conn to local HTTP listner
	srcAddr := net.TCPAddr{
		IP:   c.sourceAddr,
		Port: 0,
	}
	target, err := net.DialTCP("tcp", &srcAddr, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(c.HTTPPort)})
	if err != nil {
		return err
	}
	pipe(conn, target)
	return nil
}

func handle443(conn net.Conn) error {
	defer conn.Close()
	incoming := make([]byte, 2048)
	n, err := conn.Read(incoming)
	if err != nil {
		log.Errorln(err)
		return err
	}
	sni, err := GetHostname(incoming)
	if err != nil {
		log.Errorln(err)
		return err
	}
	// check SNI against domainlist for an extra layer of security
	if !c.AllDomains && inDomainList(sni+".") {
		log.Warnf("[TCP] a client requested connection to %s, but it's not allowed as per configuration.. resetting TCP", sni)
		conn.Close()
		return nil
	}
	rAddr, err := lookupDomain4(sni)
	rPort := 443
	if err != nil || rAddr == nil {
		log.Warnln(err)
		return err
	}
	// TODO: handle timeout and context here
	if rAddr.IsLoopback() || rAddr.IsPrivate() || rAddr.Equal(net.IPv4(0, 0, 0, 0)) {
		log.Infoln("[TLS] connection to private IP ignored")
		return nil
	}
	// TODO: if SNI is the reverse proxy, this request needs to be handled by a HTTPS handler
	if sni == c.reverseProxySNI {
		rAddr = net.IPv4(127, 0, 0, 1)
		rPort = 65000
	}
	log.Infof("[TLS] connecting to %s (%s)", rAddr, sni)
	// TODO: with the manipulation of the soruce address, we can set the outbound interface
	srcAddr := net.TCPAddr{
		IP:   c.sourceAddr,
		Port: 0,
	}
	target, err := net.DialTCP("tcp", &srcAddr, &net.TCPAddr{IP: rAddr, Port: rPort})
	if err != nil {
		log.Errorln("could not connect to target", err)
		conn.Close()
		return err
	}
	defer target.Close()
	target.Write(incoming[:n])
	pipe(conn, target)
	return nil
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

func runReverse() {
	// reverse https can't run on 443. we'll pick a random port and pipe the 443 traffic back to it.
	cert, err := tls.LoadX509KeyPair(c.ReverseProxyCert, c.ReverseProxyKey)
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	listener, err := tls.Listen("tcp", ":65000", &config)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		go handleReverse(conn)
	}
}

func runHTTPS() {

	l, err := net.Listen("tcp", c.BindIP+fmt.Sprintf(":%d", c.HTTPSPort))
	if err != nil {
		log.Fatalln(err)
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatalln(err)
		}
		go func() {
			go handle443(c)
			//TODO: there's a better way to handle TCP timeouts than just a blanket 30 seconds rule
			// c.Close()
		}()
	}
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

func main() {
	flag.StringVar(&c.BindIP, "bindIP", "0.0.0.0", "Bind 443 and 80 to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0")
	flag.StringVar(&c.UpstreamDNS, "upstreamDNS", "udp://8.8.8.8:53", "Upstream DNS URI. examples: udp://1.1.1.1:53, tcp://1.1.1.1:53, tcp-tls://1.1.1.1:853, https://dns.google/dns-query")
	flag.StringVar(&c.DomainListPath, "domainListPath", "", "Path to the domain list. eg: /tmp/domainlist.csv")
	flag.DurationVar(&c.DomainListRefreshInterval.Duration, "domainListRefreshInterval", 60*time.Minute, "Interval to re-fetch the domain list")
	flag.BoolVar(&c.AllDomains, "allDomains", false, "Route all HTTP(s) traffic through the SNI proxy")
	flag.StringVar(&c.PublicIP, "publicIP", getPublicIP(), "Public IP of the server, reply address of DNS queries")
	flag.BoolVar(&c.BindDNSOverTCP, "bindDnsOverTcp", false, "enable DNS over TCP as well as UDP")
	flag.BoolVar(&c.BindDNSOverTLS, "bindDnsOverTls", false, "enable DNS over TLS as well as UDP")
	flag.BoolVar(&c.BindDNSOverQuic, "bindDnsOverQuic", false, "enable DNS over QUIC as well as UDP")
	flag.StringVar(&c.TLSCert, "tlsCert", "", "Path to the certificate for DoH, DoT and DoQ. eg: /tmp/mycert.pem")
	flag.StringVar(&c.TLSKey, "tlsKey", "", "Path to the certificate key for DoH, DoT and DoQ. eg: /tmp/mycert.key")

	// set an domain to be redirected to a real webserver. essentially adding a simple reverse proxy to sniproxy
	flag.StringVar(&c.ReverseProxy, "reverseProxy", "", "SNI and upstream URL. example: www.example.com::http://127.0.0.1:4001")
	flag.StringVar(&c.ReverseProxyCert, "reverseProxyCert", "", "Path to the certificate for reverse proxy. eg: /tmp/mycert.pem")
	flag.StringVar(&c.ReverseProxyKey, "reverseProxyKey", "", "Path to the certificate key for reverse proxy. eg: /tmp/mycert.key")

	flag.UintVar(&c.HTTPPort, "httpPort", 80, "HTTP Port to listen on. Should remain 80 in most cases")
	flag.UintVar(&c.HTTPSPort, "httpsPort", 443, "HTTPS Port to listen on. Should remain 443 in most cases")
	flag.UintVar(&c.DNSPort, "dnsPort", 53, "HTTP Port to listen on. Should remain 53 in most cases")

	flag.StringVar(&c.Interface, "interface", "", "Interface used for outbound TLS connections. uses OS prefered one if empty")

	config := flag.StringP("config", "c", "", "path to JSON configuration file")

	flag.Parse()
	if *config != "" {
		configFile, err := os.Open(*config)
		if err != nil {
			log.Fatalf("failed to open config file: %s", err.Error())
		}
		defer configFile.Close()
		fileStat, _ := configFile.Stat()
		configBytes := make([]byte, fileStat.Size())
		_, err = configFile.Read(configBytes)
		if err != nil {
			log.Fatalf("Could not read the config file: %s", err)
		}

		err = json.Unmarshal(configBytes, &c)
		if err != nil {
			log.Fatalf("failed to parse config file: %s", err.Error())
		}
	}

	if c.DomainListPath == "" {
		log.Warnf("Domain list (--domainListPath) is not specified, routing ALL domains through the SNI proxy")
		c.AllDomains = true
	}
	if c.PublicIP != "" {
		log.Infof("Using Public IP: %s", c.PublicIP)
	} else {
		log.Fatalf("Could not automatically determine public IP. you should provide it manually using --publicIP")
	}

	// generate self-signed certificate if not provided
	if c.TLSCert == "" && c.TLSKey == "" {
		_, _, err := GenerateSelfSignedCertKey(c.PublicIP, nil, nil, os.TempDir())
		log.Infof("Certificate was not provided, using a self signed cert")
		if err != nil {
			log.Fatal("fatal Error: ", err)
		}
		c.TLSCert = filepath.Join(os.TempDir(), c.PublicIP+".crt")
		c.TLSKey = filepath.Join(os.TempDir(), c.PublicIP+".key")
	}

	// parse reverseproxy and split it into url and sni
	if c.ReverseProxy != "" {
		log.Infof("enablibng a reverse proxy")
		tmp := strings.Split(c.ReverseProxy, "::")
		c.reverseProxySNI, c.reverseProxyAddr = tmp[0], tmp[1]
		go runReverse()
	}

	// Finds source addr for outbound connections if interface is not empty
	if c.Interface != "" {
		log.Infof("Using interface %s", c.Interface)
		ief, err := net.InterfaceByName(c.Interface)
		if err != nil {
			log.Fatal(err)
		}
		addrs, err := ief.Addrs()
		if err != nil {
			log.Fatal(err)
		}
		c.sourceAddr = net.ParseIP(addrs[0].String())

	}

	var err error
	c.dnsClient, err = dnsclient.New(c.UpstreamDNS, true)
	if err != nil {
		log.Fatalln(err)
	}
	defer c.dnsClient.Close()
	go runHTTP()
	go runHTTPS()
	go runDNS()

	// fetch domain list and refresh them periodically
	if !c.AllDomains {
		c.routePrefixes, c.routeSuffixes, c.routeFQDNs = LoadDomainsCsv(c.DomainListPath)
		for range time.NewTicker(c.DomainListRefreshInterval.Duration).C {
			c.routePrefixes, c.routeSuffixes, c.routeFQDNs = LoadDomainsCsv(c.DomainListPath)
		}
	} else {
		select {}
	}
}
