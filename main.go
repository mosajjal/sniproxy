package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-collections/collections/tst"
	"github.com/mosajjal/dnsclient"
	"github.com/oschwald/maxminddb-golang"
	flag "github.com/spf13/pflag"

	"github.com/miekg/dns"
	slog "golang.org/x/exp/slog"
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

	GeoIPPath            string        `json:"geoipPath"`
	GeoIPRefreshInterval time.Duration `json:"geoipRefreshInterval"`
	GeoIPInclude         []string      `json:"geoipInclude"`
	GeoIPExclude         []string      `json:"geoipExculde"`

	mmdb *maxminddb.Reader

	dnsClient  dnsclient.Client
	sourceAddr net.IP

	reverseProxySNI  string
	reverseProxyAddr string
}

var c runConfig

var log = slog.New(slog.NewTextHandler(os.Stderr))

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
	pub, _ := getPublicIPInner()
	return pub
}

func getPublicIPInner() (string, error) {
	conn, _ := net.Dial("udp", "8.8.8.8:53")
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")
	ipaddr := localAddr[0:idx]
	if !net.ParseIP(ipaddr).IsPrivate() {
		return ipaddr, nil
	}
	externalIP := ""
	// trying to get the public IP from multiple sources to see if they match.
	resp, err := http.Get("https://myexternalip.com/raw")
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			externalIP = string(body)
		}

		// backup method of getting a public IP
		if externalIP == "" {
			// dig +short myip.opendns.com @208.67.222.222
			dnsRes, _, err := performExternalAQuery("myip.opendns.com.")
			if err != nil {
				return "", err
			}
			externalIP = dnsRes[0].(*dns.A).A.String()
		}

		if externalIP != "" {
			return externalIP, nil
		}
		log.Error("Could not automatically find the public IP address. Please specify it in the configuration.", nil)
	}
	return "", fmt.Errorf("Can't determine the public IP")

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

	// geoip helper to limit client countries
	flag.StringVar(&c.GeoIPPath, "geoipPath", "", "path to MMDB URL/path\nExample: https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb")
	flag.DurationVar(&c.GeoIPRefreshInterval, "geoipRefreshInterval", time.Hour, "MMDB refresh interval")
	flag.StringSliceVar(&c.GeoIPExclude, "geoipExclude", []string{""}, "Exclude countries to be allowed to connect. example: US,CA")
	flag.StringSliceVar(&c.GeoIPInclude, "geoipInclude", []string{""}, "Include countries to be allowed to connect. example: US,CA")

	flag.UintVar(&c.HTTPPort, "httpPort", 80, "HTTP Port to listen on. Should remain 80 in most cases")
	flag.UintVar(&c.HTTPSPort, "httpsPort", 443, "HTTPS Port to listen on. Should remain 443 in most cases")
	flag.UintVar(&c.DNSPort, "dnsPort", 53, "HTTP Port to listen on. Should remain 53 in most cases")

	flag.StringVar(&c.Interface, "interface", "", "Interface used for outbound TLS connections. uses OS prefered one if empty")

	config := flag.StringP("config", "c", "", "path to JSON configuration file")

	flag.Parse()
	if *config != "" {
		configFile, err := os.Open(*config)
		if err != nil {
			log.Error("failed to open config file", err)
		}
		defer configFile.Close()
		fileStat, _ := configFile.Stat()
		configBytes := make([]byte, fileStat.Size())
		_, err = configFile.Read(configBytes)
		if err != nil {
			log.Error("Could not read the config file", err)
		}

		err = json.Unmarshal(configBytes, &c)
		if err != nil {
			log.Error("failed to parse config file", err)
		}
	}

	if c.DomainListPath == "" {
		log.Warn("Domain list (--domainListPath) is not specified, routing ALL domains through the SNI proxy")
		c.AllDomains = true
	}
	if c.PublicIP != "" {
		log.Info("server info", "public_ip", c.PublicIP)
	} else {
		log.Error("Could not automatically determine public IP. you should provide it manually using --publicIP", nil)
	}

	// generate self-signed certificate if not provided
	if c.TLSCert == "" && c.TLSKey == "" {
		_, _, err := GenerateSelfSignedCertKey(c.PublicIP, nil, nil, os.TempDir())
		log.Info("Certificate was not provided, using a self signed cert")
		if err != nil {
			log.Error("Error while generating self-signed cert: ", err)
		}
		c.TLSCert = filepath.Join(os.TempDir(), c.PublicIP+".crt")
		c.TLSKey = filepath.Join(os.TempDir(), c.PublicIP+".key")
	}

	// parse reverseproxy and split it into url and sni
	if c.ReverseProxy != "" {
		log.Info("enablibng a reverse proxy")
		tmp := strings.Split(c.ReverseProxy, "::")
		c.reverseProxySNI, c.reverseProxyAddr = tmp[0], tmp[1]
		go runReverse()
	}

	// load mmdb if provided
	if c.GeoIPPath != "" {
		go initializeGeoIP()
		c.GeoIPExclude = toLowerSlice(c.GeoIPExclude)
		log.Info("GeoIP", "exclude", c.GeoIPExclude)
		c.GeoIPInclude = toLowerSlice(c.GeoIPInclude)
		log.Info("GeoIP", "include", c.GeoIPInclude)
	}

	// Finds source addr for outbound connections if interface is not empty
	if c.Interface != "" {
		log.Info("Using", "interface", c.Interface)
		ief, err := net.InterfaceByName(c.Interface)
		if err != nil {
			log.Error("", err)
		}
		addrs, err := ief.Addrs()
		if err != nil {
			log.Error("", err)
		}
		c.sourceAddr = net.ParseIP(addrs[0].String())

	}

	var err error
	c.dnsClient, err = dnsclient.New(c.UpstreamDNS, true)
	if err != nil {
		log.Error("", err)
	}
	defer c.dnsClient.Close()
	go runHTTP()
	go runHTTPS()
	go runDNS()

	// fetch domain list and refresh them periodically
	if !c.AllDomains {
		c.routePrefixes, c.routeSuffixes, c.routeFQDNs, _ = LoadDomainsCsv(c.DomainListPath)
		for range time.NewTicker(c.DomainListRefreshInterval.Duration).C {
			c.routePrefixes, c.routeSuffixes, c.routeFQDNs, _ = LoadDomainsCsv(c.DomainListPath)
		}
	} else {
		select {}
	}
}

func toLowerSlice(in []string) (out []string) {
	for _, v := range in {
		out = append(out, strings.ToLower(v))
	}
	return
}
