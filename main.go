package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	prometheusmetrics "github.com/deathowl/go-metrics-prometheus"
	"github.com/golang-collections/collections/tst"
	"github.com/mosajjal/dnsclient"
	"github.com/oschwald/maxminddb-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rcrowley/go-metrics"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/miekg/dns"
	slog "golang.org/x/exp/slog"
	"golang.org/x/net/proxy"
)

type runConfig struct {
	BindIP                    string   `json:"bindIP"`
	PublicIP                  string   `json:"publicIP"`
	UpstreamDNS               string   `json:"upstreamDNS"`
	UpstreamSOCKS5            string   `json:"upstreamSOCKS5"`
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
	Prometheus                string   `json:"prometheus"`

	routePrefixes *tst.TernarySearchTree
	routeSuffixes *tst.TernarySearchTree
	routeFQDNs    map[string]uint8

	GeoIPPath            string        `json:"geoipPath"`
	GeoIPRefreshInterval time.Duration `json:"geoipRefreshInterval"`
	GeoIPInclude         []string      `json:"geoipInclude"`
	GeoIPExclude         []string      `json:"geoipExculde"`

	mmdb *maxminddb.Reader

	dnsClient  DNSClient
	dialer     proxy.Dialer
	sourceAddr net.IP

	reverseProxySNI  string
	reverseProxyAddr string

	// metrics
	recievedHTTP  metrics.Counter
	proxiedHTTP   metrics.Counter
	recievedHTTPS metrics.Counter
	proxiedHTTPS  metrics.Counter
	recievedDNS   metrics.Counter
	proxiedDNS    metrics.Counter
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
			dnsRes, _, err := c.dnsClient.performExternalAQuery("myip.opendns.com.")
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
	return "", nil

}

func main() {

	cmd := &cobra.Command{
		Use:   "sniproxy",
		Short: "SNI Proxy with Embedded DNS Server",
		Run: func(command *cobra.Command, args []string) {

		},
	}
	flags := cmd.Flags()
	flags.StringVar(&c.BindIP, "bindIP", "0.0.0.0", "Bind 443 and 80 to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0")
	flags.StringVar(&c.UpstreamDNS, "upstreamDNS", "udp://8.8.8.8:53", "Upstream DNS URI. examples: udp://1.1.1.1:53, tcp://1.1.1.1:53, tcp-tls://1.1.1.1:853, https://dns.google/dns-query")
	flags.StringVar(&c.UpstreamSOCKS5, "upstreamSOCKS5", "", "Use a SOCKS proxy for upstream HTTP/HTTPS traffic. Example: socks5://admin:admin@127.0.0.1:1080")
	flags.StringVar(&c.DomainListPath, "domainListPath", "", "Path to the domain list. eg: /tmp/domainlist.csv. Look at the example file for the format. ")
	flags.DurationVar(&c.DomainListRefreshInterval.Duration, "domainListRefreshInterval", 60*time.Minute, "Interval to re-fetch the domain list")
	flags.BoolVar(&c.AllDomains, "allDomains", false, "Route all HTTP(s) traffic through the SNI proxy")
	flags.StringVar(&c.PublicIP, "publicIP", getPublicIP(), "Public IP of the server, reply address of DNS queries")
	flags.BoolVar(&c.BindDNSOverTCP, "bindDnsOverTcp", false, "enable DNS over TCP as well as UDP")
	flags.BoolVar(&c.BindDNSOverTLS, "bindDnsOverTls", false, "enable DNS over TLS as well as UDP")
	flags.BoolVar(&c.BindDNSOverQuic, "bindDnsOverQuic", false, "enable DNS over QUIC as well as UDP")
	flags.StringVar(&c.TLSCert, "tlsCert", "", "Path to the certificate for DoH, DoT and DoQ. eg: /tmp/mycert.pem")
	flags.StringVar(&c.TLSKey, "tlsKey", "", "Path to the certificate key for DoH, DoT and DoQ. eg: /tmp/mycert.key")

	// set an domain to be redirected to a real webserver. essentially adding a simple reverse proxy to sniproxy
	flags.StringVar(&c.ReverseProxy, "reverseProxy", "", "enable reverse proxy for a specific FQDN and upstream URL. example: www.example.com::http://127.0.0.1:4001")
	flags.StringVar(&c.ReverseProxyCert, "reverseProxyCert", "", "Path to the certificate for reverse proxy. eg: /tmp/mycert.pem")
	flags.StringVar(&c.ReverseProxyKey, "reverseProxyKey", "", "Path to the certificate key for reverse proxy. eg: /tmp/mycert.key")

	// geoip helper to limit client countries
	flags.StringVar(&c.GeoIPPath, "geoipPath", "", "path to MMDB URL/path\nExample: https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb")
	flags.DurationVar(&c.GeoIPRefreshInterval, "geoipRefreshInterval", time.Hour, "MMDB refresh interval")
	flags.StringSliceVar(&c.GeoIPExclude, "geoipExclude", []string{""}, "Exclude countries to be allowed to connect. example: US,CA")
	flags.StringSliceVar(&c.GeoIPInclude, "geoipInclude", []string{""}, "Include countries to be allowed to connect. example: US,CA")

	flags.UintVar(&c.HTTPPort, "httpPort", 80, "HTTP Port to listen on. Should remain 80 in most cases")
	flags.UintVar(&c.HTTPSPort, "httpsPort", 443, "HTTPS Port to listen on. Should remain 443 in most cases")
	flags.UintVar(&c.DNSPort, "dnsPort", 53, "DNS Port to listen on. Should remain 53 in most cases")

	flags.StringVar(&c.Interface, "interface", "", "Interface used for outbound TLS connections. uses OS prefered one if empty")

	flags.StringVar(&c.Prometheus, "prometheus", "", "Enable prometheus endpoint on IP:PORT. example: 127.0.0.1:8080. Always exposes /metrics and only supports HTTP")

	config := flags.StringP("config", "c", "", "path to JSON configuration file")
	if err := cmd.Execute(); err != nil {
		log.Error("failed to execute command", err)
		return
	}
	if flags.Changed("help") {
		return
	}

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

	// set up metrics
	c.recievedDNS = metrics.GetOrRegisterCounter("dns.requests.recieved", metrics.DefaultRegistry)
	c.proxiedDNS = metrics.GetOrRegisterCounter("dns.requests.proxied", metrics.DefaultRegistry)
	c.recievedHTTP = metrics.GetOrRegisterCounter("http.requests.recieved", metrics.DefaultRegistry)
	c.proxiedHTTP = metrics.GetOrRegisterCounter("http.requests.proxied", metrics.DefaultRegistry)
	c.recievedHTTPS = metrics.GetOrRegisterCounter("https.requests.recieved", metrics.DefaultRegistry)
	c.proxiedHTTPS = metrics.GetOrRegisterCounter("https.requests.proxied", metrics.DefaultRegistry)

	if c.Prometheus != "" {
		p := prometheusmetrics.NewPrometheusProvider(metrics.DefaultRegistry, "sniproxy", c.PublicIP, prometheus.DefaultRegisterer, 1*time.Second)
		go p.UpdatePrometheusMetrics()
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			log.Info("starting metrics server",
				"address", c.Prometheus,
			)
			if err := http.ListenAndServe(c.Prometheus, promhttp.Handler()); err != nil {
				log.Error("", err)
			}
		}()
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

	if c.UpstreamSOCKS5 != "" {
		uri, err := url.Parse(c.UpstreamSOCKS5)
		if err != nil {
			log.Error("", err)
		}
		if uri.Scheme != "socks5" {
			log.Error("only SOCKS5 is supported", nil)
			return
		}

		log.Info("Using an upstream SOCKS5 proxy", "address", uri.Host)
		u := uri.User.Username()
		p, _ := uri.User.Password()
		socksAuth := proxy.Auth{User: u, Password: p}
		c.dialer, err = proxy.SOCKS5("tcp", uri.Host, &socksAuth, proxy.Direct)
		if err != nil {
			fmt.Fprintln(os.Stderr, "can't connect to the proxy:", err)
			os.Exit(1)
		}
	} else {
		c.dialer = proxy.Direct
	}

	tmp, err := dnsclient.New(c.UpstreamDNS, true, c.UpstreamSOCKS5)
	if err != nil {
		log.Error("", err)
	}
	c.dnsClient = DNSClient{C: tmp}
	defer c.dnsClient.C.Close()
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
