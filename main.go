package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"

	prometheusmetrics "github.com/deathowl/go-metrics-prometheus"
	"github.com/mosajjal/dnsclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rcrowley/go-metrics"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
	"golang.org/x/net/proxy"

	_ "embed"

	"github.com/mosajjal/sniproxy/acl"
	doh "github.com/mosajjal/sniproxy/dohserver"
)

type runConfig struct {
	PublicIPv4      string `yaml:"public_ipv4"`
	PublicIPv6      string `yaml:"public_ipv6"`
	UpstreamDNS     string `yaml:"upstream_dns"`
	UpstreamSOCKS5  string `yaml:"upstream_socks5"`
	BindDNSOverUDP  string `yaml:"bind_dns_over_udp"`
	BindDNSOverTCP  string `yaml:"bind_dns_over_tcp"`
	BindDNSOverTLS  string `yaml:"bind_dns_over_tls"`
	BindDNSOverQuic string `yaml:"bind_dns_over_quic"`
	TLSCert         string `yaml:"tls_cert"`
	TLSKey          string `yaml:"tls_key"`
	BindHTTP        string `yaml:"bind_http"`
	BindHTTPS       string `yaml:"bind_https"`
	Interface       string `yaml:"interface"`
	BindPrometheus  string `yaml:"bind_prometheus"`

	acl []*acl.ACL

	dnsClient  DNSClient
	dialer     proxy.Dialer
	sourceAddr net.IP

	// metrics
	recievedHTTP  metrics.Counter
	proxiedHTTP   metrics.Counter
	recievedHTTPS metrics.Counter
	proxiedHTTPS  metrics.Counter
	recievedDNS   metrics.Counter
	proxiedDNS    metrics.Counter
}

var c runConfig

var (
	version string = "v2"
	commit  string = "none"
)

//go:embed config.defaults.yaml
var defaultConfig []byte

var logLevel = new(slog.LevelVar)
var log = slog.New(slog.HandlerOptions{Level: logLevel}.NewTextHandler(os.Stderr))

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

func getPublicIPv4() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
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
			dnsRes, _, err := c.dnsClient.performExternalAQuery("myip.opendns.com.", dns.TypeA)
			if err != nil {
				return "", err
			}
			externalIP = dnsRes[0].(*dns.A).A.String()
		}

		if externalIP != "" {

			return externalIP, nil
		}
		log.Error("Could not automatically find the public IPv4 address. Please specify it in the configuration.", nil)

	}
	return "", nil
}

func cleanIPv6(ip string) string {
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")
	return ip
}

func getPublicIPv6() (string, error) {
	conn, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")
	ipaddr := localAddr[0:idx]
	if !net.ParseIP(ipaddr).IsPrivate() {
		return cleanIPv6(ipaddr), nil
	}
	externalIP := ""
	// trying to get the public IP from multiple sources to see if they match.
	resp, err := http.Get("https://6.ident.me")
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			externalIP = string(body)
		}

		// backup method of getting a public IP
		if externalIP == "" {
			// dig +short -6 myip.opendns.com aaaa @2620:0:ccc::2
			dnsRes, _, err := c.dnsClient.performExternalAQuery("myip.opendns.com.", dns.TypeAAAA)
			if err != nil {
				return "", err
			}
			externalIP = dnsRes[0].(*dns.AAAA).AAAA.String()
		}

		if externalIP != "" {

			return cleanIPv6(externalIP), nil
		}
		log.Error("Could not automatically find the public IPv6 address. Please specify it in the configuration.", nil)

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
	config := flags.StringP("config", "c", "", "path to YAML configuration file")
	defaults := flags.String("defaultconfig", "", "write the default config yaml file to path")
	_ = flags.BoolP("version", "v", false, "show version info and exit")
	if err := cmd.Execute(); err != nil {
		log.Error("failed to execute command", "error", err)
		return
	}
	if flags.Changed("help") {
		return
	}
	if flags.Changed("version") {
		fmt.Printf("sniproxy version %s, commit %s\n", version, commit)
		return
	}
	if *defaults != "" {
		f, err := os.OpenFile(*defaults, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Error("failed to open file", "error", err)
			return
		}
		defer f.Close()
		if _, err := f.Write(defaultConfig); err != nil {
			log.Error("failed to write file", "error", err)
			return
		}
		return
	}

	k := koanf.New(".")
	// load the defaults
	if err := k.Load(rawbytes.Provider(defaultConfig), yaml.Parser()); err != nil {
		panic(err)
	}
	if *config != "" {
		if err := k.Load(file.Provider(*config), yaml.Parser()); err != nil {
			panic(err)
		}
	}

	switch k.String("log_level") {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "info":
		logLevel.Set(slog.LevelInfo)
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
	}

	log.Info("starting sniproxy", "version", version, "commit", commit)

	// verify and load config
	generalConfig := k.Cut("general")

	c.UpstreamDNS = generalConfig.String("upstream_dns")
	c.UpstreamSOCKS5 = generalConfig.String("upstream_socks5")
	c.BindDNSOverUDP = generalConfig.String("bind_dns_over_udp")
	c.BindDNSOverTCP = generalConfig.String("bind_dns_over_tcp")
	c.BindDNSOverTLS = generalConfig.String("bind_dns_over_tls")
	c.BindDNSOverQuic = generalConfig.String("bind_dns_over_quic")
	c.TLSCert = generalConfig.String("tls_cert")
	c.TLSKey = generalConfig.String("tls_key")
	c.BindHTTP = generalConfig.String("bind_http")
	c.BindHTTPS = generalConfig.String("bind_https")
	c.Interface = generalConfig.String("interface")
	c.PublicIPv4 = generalConfig.String("public_ipv4")
	if c.PublicIPv4 == "" {
		c.PublicIPv4, _ = getPublicIPv4()
	}
	c.PublicIPv6 = generalConfig.String("public_ipv6")
	if c.PublicIPv6 == "" {
		c.PublicIPv6, _ = getPublicIPv6()
	}
	c.BindPrometheus = generalConfig.String("prometheus")

	aclConfig := k.Cut("acl")
	var err error
	c.acl, err = acl.StartACLs(log, aclConfig)
	if err != nil {
		log.Error("failed to start ACLs", "error", err)
		return
	}

	// set up metrics
	c.recievedDNS = metrics.GetOrRegisterCounter("dns.requests.recieved", metrics.DefaultRegistry)
	c.proxiedDNS = metrics.GetOrRegisterCounter("dns.requests.proxied", metrics.DefaultRegistry)
	c.recievedHTTP = metrics.GetOrRegisterCounter("http.requests.recieved", metrics.DefaultRegistry)
	c.proxiedHTTP = metrics.GetOrRegisterCounter("http.requests.proxied", metrics.DefaultRegistry)
	c.recievedHTTPS = metrics.GetOrRegisterCounter("https.requests.recieved", metrics.DefaultRegistry)
	c.proxiedHTTPS = metrics.GetOrRegisterCounter("https.requests.proxied", metrics.DefaultRegistry)

	if c.BindPrometheus != "" {
		p := prometheusmetrics.NewPrometheusProvider(metrics.DefaultRegistry, "sniproxy", c.PublicIPv4, prometheus.DefaultRegisterer, 1*time.Second)
		go p.UpdatePrometheusMetrics()
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			log.Info("starting metrics server",
				"address", c.BindPrometheus,
			)
			if err := http.ListenAndServe(c.BindPrometheus, promhttp.Handler()); err != nil {
				log.Error(err.Error())
			}
		}()
	}

	// if c.DomainListPath == "" {
	// 	log.Warn("Domain list (--domainListPath) is not specified, routing ALL domains through the SNI proxy")
	// 	c.AllDomains = true
	// }
	if c.PublicIPv4 != "" {
		log.Info("server info", "public_ip", c.PublicIPv4)
	} else {
		log.Error("Could not automatically determine public IPv4. you should provide it manually using --publicIPv4")
	}

	if c.PublicIPv6 != "" {
		log.Info("server info", "public_ip", c.PublicIPv6)
	} else {
		log.Error("Could not automatically determine public IPv6. you should provide it manually using --publicIPv6")
	}

	// generate self-signed certificate if not provided
	if c.TLSCert == "" && c.TLSKey == "" {
		_, _, err := doh.GenerateSelfSignedCertKey(c.PublicIPv4, nil, nil, os.TempDir())
		log.Info("certificate was not provided, generating a self signed cert in temp directory")
		if err != nil {
			log.Error("error while generating self-signed cert: ", "error", err)
		}
		c.TLSCert = filepath.Join(os.TempDir(), c.PublicIPv4+".crt")
		c.TLSKey = filepath.Join(os.TempDir(), c.PublicIPv4+".key")
	}

	// throw an error if geoip include or exclude is present, but geoippath is not
	// if c.GeoIPPath == "" && (len(c.GeoIPInclude)+len(c.GeoIPExclude) >= 1) {
	// 	log.Error("GeoIP include or exclude is present, but GeoIPPath is not")
	// }
	//
	// // load mmdb if provided
	// if c.GeoIPPath != "" {
	// 	go initializeGeoIP(c.GeoIPPath)
	// 	c.GeoIPExclude = toLowerSlice(c.GeoIPExclude)
	// 	log.Info("GeoIP", "exclude", c.GeoIPExclude)
	// 	c.GeoIPInclude = toLowerSlice(c.GeoIPInclude)
	// 	log.Info("GeoIP", "include", c.GeoIPInclude)
	// }

	// Finds source addr for outbound connections if interface is not empty
	if c.Interface != "" {
		log.Info("Using", "interface", c.Interface)
		ief, err := net.InterfaceByName(c.Interface)
		if err != nil {
			log.Error(err.Error())
		}
		addrs, err := ief.Addrs()
		if err != nil {
			log.Error(err.Error())

		}
		c.sourceAddr = net.ParseIP(addrs[0].String())

	}

	if c.UpstreamSOCKS5 != "" {
		uri, err := url.Parse(c.UpstreamSOCKS5)
		if err != nil {
			log.Error(err.Error())
		}
		if uri.Scheme != "socks5" {
			log.Error("only SOCKS5 is supported")
			return
		}

		log.Info("Using an upstream SOCKS5 proxy", "address", uri.Host)
		u := uri.User.Username()
		p, _ := uri.User.Password()
		socksAuth := proxy.Auth{User: u, Password: p}
		c.dialer, err = proxy.SOCKS5("tcp", uri.Host, &socksAuth, proxy.Direct)
		if err != nil {
			log.Error("can't connect to proxy", "error", err.Error())
			os.Exit(1)
		}
	} else {
		c.dialer = proxy.Direct
	}

	tmp, err := dnsclient.New(c.UpstreamDNS, true, c.UpstreamSOCKS5)
	if err != nil {
		log.Error(err.Error())
	}
	c.dnsClient = DNSClient{tmp}
	defer c.dnsClient.Close()
	go runHTTP()
	go runHTTPS()
	go runDNS()

	// fetch domain list and refresh them periodically
	// if !c.AllDomains {
	// 	c.routePrefixes, c.routeSuffixes, c.routeFQDNs, _ = LoadDomainsCsv(c.DomainListPath)
	// 	for range time.NewTicker(c.DomainListRefreshInterval.Duration).C {
	// 		c.routePrefixes, c.routeSuffixes, c.routeFQDNs, _ = LoadDomainsCsv(c.DomainListPath)
	// 	}
	// } else {
	// 	select {}
	// }
	select {}
}
