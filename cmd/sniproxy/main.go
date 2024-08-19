package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/rs/zerolog"
	"github.com/txthinking/socks5"

	prometheusmetrics "github.com/deathowl/go-metrics-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rcrowley/go-metrics"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	_ "embed"
	stdlog "log"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"

	sniproxy "github.com/mosajjal/sniproxy/v2/pkg"
	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/mosajjal/sniproxy/v2/pkg/doh"
)

var c sniproxy.Config

var (
	version   string = "v2-UNKNOWN"
	commit    string = "NOT PROVIDED"
	envPrefix string = "SNIPROXY_" // used as the prefix to read env variables at runtime
)

//go:embed config.defaults.yaml
var defaultConfig []byte

// disable colors in logging if NO_COLOR is set
var nocolorLog = strings.ToLower(os.Getenv("NO_COLOR")) == "true"
var logger = zerolog.New(os.Stderr).With().Timestamp().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339, NoColor: nocolorLog})

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

		if externalIP != "" {
			return externalIP, nil
		}
		logger.Error().Msg("Could not automatically find the public IPv4 address. Please specify it in the configuration.")

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
			dnsRes, err := c.DnsClient.PerformExternalAQuery("myip.opendns.com.", dns.TypeAAAA)
			if err != nil {
				return "", err
			}
			externalIP = dnsRes[0].(*dns.AAAA).AAAA.String()
		}

		if externalIP != "" {
			return cleanIPv6(externalIP), nil
		}
		logger.Error().Msg("Could not automatically find the public IPv6 address. Please specify it in the configuration.")

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
	_ = flags.Bool("defaultconfig", false, "write the default config yaml file to stdout")
	_ = flags.BoolP("version", "v", false, "show version info and exit")
	if err := cmd.Execute(); err != nil {
		logger.Error().Msgf("failed to execute command: %s", err)
		return
	}
	if flags.Changed("help") {
		return
	}
	if flags.Changed("version") {
		fmt.Printf("sniproxy version %s, commit %s\n", version, commit)
		return
	}
	if flags.Changed("defaultconfig") {
		fmt.Fprintf(os.Stdout, string(defaultConfig))
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
	// load environment variables starting with envPrefix
	k.Load(env.Provider(envPrefix, ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, envPrefix)), "__", ".", -1)
	}), nil)

	logger.Info().Msgf("starting sniproxy. version %s, commit %s", version, commit)

	// verify and load config
	generalConfig := k.Cut("general")

	stdlog.SetFlags(0)
	stdlog.SetOutput(logger)

	switch l := generalConfig.String("log_level"); l {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		logger = logger.With().Caller().Logger()
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		logger = logger.With().Caller().Logger()
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	c.UpstreamDNS = generalConfig.String("upstream_dns")
	c.UpstreamDNSOverSocks5 = generalConfig.Bool("upstream_dns_over_socks5")
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
	if c.PublicIPv4 == "" && c.PublicIPv6 == "" {
		logger.Error().Msg("Could not automatically determine public IP. you should provide it manually using --publicIPv4 and --publicIPv6")
		return
	}
	c.BindPrometheus = generalConfig.String("prometheus")
	c.AllowConnToLocal = generalConfig.Bool("allow_conn_to_local")

	c.PreferredVersion = uint(generalConfig.Int("preferred_version"))

	var err error
	c.Acl, err = acl.StartACLs(&logger, k)
	if err != nil {
		logger.Error().Msgf("failed to start ACLs: %s", err)
		return
	}

	// set up metrics
	c.RecievedDNS = metrics.GetOrRegisterCounter("dns.requests.recieved", metrics.DefaultRegistry)
	c.ProxiedDNS = metrics.GetOrRegisterCounter("dns.requests.proxied", metrics.DefaultRegistry)
	c.RecievedHTTP = metrics.GetOrRegisterCounter("http.requests.recieved", metrics.DefaultRegistry)
	c.ProxiedHTTP = metrics.GetOrRegisterCounter("http.requests.proxied", metrics.DefaultRegistry)
	c.RecievedHTTPS = metrics.GetOrRegisterCounter("https.requests.recieved", metrics.DefaultRegistry)
	c.ProxiedHTTPS = metrics.GetOrRegisterCounter("https.requests.proxied", metrics.DefaultRegistry)

	if c.BindPrometheus != "" {
		p := prometheusmetrics.NewPrometheusProvider(metrics.DefaultRegistry, "sniproxy", c.PublicIPv4, prometheus.DefaultRegisterer, 1*time.Second)
		go p.UpdatePrometheusMetrics()
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			logger.Info().Str(
				"address", c.BindPrometheus,
			).Msg("starting metrics server")
			if err := http.ListenAndServe(c.BindPrometheus, promhttp.Handler()); err != nil {
				logger.Error().Msgf("%s", err)
			}
		}()
	}

	if c.PublicIPv4 != "" {
		logger.Info().Str("public_ip", c.PublicIPv4).Msg("server info")
	} else {
		logger.Error().Msg("Could not automatically determine public IPv4. you should provide it manually using --publicIPv4")
	}

	if c.PublicIPv6 != "" {
		logger.Info().Str("public_ip", c.PublicIPv6).Msg("server info")
	} else {
		logger.Error().Msg("Could not automatically determine public IPv6. you should provide it manually using --publicIPv6")
	}

	// generate self-signed certificate if not provided
	if c.TLSCert == "" && c.TLSKey == "" {
		_, _, err := doh.GenerateSelfSignedCertKey(c.PublicIPv4, nil, nil, os.TempDir())
		logger.Info().Msg("certificate was not provided, generating a self signed cert in temp directory")
		if err != nil {
			logger.Error().Msgf("error while generating self-signed cert: %s", err)
		}
		c.TLSCert = filepath.Join(os.TempDir(), c.PublicIPv4+".crt")
		c.TLSKey = filepath.Join(os.TempDir(), c.PublicIPv4+".key")
	}

	// Finds source addr for outbound connections if interface is not empty
	if c.Interface != "" {
		logger.Info().Msgf("Using interface %s", c.Interface)
		ief, err := net.InterfaceByName(c.Interface)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
		addrs, err := ief.Addrs()
		if err != nil {
			logger.Error().Msg(err.Error())
		}
		// TODO: split ipv4 and ipv6 to different lists
		for _, addr := range addrs {
			c.SourceAddr = append(c.SourceAddr, netip.MustParseAddr(addr.String()))
		}
	}

	if c.UpstreamSOCKS5 != "" {
		uri, err := url.Parse(c.UpstreamSOCKS5)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
		if uri.Scheme != "socks5" {
			logger.Error().Msg("only SOCKS5 is supported")
			return
		}

		logger.Info().Msgf("Using an upstream SOCKS5 proxy: %s", uri.Host)
		socksAuth := new(proxy.Auth)
		socksAuth.User = uri.User.Username()
		socksAuth.Password, _ = uri.User.Password()
		c.Dialer, err = socks5.NewClient(uri.Host, socksAuth.User, socksAuth.Password, 60, 60)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
	} else {
		c.Dialer = proxy.Direct
	}

	dnsProxy := c.UpstreamSOCKS5
	if c.UpstreamSOCKS5 != "" && !c.UpstreamDNSOverSocks5 {
		logger.Debug().Msg("disabling socks5 for dns")
		dnsProxy = ""
	}
	tmp, err := sniproxy.NewDNSClient(&c, c.UpstreamDNS, true, dnsProxy)
	if err != nil {
		logger.Error().Msgf("error setting up dns client, removing proxy if provided: %v", err)
		tmp, err = sniproxy.NewDNSClient(&c, c.UpstreamDNS, false, "")
		if err != nil {
			logger.Error().Msgf("error setting up dns client: %v", err)
			return
		}
	}
	c.DnsClient = *tmp
	go sniproxy.RunHTTP(&c, logger)
	go sniproxy.RunHTTPS(&c, logger.With().Str("service", "https").Logger())
	go sniproxy.RunDNS(&c, logger.With().Str("service", "dns").Logger())

	select {}
}
