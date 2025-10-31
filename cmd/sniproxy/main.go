// sniproxy's main CLI entrpoint.
package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	prometheusmetrics "github.com/deathowl/go-metrics-prometheus"
	"github.com/google/uuid"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/pkg/profile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	_ "embed"
	stdlog "log"

	sniproxy "github.com/mosajjal/sniproxy/v2/pkg"
	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/mosajjal/sniproxy/v2/pkg/doh"
)

var c sniproxy.Config

var (
	version   = "v2-UNKNOWN"
	commit    = "NOT PROVIDED"
	envPrefix = "SNIPROXY_" // used as the prefix to read env variables at runtime
)

//go:embed config.defaults.yaml
var defaultConfig []byte

// disable colors in logging if NO_COLOR is set
var nocolorLog = strings.ToLower(os.Getenv("NO_COLOR")) == "true"
var logger = zerolog.New(os.Stderr).With().Timestamp().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339, NoColor: nocolorLog})

func enableProfile(profileType string) interface{ Stop() } {
	switch profileType {
	case "":
		return nil
	case "cpu":
		return profile.Start(profile.CPUProfile)
	case "mem":
		return profile.Start(profile.MemProfile)
	case "block":
		return profile.Start(profile.BlockProfile)
	case "mutex":
		return profile.Start(profile.MutexProfile)
	case "trace":
		return profile.Start(profile.TraceProfile)
	case "threadcreate":
		return profile.Start(profile.ThreadcreationProfile)
	case "goroutine":
		return profile.Start(profile.GoroutineProfile)
	case "clock":
		return profile.Start(profile.ClockProfile)
	default:
		logger.Error().Msgf("unknown profile type: %s", profileType)
	}
	return nil
}

func main() {

	cmd := &cobra.Command{
		Use:   "sniproxy",
		Short: "SNI Proxy with Embedded DNS Server",
		Run:   func(_ *cobra.Command, _ []string) {},
	}
	flags := cmd.Flags()
	config := flags.StringP("config", "c", "", "path to YAML configuration file")
	_ = flags.Bool("defaultconfig", false, "write the default config yaml file to stdout")
	prof := flags.String("prof", "", "enable profiling. can be one of: [cpu, mem, block, mutex, trace, threadcreate, goroutine, clock]")
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
		fmt.Fprint(os.Stdout, string(defaultConfig))
		return
	}
	ret := enableProfile(*prof)
	if ret != nil {
		defer ret.Stop()
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
	c.BindHTTPAdditional = generalConfig.Strings("bind_http_additional")
	c.BindHTTPS = generalConfig.String("bind_https")
	c.BindHTTPSAdditional = generalConfig.Strings("bind_https_additional")
	c.Interface = generalConfig.String("interface")
	c.PreferredVersion = generalConfig.String("preferred_version")

	// if preferred version is ipv6only, we don't need to check for ipv4 public ip
	if c.PreferredVersion != "ipv6only" {
		c.PublicIPv4 = generalConfig.String("public_ipv4")
		if c.PublicIPv4 == "" {
			var err error
			c.PublicIPv4, err = sniproxy.GetPublicIPv4()
			if err != nil {
				logger.Fatal().Msgf("failed to get public IPv4, while ipv4 is enabled in preferred_version: %s", err)
			}
			logger.Info().Msgf("public IPv4 (automatically determined): %s", c.PublicIPv4)
		} else {
			logger.Info().Msgf("public IPv4 (manually provided): %s", c.PublicIPv4)
		}
	}
	// if preferred version is ipv4only, we don't need to check for ipv6 public ip
	if c.PreferredVersion != "ipv4only" {
		c.PublicIPv6 = generalConfig.String("public_ipv6")
		if c.PublicIPv6 == "" {
			var err error
			c.PublicIPv6, err = sniproxy.GetPublicIPv6()
			if err != nil {
				logger.Fatal().Msgf("failed to get public IPv6, while ipv6 is enabled in preferred_version: %s", err)
			}
			logger.Info().Msgf("public IPv6 (automatically determined): %s", c.PublicIPv6)
		} else {
			logger.Info().Msgf("public IPv6 (manually provided): %s", c.PublicIPv6)
		}
	}

	// in any case, at least one public IP address is needed to run the server. if both are empty, we can't proceed
	if c.PublicIPv4 == "" && c.PublicIPv6 == "" {
		logger.Error().Msg("Could not automatically determine any public IP. you should provide it manually using --publicIPv4 or --publicIPv6 or both.")
		logger.Error().Msg("if your environment is single-stack, you can use --preferredVersion to specify the version as ipv4only or ipv6only.")
		return
	}

	c.BindPrometheus = generalConfig.String("prometheus")
	c.AllowConnToLocal = generalConfig.Bool("allow_conn_to_local")

	// Validate configuration before proceeding
	if err := c.Validate(); err != nil {
		logger.Fatal().Msgf("configuration validation failed: %s", err)
	}

	var err error
	c.ACL, err = acl.StartACLs(&logger, k)
	if err != nil {
		logger.Error().Msgf("failed to start ACLs: %s", err)
		return
	}

	// set up metrics
	c.ReceivedDNS = metrics.GetOrRegisterCounter("dns.requests.received", metrics.DefaultRegistry)
	c.ProxiedDNS = metrics.GetOrRegisterCounter("dns.requests.proxied", metrics.DefaultRegistry)
	c.ReceivedHTTP = metrics.GetOrRegisterCounter("http.requests.received", metrics.DefaultRegistry)
	c.ProxiedHTTP = metrics.GetOrRegisterCounter("http.requests.proxied", metrics.DefaultRegistry)
	c.ReceivedHTTPS = metrics.GetOrRegisterCounter("https.requests.received", metrics.DefaultRegistry)
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

	// generate self-signed certificate if not provided.
	if c.TLSCert == "" && c.TLSKey == "" {
		// generate a random 16 char string as hostname
		hostname := uuid.NewString()[:16]
		logger.Info().Msg("certificate was not provided, generating a self signed cert in temp directory")
		_, _, err := doh.GenerateSelfSignedCertKey(hostname, nil, nil, os.TempDir())
		if err != nil {
			logger.Error().Msgf("error while generating self-signed cert: %s", err)
		}
		c.TLSCert = filepath.Join(os.TempDir(), hostname+".crt")
		c.TLSKey = filepath.Join(os.TempDir(), hostname+".key")
	}

	// if the "interface" configuration is provided, sniproxy must translate the interface name to the IP addresses
	// and add them to the source address list
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
		var ipv4Count, ipv6Count int
		for _, addr := range addrs {
			ipAddr, err := netip.ParseAddr(strings.Split(addr.String(), "/")[0])
			if err != nil {
				logger.Warn().Msgf("failed to parse address %s: %v", addr.String(), err)
				continue
			}
			c.SourceAddr = append(c.SourceAddr, ipAddr)
			if ipAddr.Is4() {
				ipv4Count++
			} else if ipAddr.Is6() {
				ipv6Count++
			}
		}
		logger.Info().Msgf("Added %d IPv4 and %d IPv6 source addresses from interface %s", ipv4Count, ipv6Count, c.Interface)
	}

	// set up dialer based on SOCKS5 configuration
	if err := c.SetDialer(logger); err != nil {
		logger.Error().Msgf("error setting up dialer: %v", err)
		return
	}

	// set up the DNS Client based on the configuration
	if err := c.SetDNSClient(logger); err != nil {
		logger.Error().Msgf("error setting up DNS client: %v", err)
		return
	}

	// get a list of http and https binds
	if err := c.SetBindHTTPListeners(logger); err != nil {
		logger.Error().Msgf("error setting up HTTP listeners: %v", err)
		return
	}
	logger.Info().Msgf("HTTP listeners: %v", c.BindHTTPListeners)
	if err := c.SetBindHTTPSListeners(logger); err != nil {
		logger.Error().Msgf("error setting up HTTPS listeners: %v", err)
		return
	}
	logger.Info().Msgf("HTTPS listeners: %v", c.BindHTTPSListeners)

	for _, addr := range c.BindHTTPListeners {
		go sniproxy.RunHTTP(&c, addr, logger)
	}
	for _, addr := range c.BindHTTPSListeners {
		go sniproxy.RunHTTPS(&c, addr, logger)
	}
	go sniproxy.RunDNS(&c, logger)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	logger.Info().Msgf("received signal %v, shutting down gracefully...", sig)

	// Allow some time for connections to finish
	// In a production system, you'd want to track active connections and wait for them
	time.Sleep(2 * time.Second)
	logger.Info().Msg("shutdown complete")
}
