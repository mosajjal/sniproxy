package acl

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf"
	dohserver "github.com/mosajjal/sniproxy/v2/pkg/doh"
	"github.com/rs/zerolog"
	"inet.af/tcpproxy"
)

// override ACL. This ACL is used to override the destination IP to not be the one resolved by the upstream DNS or the proxy itself, rather a custom IP and port
// if the destination is HTTP, it uses tls_cert and tls_key certificate to terminate the original connection.
type override struct {
	priority     uint
	rules        map[string]string
	doh          *dohserver.Server
	dohPort      int
	tcpproxy     *tcpproxy.Proxy
	tcpproxyport int
	tlsCert      string
	tlsKey       string
	logger       *zerolog.Logger
}

// GetFreePort returns a random open port
func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return GetFreePort()
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// tcpproxy listens on a random port on localhost
func (o *override) startProxy() {
	o.tcpproxy = new(tcpproxy.Proxy)
	var err error
	o.tcpproxyport, err = GetFreePort()
	if err != nil {
		o.logger.Error().Msgf("failed to get a free port for tcpproxy: %s", err)
		return
	}
	for k, v := range o.rules {
		o.logger.Info().Msgf("adding override rule %s -> %s", k, v)
		// AddSNIRoute supports exact matches and wildcards (*.example.com)
		// Regex matching would require changes to the tcpproxy library
		o.tcpproxy.AddSNIRoute(fmt.Sprintf("127.0.0.1:%d", o.tcpproxyport), k, tcpproxy.To(v))
	}
	o.logger.Info().Msgf("starting tcpproxy on port %d", o.tcpproxyport)
	o.tcpproxy.Run()
}

func (o override) Decide(c *ConnInfo) error {
	o.logger.Debug().Any("conn", c).Msg("deciding on override acl")
	domain := strings.TrimSuffix(c.Domain, ".")
	for k := range o.rules {
		if strings.TrimSuffix(k, ".") == domain {
			c.Decision = Override
			a, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", o.tcpproxyport))
			c.DstIP = *a
			break
		}
	}
	o.logger.Debug().Any("conn", c).Msg("decided on override acl")
	return nil
}

func (o override) Name() string {
	return "override"
}
func (o override) Priority() uint {
	return o.priority
}

func (o *override) ConfigAndStart(logger *zerolog.Logger, c *koanf.Koanf) error {
	DNSBind := c.String("general.bind_dns_over_udp")
	c = c.Cut(fmt.Sprintf("acl.%s", o.Name()))
	tmpRules := c.StringMap("rules")
	o.logger = logger
	o.priority = uint(c.Int("priority"))
	o.tlsCert = c.String("tls_cert")
	o.tlsKey = c.String("tls_key")
	if c.String("doh_sni") != "" {
		dohSNI := c.String("doh_sni")
		var err error
		o.dohPort, err = GetFreePort()
		if err != nil {
			return err
		}
		dohConfig := dohserver.NewDefaultConfig()
		dohConfig.Listen = []string{fmt.Sprintf("127.0.0.1:%d", o.dohPort)}
		if o.tlsCert == "" || o.tlsKey == "" {
			_, _, err := dohserver.GenerateSelfSignedCertKey(dohSNI, nil, nil, os.TempDir())
			o.logger.Info().Msg("certificate was not provided, generating a self signed cert in temp directory")
			if err != nil {
				o.logger.Error().Msgf("error while generating self-signed cert: %s", err)
			}
			o.tlsCert = filepath.Join(os.TempDir(), dohSNI+".crt")
			o.tlsKey = filepath.Join(os.TempDir(), dohSNI+".key")
		}
		dohConfig.Cert = o.tlsCert
		dohConfig.Key = o.tlsKey
		dohConfig.Upstream = []string{fmt.Sprintf("udp:%s", DNSBind)}
		dohS, err := dohserver.NewServer(dohConfig)
		if err != nil {
			return err
		}
		go dohS.Start()
		// append a rule to the rules map to redirect the DoH SNI to DoH
		tmpRules[dohSNI] = fmt.Sprintf("127.0.0.1:%d", o.dohPort)
	}
	o.rules = tmpRules

	go o.startProxy()
	return nil
}

// make domain available to the ACL system at import time
func init() {
	availableACLs = append(availableACLs, &override{})
}
