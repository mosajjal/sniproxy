package main

import (
	"fmt"
	"net"

	acl "github.com/mosajjal/sniproxy/v2/acl"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

func handle443(conn net.Conn, httpslog zerolog.Logger) error {
	c.recievedHTTPS.Inc(1)

	defer conn.Close()
	incoming := make([]byte, 2048)
	n, err := conn.Read(incoming)
	if err != nil {
		httpslog.Err(err)
		return err
	}
	sni, err := GetHostname(incoming)
	if err != nil {
		httpslog.Err(err)
		return err
	}
	connInfo := acl.ConnInfo{
		SrcIP:  conn.RemoteAddr(),
		Domain: sni,
	}
	acl.MakeDecision(&connInfo, c.acl)

	if connInfo.Decision == acl.Reject {
		httpslog.Warn().Msgf("ACL rejection srcip=%s", conn.RemoteAddr().String())
		conn.Close()
		return nil
	}
	// check SNI against domainlist for an extra layer of security
	if connInfo.Decision == acl.OriginIP {
		httpslog.Warn().Str("sni", sni).Str("srcip", conn.RemoteAddr().String()).Msg("connection request rejected since it's not allowed as per ACL.. resetting TCP")
		conn.Close()
		return nil
	}
	rPort := 443
	var rAddr net.IP
	if connInfo.Decision == acl.Override {
		httpslog.Debug().Msgf("overriding destination IP %s with %s as per override ACL", rAddr.String(), connInfo.DstIP.String())
		rAddr = connInfo.DstIP.IP
		rPort = connInfo.DstIP.Port
	} else {
		rAddr, err = c.dnsClient.lookupDomain4(sni)
		if err != nil || rAddr == nil {
			httpslog.Warn().Msg(err.Error())
			return err
		}
		// TODO: handle timeout and context here
		if rAddr.IsLoopback() || rAddr.Equal(net.IPv4(0, 0, 0, 0)) || rAddr.Equal(net.IP(c.PublicIPv4)) || rAddr.Equal(net.IP(c.sourceAddr)) || rAddr.Equal(net.IP(c.PublicIPv6)) {
			httpslog.Info().Msg("connection to private IP or self ignored")
			return nil
		}
	}

	httpslog.Debug().Str("sni", sni).Str("srcip", conn.RemoteAddr().String()).Str("dstip", rAddr.String()).Msg("connection request accepted")
	// var target *net.TCPConn
	var target net.Conn
	// if the proxy is not set, or the destination IP is localhost, we'll use the OS's TCP stack and won't go through the SOCKS5 proxy
	if c.dialer == proxy.Direct || rAddr.IsLoopback() {
		// with the manipulation of the soruce address, we can set the outbound interface
		srcAddr := net.TCPAddr{
			IP:   c.sourceAddr,
			Port: 0,
		}
		target, err = net.DialTCP("tcp", &srcAddr, &net.TCPAddr{IP: rAddr, Port: rPort})
		if err != nil {
			httpslog.Info().Msgf("could not connect to target with error: %s", err)
			conn.Close()
			return err
		}
	} else {
		target, err = c.dialer.Dial("tcp", fmt.Sprintf("%s:%d", rAddr, rPort))
		if err != nil {
			httpslog.Info().Msgf("could not connect to target with error: %s", err)
			conn.Close()
			return err
		}
		// target = tmp.(*net.TCPConn)
	}
	defer target.Close()
	c.proxiedHTTPS.Inc(1)
	target.Write(incoming[:n])
	pipe(conn, target)
	return nil
}

func runHTTPS(log zerolog.Logger) {
	httpslog := log.With().Str("service", "https").Logger()
	l, err := net.Listen("tcp", c.BindHTTPS)
	if err != nil {
		httpslog.Err(err)
		panic(-1)
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			httpslog.Err(err)
		}
		go handle443(c, httpslog)
	}
}
