package sniproxy

import (
	"fmt"
	"net"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

func handle443(c *Config, conn net.Conn, httpslog zerolog.Logger) error {
	c.RecievedHTTPS.Inc(1)

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
	acl.MakeDecision(&connInfo, c.Acl)

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
		rAddr, err = c.DnsClient.lookupDomain4(sni)
		if err != nil || rAddr == nil {
			httpslog.Warn().Msg(err.Error())
			return err
		}
		// TODO: handle timeout and context here
		if rAddr.IsLoopback() || (rAddr.IsPrivate() && !c.AllowConnToLocal) || rAddr.Equal(net.IPv4(0, 0, 0, 0)) || rAddr.Equal(net.IP(c.PublicIPv4)) || rAddr.Equal(net.IP(c.SourceAddr)) || rAddr.Equal(net.IP(c.PublicIPv6)) {
			httpslog.Info().Msg("connection to private IP or self ignored")
			return nil
		}
	}

	httpslog.Debug().Str("sni", sni).Str("srcip", conn.RemoteAddr().String()).Str("dstip", rAddr.String()).Msg("connection request accepted")
	// var target *net.TCPConn
	var target net.Conn
	// if the proxy is not set, or the destination IP is localhost, we'll use the OS's TCP stack and won't go through the SOCKS5 proxy
	if c.Dialer == proxy.Direct || rAddr.IsLoopback() {
		// with the manipulation of the soruce address, we can set the outbound interface
		srcAddr := net.TCPAddr{
			IP:   c.SourceAddr,
			Port: 0,
		}
		target, err = net.DialTCP("tcp", &srcAddr, &net.TCPAddr{IP: rAddr, Port: rPort})
		if err != nil {
			httpslog.Info().Msgf("could not connect to target with error: %s", err)
			conn.Close()
			return err
		}
	} else {
		target, err = c.Dialer.Dial("tcp", fmt.Sprintf("%s:%d", rAddr, rPort))
		if err != nil {
			httpslog.Info().Msgf("could not connect to target with error: %s", err)
			conn.Close()
			return err
		}
		// target = tmp.(*net.TCPConn)
	}
	defer target.Close()
	c.ProxiedHTTPS.Inc(1)
	target.Write(incoming[:n])
	pipe(conn, target)
	return nil
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

func RunHTTPS(c *Config, log zerolog.Logger) {
	l, err := net.Listen("tcp", c.BindHTTPS)
	if err != nil {
		log.Err(err)
		panic(-1)
	}
	defer l.Close()
	for {
		con, err := l.Accept()
		if err != nil {
			log.Err(err)
		}
		go handle443(c, con, log)
	}
}
