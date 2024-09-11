package sniproxy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

// checks if the IP is the sniproxy itself
func isSelf(c *Config, ip netip.Addr) bool {
	condition1 := ip.IsLoopback() ||
		ip.IsPrivate() || ip == (netip.IPv4Unspecified())

	if c.PublicIPv4 != "" {
		condition1 = condition1 || (ip == netip.MustParseAddr(c.PublicIPv4))
	}
	if c.PublicIPv6 != "" {
		condition1 = condition1 || (ip == netip.MustParseAddr(c.PublicIPv6))
	}
	if condition1 {
		return true
	}

	for _, v := range c.SourceAddr {
		if ip == v {
			return true
		}
	}
	return false
}

// handleTLS handles the incoming TLS connection
func handleTLS(c *Config, conn net.Conn, httpslog zerolog.Logger) error {
	c.RecievedHTTPS.Inc(1)

	defer conn.Close()
	incoming := make([]byte, 2048) // 2048 should be enough for a TLS Client Hello packet. But it could become problematic if tcp connection is fragmented or too big
	n, err := conn.Read(incoming)
	if err != nil {
		httpslog.Err(err)
		return err
	}
	sni, err := GetHostname(incoming[:n])
	if err != nil {
		httpslog.Err(err)
		return err
	}
	if !isValidFQDN(sni) {
		httpslog.Warn().Msgf("Invalid SNI: %s", sni)
		conn.Close()
		return nil
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
	rPort := getPortFromConn(conn) // by default, we'll use the listening port as the destination port
	var rAddr net.IP
	if connInfo.Decision == acl.Override {
		httpslog.Debug().Msgf("overriding destination IP %s with %s as per override ACL", rAddr.String(), connInfo.DstIP.String())
		rAddr = connInfo.DstIP.IP
		rPort = connInfo.DstIP.Port
	} else {
		// TODO: lookup needs to be both ipv4 and ipv6
		rAddrTmp, err := c.DnsClient.lookupDomain(sni, c.PreferredVersion)
		if err != nil {
			httpslog.Warn().Msg(err.Error())
			return err
		}
		// TODO: handle timeout and context here
		if isSelf(c, rAddrTmp) && !c.AllowConnToLocal {
			httpslog.Info().Msg("connection to private IP or self ignored")
			return nil
		}
		rAddr = rAddrTmp.AsSlice()
	}

	httpslog.Debug().Str("sni", sni).Str("srcip", conn.RemoteAddr().String()).Str("dstip", rAddr.String()).Msg("connection request accepted")
	var target net.Conn
	// if the proxy is not set, or the destination IP is localhost, we'll use the OS's TCP stack and won't go through the SOCKS5 proxy
	if c.Dialer == proxy.Direct || rAddr.IsLoopback() {
		// with the manipulation of the soruce address, we can set the outbound interface
		srcAddr := net.TCPAddr{
			IP:   c.pickSrcAddr(c.PreferredVersion),
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

func getPortFromConn(conn net.Conn) int {
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	// convert the port string to its int format
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return portnum
}

func RunHTTPS(c *Config, bind string, log zerolog.Logger) {
	if l, err := net.Listen("tcp", bind); err != nil {
		log.Error().Msg(err.Error())
		panic(-1)
	} else {
		log.Info().Msgf("listening https on %s", bind)
		defer l.Close()
		for {
			if con, err := l.Accept(); err != nil {
				log.Error().Msg(err.Error())
			} else {
				go handleTLS(c, con, log)
			}
		}
	}
}
