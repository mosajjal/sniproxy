package sniproxy

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

const (
	// TLSClientHelloBufferSize is the buffer size for reading TLS Client Hello
	// 2048 should be enough for a TLS Client Hello packet. But it could become
	// problematic if tcp connection is fragmented or too big
	TLSClientHelloBufferSize = 2048
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
func handleTLS(c *Config, conn net.Conn, l zerolog.Logger) error {
	c.ReceivedHTTPS.Inc(1)

	incoming := make([]byte, TLSClientHelloBufferSize)
	n, err := conn.Read(incoming)
	if err != nil {
		l.Err(err)
		return err
	}
	sni, err := GetHostname(incoming[:n])
	if err != nil {
		l.Err(err)
		return err
	}
	if !isValidFQDN(sni) {
		l.Warn().Msgf("Invalid SNI: %s", sni)
		conn.Close()
		return nil
	}
	connInfo := acl.ConnInfo{
		SrcIP:  conn.RemoteAddr(),
		Domain: sni,
	}
	acl.MakeDecision(&connInfo, c.ACL)

	if connInfo.Decision == acl.Reject {
		l.Warn().Msgf("ACL rejection srcip=%s", conn.RemoteAddr().String())
		conn.Close()
		return nil
	}
	// check SNI against domainlist for an extra layer of security
	if connInfo.Decision == acl.OriginIP {
		l.Warn().Str("sni", sni).Str("srcip", conn.RemoteAddr().String()).Msg("connection request rejected since it's not allowed as per ACL.. resetting TCP")
		conn.Close()
		return nil
	}
	rPort := getPortFromConn(conn) // by default, we'll use the listening port as the destination port
	var rAddr net.IP
	if connInfo.Decision == acl.Override {
		l.Debug().Msgf("overriding destination IP %s with %s as per override ACL", rAddr.String(), connInfo.DstIP.String())
		rAddr = connInfo.DstIP.IP
		rPort = connInfo.DstIP.Port
	} else {
		rAddrTmp, err := c.DNSClient.lookupDomain(sni, c.PreferredVersion)
		if err != nil {
			l.Warn().Err(err).Str("sni", sni).Msg("failed to resolve domain")
			return err
		}
		if isSelf(c, rAddrTmp) && !c.AllowConnToLocal {
			l.Info().Msg("connection to private IP or self ignored")
			return nil
		}
		rAddr = rAddrTmp.AsSlice()
	}

	l.Debug().Str("sni", sni).Str("srcip", conn.RemoteAddr().String()).Str("dstip", rAddr.String()).Msg("connection request accepted")
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
			l.Info().Msgf("could not connect to target with error: %s", err)
			conn.Close()
			return err
		}
	} else {
		target, err = c.Dialer.Dial("tcp", fmt.Sprintf("%s:%d", rAddr, rPort))
		if err != nil {
			l.Info().Msgf("could not connect to target with error: %s", err)
			conn.Close()
			return err
		}
	}
	c.ProxiedHTTPS.Inc(1)
	target.Write(incoming[:n])

	errc := make(chan error, 2)
	go proxyCopy(errc, conn, target)
	go proxyCopy(errc, target, conn)
	<-errc
	<-errc
	return nil
}

func proxyCopy(errc chan<- error, dst, src net.Conn) {
	defer src.Close()
	defer dst.Close()

	_, err := io.Copy(dst, src)
	errc <- err
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

// RunHTTPS starts the HTTPS/TLS proxy server on the specified bind address.
// The bind address should be in the format "0.0.0.0:443" or similar (ip:port).
// This function blocks and should typically be run in a goroutine.
func RunHTTPS(c *Config, bind string, l zerolog.Logger) {
	l = l.With().Str("service", "https").Str("listener", bind).Logger()
	if listener, err := net.Listen("tcp", bind); err != nil {
		l.Fatal().Msg(err.Error())
	} else {
		l.Info().Msgf("listening https on %s", bind)
		defer listener.Close()
		for {
			if con, err := listener.Accept(); err != nil {
				l.Error().Msg(err.Error())
			} else {
				go handleTLS(c, con, l)
			}
		}
	}
}
