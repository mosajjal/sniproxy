package sniproxy

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

const (
	// TLSClientHelloBufferSize is the buffer size for reading a full TLS record
	// containing the ClientHello. TLS record payloads can be up to 16KB, plus
	// the 5-byte TLS record header.
	TLSClientHelloBufferSize = 16*1024 + 5

	// tlsReadTimeout is the deadline for reading the TLS ClientHello
	tlsReadTimeout = 10 * time.Second

	// upstreamDialTimeout is the deadline for dialing upstream targets
	upstreamDialTimeout = 10 * time.Second
)

// tlsBufferPool reuses buffers for reading TLS ClientHello packets
var tlsBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, TLSClientHelloBufferSize)
		return &buf
	},
}

// isSelf checks if the IP is the sniproxy itself
func isSelf(c *Config, ip netip.Addr) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip == netip.IPv4Unspecified() {
		return true
	}

	if c.PublicIPv4 != "" {
		if parsed, err := netip.ParseAddr(c.PublicIPv4); err == nil && ip == parsed {
			return true
		}
	}
	if c.PublicIPv6 != "" {
		if parsed, err := netip.ParseAddr(c.PublicIPv6); err == nil && ip == parsed {
			return true
		}
	}

	if slices.Contains(c.SourceAddr, ip) {
		return true
	}
	return false
}

func readFullTLSRecord(conn net.Conn, buf []byte) (int, error) {
	if len(buf) < 5 {
		return 0, fmt.Errorf("buffer too small for TLS header")
	}

	total := 0

	// Read TLS record header (5 bytes)
	for total < 5 {
		n, err := conn.Read(buf[total:5])
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
		total += n
	}

	// TLS record type: 0x16 = Handshake
	if buf[0] != 0x16 {
		return total, fmt.Errorf("not a TLS handshake record: type=%d", buf[0])
	}

	// TLS version: major must be 0x03 (TLS 1.0–1.3 all use this)
	if buf[1] != 0x03 {
		return total, fmt.Errorf("invalid TLS version: %d.%d", buf[1], buf[2])
	}

	// Parse record length (bytes 3-4)
	recordLen := int(buf[3])<<8 | int(buf[4])
	fullLen := 5 + recordLen

	if recordLen == 0 {
		return total, fmt.Errorf("empty TLS record")
	}

	if fullLen > len(buf) {
		return total, fmt.Errorf("TLS record too large: %d > %d", fullLen, len(buf))
	}

	// Read the rest of the record
	for total < fullLen {
		n, err := conn.Read(buf[total:fullLen])
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
		total += n
	}

	return total, nil
}

// handleTLS handles the incoming TLS connection
func handleTLS(c *Config, conn net.Conn, l zerolog.Logger) error {
	c.ReceivedHTTPS.Inc(1)
	defer func() { _ = conn.Close() }()

	bufPtr := tlsBufferPool.Get().(*[]byte)
	incoming := *bufPtr
	defer tlsBufferPool.Put(bufPtr)

	// Set a read deadline to prevent slowloris-style attacks
	if err := conn.SetReadDeadline(time.Now().Add(tlsReadTimeout)); err != nil {
		l.Error().Err(err).Msg("failed to set read deadline")
		return err
	}

	n, err := readFullTLSRecord(conn, incoming)
	if err != nil {
		l.Error().Err(err).Msg("failed to read full TLS record")
		return err
	}

	// Clear the read deadline for proxied data
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		l.Debug().Err(err).Msg("failed to clear read deadline")
	}

	sni, err := GetHostname(incoming[:n])
	if err != nil {
		l.Error().Err(err).Msg("failed to extract SNI")
		return err
	}
	if !isValidFQDN(sni) {
		l.Warn().Msgf("Invalid SNI: %s", sni)
		return nil
	}
	connInfo := acl.ConnInfo{
		SrcIP:  conn.RemoteAddr(),
		Domain: sni,
	}
	if err := acl.MakeDecision(&connInfo, c.ACL); err != nil {
		l.Error().Err(err).Msg("ACL decision failed")
		return err
	}

	if connInfo.Decision == acl.Reject {
		l.Warn().Msgf("ACL rejection srcip=%s", conn.RemoteAddr().String())
		return nil
	}
	// check SNI against domainlist for an extra layer of security
	if connInfo.Decision == acl.OriginIP {
		l.Warn().Str("sni", sni).Str("srcip", conn.RemoteAddr().String()).Msg("connection request rejected since it's not allowed as per ACL.. resetting TCP")
		return nil
	}
	rPort := getPortFromConn(conn) // by default, we'll use the listening port as the destination port
	var rAddr net.IP
	if connInfo.Decision == acl.Override {
		l.Debug().Msgf("overriding destination with %s as per override ACL", connInfo.DstIP.String())
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
		// with the manipulation of the source address, we can set the outbound interface
		srcAddr := net.TCPAddr{
			IP:   c.pickSrcAddr(c.PreferredVersion),
			Port: 0,
		}
		dialer := net.Dialer{
			Timeout:   upstreamDialTimeout,
			LocalAddr: &srcAddr,
		}
		target, err = dialer.Dial("tcp", net.JoinHostPort(rAddr.String(), strconv.Itoa(rPort)))
		if err != nil {
			l.Info().Msgf("could not connect to target with error: %s", err)
			return err
		}
	} else {
		target, err = c.Dialer.Dial("tcp", net.JoinHostPort(rAddr.String(), strconv.Itoa(rPort)))
		if err != nil {
			l.Info().Msgf("could not connect to target with error: %s", err)
			return err
		}
	}
	defer func() { _ = target.Close() }()

	c.ProxiedHTTPS.Inc(1)
	if _, err := target.Write(incoming[:n]); err != nil {
		l.Error().Err(err).Msg("failed to write ClientHello to target")
		return err
	}

	errc := make(chan error, 2)
	go proxyCopy(errc, conn, target)
	go proxyCopy(errc, target, conn)
	<-errc
	<-errc
	return nil
}

func proxyCopy(errc chan<- error, dst, src net.Conn) {
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
		defer func() { _ = listener.Close() }()
		var acceptErrors int
		for {
			con, err := listener.Accept()
			if err != nil {
				acceptErrors++
				l.Error().Msg(err.Error())
				// Backoff on repeated accept errors to avoid tight loop
				if acceptErrors > 5 {
					time.Sleep(100 * time.Millisecond)
				}
				continue
			}
			acceptErrors = 0
			go func(conn net.Conn) { _ = handleTLS(c, conn, l) }(con)
		}
	}
}
