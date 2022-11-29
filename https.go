package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	slog "golang.org/x/exp/slog"
)

var httpslog = slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue("https")}}))

// handle HTTPS connections coming to the reverse proxy. this will get a connction from the handle443 function
// need to grab the HTTP request from this, and pass it on to the HTTP handler.
func handleReverse(conn net.Conn) error {
	httpslog.Info("connecting to HTTP")
	// send the reverse conn to local HTTP listner
	srcAddr := net.TCPAddr{
		IP:   c.sourceAddr,
		Port: 0,
	}
	target, err := net.DialTCP("tcp", &srcAddr, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(c.HTTPPort)})
	if err != nil {
		return err
	}
	pipe(conn, target)
	return nil
}

func handle443(conn net.Conn) error {
	c.recievedHTTPS.Inc(1)
	if !checkGeoIPSkip(conn.RemoteAddr().String()) {
		httpslog.Warn("Rejected request due to GEOIP restriction", "ip", conn.RemoteAddr().String())
		conn.Close()
		return nil
	}

	defer conn.Close()
	incoming := make([]byte, 2048)
	n, err := conn.Read(incoming)
	if err != nil {
		httpslog.Error("", err)
		return err
	}
	sni, err := GetHostname(incoming)
	if err != nil {
		httpslog.Error("", err)
		return err
	}
	// check SNI against domainlist for an extra layer of security
	if !c.AllDomains && inDomainList(sni+".") {
		httpslog.Warn("a client requested connection to " + sni + ", but it's not allowed as per configuration.. resetting TCP")
		conn.Close()
		return nil
	}
	rAddr, err := c.dnsClient.lookupDomain4(sni)
	rPort := 443
	if err != nil || rAddr == nil {
		httpslog.Warn(err.Error())
		return err
	}
	// TODO: handle timeout and context here
	if rAddr.IsLoopback() || rAddr.IsPrivate() || rAddr.Equal(net.IPv4(0, 0, 0, 0)) {
		httpslog.Info("connection to private IP ignored")
		return nil
	}
	// if SNI is the reverse proxy, this request needs to be handled by a HTTPS handler
	if sni == c.reverseProxySNI {
		rAddr = net.IPv4(127, 0, 0, 1)
		// TODO: maybe 65000 as a static port is not a good idea and this needs to be random OR unix socket
		rPort = 65000
	}
	httpslog.Info("establishing connection", "remote_ip", rAddr, "host", sni)
	// with the manipulation of the soruce address, we can set the outbound interface
	srcAddr := net.TCPAddr{
		IP:   c.sourceAddr,
		Port: 0,
	}
	target, err := net.DialTCP("tcp", &srcAddr, &net.TCPAddr{IP: rAddr, Port: rPort})
	if err != nil {
		httpslog.Error("could not connect to target", err)
		conn.Close()
		return err
	}
	defer target.Close()
	c.proxiedHTTPS.Inc(1)
	target.Write(incoming[:n])
	pipe(conn, target)
	return nil
}

func runReverse() {
	// reverse https can't run on 443. we'll pick a random port and pipe the 443 traffic back to it.
	cert, err := tls.LoadX509KeyPair(c.ReverseProxyCert, c.ReverseProxyKey)
	if err != nil {
		httpslog.Error("", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	listener, err := tls.Listen("tcp", ":65000", &config)
	if err != nil {
		httpslog.Error("", err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			httpslog.Error("", err)
			break
		}
		defer conn.Close()
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		go handleReverse(conn)
	}
}

func runHTTPS() {

	l, err := net.Listen("tcp", c.BindIP+fmt.Sprintf(":%d", c.HTTPSPort))
	if err != nil {
		httpslog.Error("", err)
		panic(-1)
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			httpslog.Error("", err)
		}
		go func() {
			go handle443(c)
		}()
	}
}
