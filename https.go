package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

// handle HTTPS connections coming to the reverse proxy. this will get a connction from the handle443 function
// need to grab the HTTP request from this, and pass it on to the HTTP handler.
func handleReverse(conn net.Conn) error {
	log.Infof("[Reverse] connecting to HTTP")
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

	if !checkGeoIPSkip(conn.RemoteAddr().String()) {
		log.Warnf("Rejected request from %s", conn.RemoteAddr().String())
		conn.Close()
		return nil
	}

	defer conn.Close()
	incoming := make([]byte, 2048)
	n, err := conn.Read(incoming)
	if err != nil {
		log.Errorln(err)
		return err
	}
	sni, err := GetHostname(incoming)
	if err != nil {
		log.Errorln(err)
		return err
	}
	// check SNI against domainlist for an extra layer of security
	if !c.AllDomains && inDomainList(sni+".") {
		log.Warnf("[TCP] a client requested connection to %s, but it's not allowed as per configuration.. resetting TCP", sni)
		conn.Close()
		return nil
	}
	rAddr, err := lookupDomain4(sni)
	rPort := 443
	if err != nil || rAddr == nil {
		log.Warnln(err)
		return err
	}
	// TODO: handle timeout and context here
	if rAddr.IsLoopback() || rAddr.IsPrivate() || rAddr.Equal(net.IPv4(0, 0, 0, 0)) {
		log.Infoln("[TLS] connection to private IP ignored")
		return nil
	}
	// TODO: if SNI is the reverse proxy, this request needs to be handled by a HTTPS handler
	if sni == c.reverseProxySNI {
		rAddr = net.IPv4(127, 0, 0, 1)
		rPort = 65000
	}
	log.Infof("[TLS] connecting to %s (%s)", rAddr, sni)
	// TODO: with the manipulation of the soruce address, we can set the outbound interface
	srcAddr := net.TCPAddr{
		IP:   c.sourceAddr,
		Port: 0,
	}
	target, err := net.DialTCP("tcp", &srcAddr, &net.TCPAddr{IP: rAddr, Port: rPort})
	if err != nil {
		log.Errorln("could not connect to target", err)
		conn.Close()
		return err
	}
	defer target.Close()
	target.Write(incoming[:n])
	pipe(conn, target)
	return nil
}

func runReverse() {
	// reverse https can't run on 443. we'll pick a random port and pipe the 443 traffic back to it.
	cert, err := tls.LoadX509KeyPair(c.ReverseProxyCert, c.ReverseProxyKey)
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	listener, err := tls.Listen("tcp", ":65000", &config)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		go handleReverse(conn)
	}
}

func runHTTPS() {

	l, err := net.Listen("tcp", c.BindIP+fmt.Sprintf(":%d", c.HTTPSPort))
	if err != nil {
		log.Fatalln(err)
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatalln(err)
		}
		go func() {
			go handle443(c)
			//TODO: there's a better way to handle TCP timeouts than just a blanket 30 seconds rule
			// c.Close()
		}()
	}
}
