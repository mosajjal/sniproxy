package main

import (
	"fmt"
	"net"

	"github.com/mosajjal/sniproxy/acl"
	"golang.org/x/exp/slog"
	"golang.org/x/net/proxy"
)

var httpslog = slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue("https")}}))

func handle443(conn net.Conn) error {
	c.recievedHTTPS.Inc(1)

	defer conn.Close()
	incoming := make([]byte, 2048)
	n, err := conn.Read(incoming)
	if err != nil {
		httpslog.Error(err.Error())
		return err
	}
	sni, err := GetHostname(incoming)
	if err != nil {
		httpslog.Error(err.Error())
		return err
	}
	connInfo := acl.ConnInfo{
		SrcIP:  conn.RemoteAddr(),
		Domain: sni,
	}
	acl.MakeDecision(&connInfo, c.acl)

	if connInfo.Decision == acl.Reject {
		httpslog.Warn("ACL rejection", "ip", conn.RemoteAddr().String())
		conn.Close()
		return nil
	}
	// check SNI against domainlist for an extra layer of security
	if connInfo.Decision == acl.OriginIP {
		httpslog.Warn("a client requested connection to " + sni + ", but it's not allowed as per configuration.. resetting TCP")
		conn.Close()
		return nil
	}
	rPort := 443
	var rAddr net.IP
	if connInfo.Decision == acl.Override {
		httpslog.Info("overriding destination IP", "ip", rAddr.String(), "newip", connInfo.DstIP.String())
		rAddr = connInfo.DstIP.IP
		rPort = connInfo.DstIP.Port
	} else {
		rAddr, err = c.dnsClient.lookupDomain4(sni)
		if err != nil || rAddr == nil {
			httpslog.Warn(err.Error())
			return err
		}
		// TODO: handle timeout and context here
		if rAddr.IsLoopback() || rAddr.IsPrivate() || rAddr.Equal(net.IPv4(0, 0, 0, 0)) || rAddr.Equal(net.IP(c.PublicIPv4)) || rAddr.Equal(net.IP(c.sourceAddr)) || rAddr.Equal(net.IP(c.PublicIPv6)) {
			httpslog.Info("connection to private IP or self ignored")
			return nil
		}
	}

	httpslog.Info("establishing connection",
		"remote", fmt.Sprintf("%s:%d", rAddr.String(), rPort),
		"source", conn.RemoteAddr().String(),
		"host", sni,
	)
	var target *net.TCPConn
	if c.dialer == proxy.Direct {
		// with the manipulation of the soruce address, we can set the outbound interface
		srcAddr := net.TCPAddr{
			IP:   c.sourceAddr,
			Port: 0,
		}
		target, err = net.DialTCP("tcp", &srcAddr, &net.TCPAddr{IP: rAddr, Port: rPort})
		if err != nil {
			httpslog.Error("could not connect to target", "detail", err)
			conn.Close()
			return err
		}
	} else {
		tmp, err := c.dialer.Dial("tcp", fmt.Sprintf("%s:%d", rAddr, rPort))
		if err != nil {
			httpslog.Error("could not connect to target", "detail", err)
			conn.Close()
			return err
		}
		target = tmp.(*net.TCPConn)
	}
	defer target.Close()
	c.proxiedHTTPS.Inc(1)
	target.Write(incoming[:n])
	pipe(conn, target)
	return nil
}

func runHTTPS() {

	l, err := net.Listen("tcp", c.BindHTTPS)
	if err != nil {
		httpslog.Error(err.Error())
		panic(-1)
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			httpslog.Error(err.Error())
		}
		go func() {
			go handle443(c)
		}()
	}
}
