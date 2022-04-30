package doh

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"net/http"
	"net/http/httptrace"
	"net/url"

	"github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type Client struct {
	Session *httptrace.ClientTrace
	Url     url.URL
}

func mustNewName(name string) dnsmessage.Name {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		panic(err)
	}
	return n
}

func New(server url.URL, tlsInsecureSkipVerify bool, compat bool) (Client, error) {
	// Select TLS protocols for DoH
	c := Client{}
	// Connect to DoQ server
	// log.Debugln("dialing doh server")
	c.Session = &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {},
	}
	c.Url = server
	return c, nil // nil error
}

func (c Client) SendQuery(msg dns.Msg) (dns.Msg, time.Duration, error) {
	// get the time
	start := time.Now()
	msgbytes, err := msg.Pack()
	if err != nil {
		return dns.Msg{}, 0, err
	}

	m := dnsmessage.Message{}
	err = m.Unpack(msgbytes)
	if err != nil {
		return dns.Msg{}, 0, err
	}
	dohbytes, err := m.Pack()
	if err != nil {
		return dns.Msg{}, 0, err
	}
	// convert to base64
	dohbase64 := base64.StdEncoding.EncodeToString(dohbytes)
	dohbase64 = strings.TrimSuffix(dohbase64, "=")
	// and get the response
	traceCtx := httptrace.WithClientTrace(context.Background(), c.Session)

	doh_url := c.Url.Scheme + "://" + c.Url.Host + c.Url.Path + "?dns=" + dohbase64
	req, err := http.NewRequestWithContext(traceCtx, http.MethodGet, doh_url, nil)
	if err != nil {
		log.Println(err)
		return dns.Msg{}, 0, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return dns.Msg{}, 0, err
	}
	// read the body
	body, _ := ioutil.ReadAll(res.Body)
	// parse body as a dns message
	var msg2 dns.Msg
	msg2.Unpack(body)

	//end time
	end := time.Now()
	// return the message
	return msg2, end.Sub(start), nil
}
