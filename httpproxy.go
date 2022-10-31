package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var verbose = false

var passthruRequestHeaderKeys = [...]string{
	"Accept",
	"Accept-Encoding",
	"Accept-Language",
	"Cache-Control",
	"Cookie",
	"Referer",
	"User-Agent",
}

var passthruResponseHeaderKeys = [...]string{
	"Content-Encoding",
	"Content-Language",
	"Content-Type",
	"Cache-Control", // TODO: Is this valid in a response?
	"Date",
	"Etag",
	"Expires",
	"Last-Modified",
	"Location",
	"Server",
	"Vary",
}

func runHTTP() {
	handler := http.DefaultServeMux

	handler.HandleFunc("/", handle80)

	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", c.HTTPPort),
		Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	s.ListenAndServe()
}

func handle80(w http.ResponseWriter, r *http.Request) {
	if !checkGeoIPSkip(r.RemoteAddr) {
		http.Error(w, "Could not reach origin server", 403)
		return
	} else {
		log.Infof("Rejected request from %s", r.RemoteAddr)
	}

	// NOTE: if the URL starts with the public IP, it needs to be skipped to avoid loops
	if strings.HasPrefix(r.Host, c.PublicIP) {
		log.Warnf("[HTTP] someone is requesting HTTP to sniproxy itself, ignoring...")
		http.Error(w, "Could not reach origin server", 404)
		return
	}

	log.Infof("[HTTP] REQ: %v %v%v\n", r.Method, r.Host, r.URL)

	// Construct filtered header to send to origin server
	hh := http.Header{}
	for _, hk := range passthruRequestHeaderKeys {
		if hv, ok := r.Header[hk]; ok {
			hh[hk] = hv
		}
	}

	// Construct request to send to origin server
	rr := http.Request{
		Method: r.Method,
		URL:    r.URL,
		Header: hh,
		Body:   r.Body,
		// TODO: Is this correct for a 0 value?
		//       Perhaps a 0 may need to be reinterpreted as -1?
		ContentLength: r.ContentLength,
		Close:         r.Close,
	}
	rr.URL.Scheme = "http"
	rr.URL.Host = r.Host

	// check to see if this host is listed to be processed, otherwise RESET
	if !c.AllDomains && inDomainList(r.Host+".") {
		http.Error(w, "Could not reach origin server", 403)
		log.Warnf("[HTTP] a client requested connection to %s, but it's not allowed as per configuration.. sending 403", r.Host)
		return
	}

	// TODO: if host is the reverse proxy, this request needs to be handled by the upstream address
	if r.Host == c.reverseProxySNI {
		reverseProxyURI, err := url.Parse(c.reverseProxyAddr)
		if err != nil {
			log.Errorf("failed to parse reverseproxy url: %s", err)
		}
		// TODO: maybe this won't work and I need to be more specific
		// rr.URL = reverseProxyURI
		hostPort := fmt.Sprintf("%s:%s", reverseProxyURI.Host, reverseProxyURI.Port())
		rr.URL.Host = reverseProxyURI.Host
		// add the port to the host header
		rr.Header.Set("Host", hostPort)
	}

	// Forward request to origin server
	resp, err := http.DefaultTransport.RoundTrip(&rr)
	if err != nil {
		// TODO: Passthru more error information
		http.Error(w, "Could not reach origin server", 500)
		log.Warnf("%s", err)
		return
	}
	defer resp.Body.Close()

	if verbose {
		log.Infof("[HTTP] RES: %v %+v\n", resp.Status, resp.Header)
	} else {
		log.Infof("[HTTP] RES: %v\n", resp.Status)
	}

	// Transfer filtered header from origin server -> client
	respH := w.Header()
	for _, hk := range passthruResponseHeaderKeys {
		if hv, ok := resp.Header[hk]; ok {
			respH[hk] = hv
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Transfer response from origin server -> client
	if resp.ContentLength > 0 {
		// (Ignore I/O errors, since there's nothing we can do)
		io.CopyN(w, resp.Body, resp.ContentLength)
	} else if resp.Close { // TODO: Is this condition right?
		// Copy until EOF or some other error occurs
		for {
			if _, err := io.Copy(w, resp.Body); err != nil {
				break
			}
		}
	}
}
