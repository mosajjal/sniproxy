package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	slog "golang.org/x/exp/slog"
)

var httplog = slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue("http")}}))

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
	}
	httplog.Info("rejected request", "ip", r.RemoteAddr)

	// if the URL starts with the public IP, it needs to be skipped to avoid loops
	if strings.HasPrefix(r.Host, c.PublicIP) {
		httplog.Warn("someone is requesting HTTP to sniproxy itself, ignoring...")
		http.Error(w, "Could not reach origin server", 404)
		return
	}

	httplog.Info("REQ", "method", r.Method, "host", r.Host, "url", r.URL)

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
		httplog.Warn("a client requested connection to " + r.Host + ", but it's not allowed as per configuration.. sending 403")
		return
	}

	// if host is the reverse proxy, this request needs to be handled by the upstream address
	if r.Host == c.reverseProxySNI {
		reverseProxyURI, err := url.Parse(c.reverseProxyAddr)
		if err != nil {
			httplog.Error("failed to parse reverseproxy url", err)

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
		httplog.Error("", err)
		return
	}
	defer resp.Body.Close()

	httplog.Info("http response", "status_code", resp.Status)

	// Transfer filtered header from origin server -> client
	respH := w.Header()
	for _, hk := range passthruResponseHeaderKeys {
		if hv, ok := resp.Header[hk]; ok {
			respH[hk] = hv
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Transfer response from origin server -> client
	//TODO: error handling
	io.Copy(w, resp.Body)
	// if resp.ContentLength > 0 {
	// 	// (Ignore I/O errors, since there's nothing we can do)
	// 	io.CopyN(w, resp.Body, resp.ContentLength)
	// } else if resp.Close { // TODO: Is this condition right?
	// 	// Copy until EOF or some other error occurs
	// 	for {
	// 		if _, err := io.Copy(w, resp.Body); err != nil {
	// 			break
	// 		}
	// 	}
	// }
}
