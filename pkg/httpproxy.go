package sniproxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rs/zerolog"
)

// var httplog = logger.With().Str("service", "http").Logger()
var httplog zerolog.Logger

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

func RunHTTP(c *Config, l zerolog.Logger) {
	httplog = l.With().Str("service", "http").Logger()
	handler := http.DefaultServeMux

	handler.HandleFunc("/", handle80(c))

	s := &http.Server{
		Addr:           c.BindHTTP,
		Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if err := s.ListenAndServe(); err != nil {
		httplog.Error().Msg(err.Error())
		panic(-1)
	}
}
func handle80(c *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.RecievedHTTP.Inc(1)

		addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)

		connInfo := acl.ConnInfo{
			SrcIP:  addr,
			Domain: r.Host,
		}
		acl.MakeDecision(&connInfo, c.Acl)
		if connInfo.Decision == acl.Reject || connInfo.Decision == acl.OriginIP || err != nil {
			httplog.Info().Str("src_ip", r.RemoteAddr).Msgf("rejected request")
			http.Error(w, "Could not reach origin server", 403)
			return
		}
		// if the URL starts with the public IP, it needs to be skipped to avoid loops
		if strings.HasPrefix(r.Host, c.PublicIPv4) {
			httplog.Warn().Msg("someone is requesting HTTP to sniproxy itself, ignoring...")
			http.Error(w, "Could not reach origin server", 404)
			return
		}

		httplog.Info().Str("method", r.Method).Str("host", r.Host).Str("url", r.URL.String()).Msg("request received")

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
		// if !c.AllDomains && inDomainList(r.Host+".") {
		// 	http.Error(w, "Could not reach origin server", 403)
		// 	httplog.Warn().Msg("a client requested connection to " + r.Host + ", but it's not allowed as per configuration.. sending 403")
		// 	return
		// }

		transport := http.Transport{
			Dial: c.Dialer.Dial,
		}

		// Forward request to origin server
		resp, err := transport.RoundTrip(&rr)
		if err != nil {
			// TODO: Passthru more error information
			httplog.Error().Msg(err.Error())
			return
		}
		defer resp.Body.Close()

		httplog.Info().Msgf("http response with status_code %s", resp.Status)

		// Transfer filtered header from origin server -> client
		respH := w.Header()
		for _, hk := range passthruResponseHeaderKeys {
			if hv, ok := resp.Header[hk]; ok {
				respH[hk] = hv
			}
		}
		c.ProxiedHTTP.Inc(1)
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
}
