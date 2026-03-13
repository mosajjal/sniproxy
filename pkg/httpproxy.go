package sniproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mosajjal/sniproxy/v2/pkg/acl"
	"github.com/rs/zerolog"
)

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
	"Cache-Control",
	"Date",
	"Etag",
	"Expires",
	"Last-Modified",
	"Location",
	"Server",
	"Vary",
}

// RunHTTP starts the HTTP proxy server on the specified bind address.
// The bind address should be in the format "0.0.0.0:80" or similar.
// This function blocks and should typically be run in a goroutine.
func RunHTTP(c *Config, bind string, l zerolog.Logger) {
	handler := http.NewServeMux()
	l = l.With().Str("service", "http").Str("listener", bind).Logger()

	// Create transport once and reuse across requests for connection pooling
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     0, // unlimited per-host concurrent connections
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.Dialer.Dial(network, addr)
		},
	}

	handler.HandleFunc("/", handle80(c, l, transport))

	s := &http.Server{
		Addr:           bind,
		Handler:        handler,
		ReadTimeout:    HTTPReadTimeout,
		WriteTimeout:   HTTPWriteTimeout,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	l.Info().Str("bind", bind).Msg("starting http server")
	if err := s.ListenAndServe(); err != nil {
		l.Fatal().Err(err).Msg("failed to start http server")
	}
}

func handle80(c *Config, l zerolog.Logger, transport *http.Transport) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.ReceivedHTTP.Inc(1)

		// Get the TCP address from RemoteAddr
		remoteAddr := r.RemoteAddr
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			host = remoteAddr
		}

		connInfo := acl.ConnInfo{
			SrcIP:  &net.TCPAddr{IP: net.ParseIP(host)},
			Domain: r.Host,
		}
		if err := acl.MakeDecision(&connInfo, c.ACL); err != nil {
			l.Error().Err(err).Msg("ACL decision failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if connInfo.Decision == acl.Reject || connInfo.Decision == acl.OriginIP {
			l.Info().Str("src_ip", remoteAddr).Msgf("rejected request")
			http.Error(w, "Could not reach origin server", http.StatusForbidden)
			return
		}
		// if the URL starts with the public IP, it needs to be skipped to avoid loops
		if strings.HasPrefix(r.Host, c.PublicIPv4) || (c.PublicIPv6 != "" && strings.HasPrefix(r.Host, c.PublicIPv6)) {
			l.Warn().Msg("someone is requesting HTTP to sniproxy itself, ignoring...")
			http.Error(w, "Could not reach origin server", 404)
			return
		}

		l.Info().Str("method", r.Method).Str("host", r.Host).Str("url", r.URL.String()).Msg("request received")

		// Construct filtered header to send to origin server
		hh := http.Header{}
		for _, hk := range passthruRequestHeaderKeys {
			if hv, ok := r.Header[hk]; ok {
				hh[hk] = hv
			}
		}

		// Construct request to send to origin server
		rr := http.Request{
			Method:        r.Method,
			URL:           r.URL,
			Header:        hh,
			Body:          r.Body,
			ContentLength: r.ContentLength,
			Close:         r.Close,
		}
		rr.URL.Scheme = "http"
		rr.URL.Host = r.Host

		// Forward request to origin server
		resp, err := transport.RoundTrip(&rr)
		if err != nil {
			l.Error().Err(err).Str("host", r.Host).Msg("failed to forward HTTP request")
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		l.Info().Msgf("http response with status_code %s", resp.Status)

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
		if _, err := io.Copy(w, resp.Body); err != nil {
			l.Debug().Err(err).Msg("error copying response body")
		}
	}
}
