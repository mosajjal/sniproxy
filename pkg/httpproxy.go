package sniproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
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

// dstIsSelf reports whether a proxied destination points back at sniproxy
// itself, at loopback, or into private address space, along with the address it
// resolved to.
//
// An IP literal is checked directly. A hostname is resolved through the same
// upstream the TLS path uses, so a name that resolves to 127.0.0.1 is caught
// too. When no DNS client is configured there is nothing to resolve with, and
// the destination is treated as external.
func dstIsSelf(c *Config, hostPort string) (netip.Addr, bool) {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, isSelf(c, ip)
	}

	// localhost is special-cased because it usually resolves through the
	// system, not through the configured upstream
	if strings.EqualFold(host, "localhost") {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1}), true
	}

	if c.DNSClient.Resolver == nil {
		return netip.Addr{}, false
	}
	ip, err := c.DNSClient.lookupDomain(host, c.PreferredVersion)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, isSelf(c, ip)
}

// isManagementPort reports whether port belongs to one of sniproxy's own
// diagnostic listeners. Those serve stack traces and runtime internals with no
// authentication, so they must never be reachable through the proxy.
func (c *Config) isManagementPort(port string) bool {
	for _, bind := range []string{c.BindPprof, c.BindPrometheus} {
		if bind == "" {
			continue
		}
		if _, p, err := net.SplitHostPort(bind); err == nil && p == port {
			return true
		}
	}
	return false
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
		// Refuse to proxy back into sniproxy itself. This used to be a string
		// prefix test against the configured public IP, which meant a Host of
		// 127.0.0.1, or any private address, was proxied happily. That let a
		// client reach sniproxy's own loopback-bound listeners through the
		// proxy, so binding the pprof endpoint to loopback protected nothing.
		// The TLS path has always run this check after resolving the SNI.
		if dstIP, self := dstIsSelf(c, r.Host); self {
			if !c.AllowConnToLocal {
				l.Warn().Str("host", r.Host).Msg("refusing to proxy to sniproxy itself or a local address")
				http.Error(w, "Could not reach origin server", 404)
				return
			}
			// allow_conn_to_local opts into proxying private destinations, but
			// never into sniproxy's own diagnostic listeners: they carry no
			// authentication of their own.
			if _, port, err := net.SplitHostPort(r.Host); err == nil && c.isManagementPort(port) {
				l.Warn().Str("host", r.Host).Str("dst", dstIP.String()).Msg("refusing to proxy to sniproxy's own diagnostic listener")
				http.Error(w, "Could not reach origin server", 404)
				return
			}
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
