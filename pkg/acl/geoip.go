package acl

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knadh/koanf"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
)

// geoIP is an ACL that checks the geolocation of incoming connections and
// allows or rejects them based on the country of origin. It uses an MMDB
// database file to determine the country of origin.
// unlike ip and domain ACLs, geoIP does not load the list of countries
// from a CSV file. Instead it reads the country codes to reject or accept
// from the YAML configuration. This is due to the fact that domain and IP
// lists could be loaded from external resources and could be highly dynamic
// whereas geoip restrictions are usually static.
type geoIP struct {
	Path             string
	AllowedCountries []string
	BlockedCountries []string
	Refresh          time.Duration
	mu               sync.RWMutex
	mmdb             *maxminddb.Reader
	logger           *zerolog.Logger
	priority         uint
}

func toLowerSlice(in []string) (out []string) {
	for _, v := range in {
		out = append(out, strings.ToLower(v))
	}
	return
}

// getCountry returns the country code for the given IP address in ISO format
func (g *geoIP) getCountry(ipAddr string) (string, error) {
	ip := net.ParseIP(ipAddr)
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	err := g.mmdb.Lookup(ip, &record)
	if err != nil {
		return "", err
	}
	return record.Country.ISOCode, nil
}

// loadMMDB fetches the MMDB database from file or URL and loads it
func (g *geoIP) loadMMDB() error {
	g.logger.Info().Msg("loading the geoip db from file/url")
	var data []byte
	if strings.HasPrefix(g.Path, "http://") || strings.HasPrefix(g.Path, "https://") {
		g.logger.Info().Msg("geoip db path is a URL, trying to fetch")
		client := http.Client{Timeout: 60 * time.Second}
		resp, err := client.Get(g.Path)
		if err != nil {
			return err
		}
		g.logger.Info().Msgf("(re)fetching %s", g.Path)
		defer func() { _ = resp.Body.Close() }()
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
	} else {
		g.logger.Info().Msgf("(re)loading file: %s", g.Path)
		var err error
		if data, err = os.ReadFile(g.Path); err != nil {
			return err
		}
	}
	g.logger.Info().Msgf("geolocation database with %d bytes loaded", len(data))

	newMMDB, err := maxminddb.FromBytes(data)
	if err != nil {
		return err
	}

	g.mu.Lock()
	g.mmdb = newMMDB
	g.mu.Unlock()

	g.logger.Info().Msg("Loaded MMDB")
	return nil
}

// initializeGeoIP loads the geolocation database and periodically refreshes it
func (g *geoIP) initializeGeoIP() error {
	if err := g.loadMMDB(); err != nil {
		return err
	}
	for range time.NewTicker(g.Refresh).C {
		if err := g.loadMMDB(); err != nil {
			g.logger.Warn().Err(err).Msg("failed to reload MMDB")
		}
	}
	return nil
}

// checkGeoIPSkip checks an IP address against the exclude and include lists and returns
// true if the IP address should be allowed to pass through.
// the logic is as follows:
// 1. if mmdb is not loaded or not available, it's fail-open (allow by default)
// 2. if the IP can't be resolved to a country, it's rejected
// 3. if the country is in the blocked list, it's rejected
// 4. if the country is in the allowed list, it's allowed
// note that the reject list is checked first and takes priority over the allow list
// if the IP's country doesn't match any of the above, it's allowed if the blocked list is not empty
func (g *geoIP) checkGeoIPSkip(addr net.Addr) bool {
	g.mu.RLock()
	mmdbLoaded := g.mmdb != nil
	g.mu.RUnlock()

	if !mmdbLoaded {
		return true
	}

	// Use net.SplitHostPort for correct IPv6 handling
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		// fallback - might be IP without port
		host = addr.String()
	}

	var country string
	country, err = g.getCountry(host)
	country = strings.ToLower(country)
	g.logger.Debug().Msgf("incoming tcp connection from ip %s and country %s", host, country)

	if err != nil {
		g.logger.Info().Msgf("failed to get the geolocation of ip %s", host)
		return false
	}
	if slices.Contains(g.BlockedCountries, country) {
		return false
	}
	if slices.Contains(g.AllowedCountries, country) {
		return true
	}

	// if exclusion is provided, the rest will be allowed
	if len(g.BlockedCountries) > 0 {
		return true
	}

	// otherwise fail
	return false
}

// Decide implements the ACL interface
func (g *geoIP) Decide(c *ConnInfo) error {
	g.logger.Debug().Any("conn", c).Msg("deciding on geoip acl")
	// in checkGeoIPSkip, false is reject
	if !g.checkGeoIPSkip(c.SrcIP) {
		g.logger.Info().Msgf("rejecting connection from ip %s", c.SrcIP)
		c.Decision = Reject
	}
	g.logger.Debug().Any("conn", c).Msg("decided on geoip acl")
	return nil
}
func (g *geoIP) Name() string {
	return "geoip"
}
func (g *geoIP) Priority() uint {
	return g.priority
}

func (g *geoIP) ConfigAndStart(logger *zerolog.Logger, c *koanf.Koanf) error {
	c = c.Cut(fmt.Sprintf("acl.%s", g.Name()))
	g.logger = logger
	g.Path = c.String("path")
	g.priority = uint(c.Int("priority")) //nolint:gosec // G115 - priority is a small non-negative config value
	g.AllowedCountries = toLowerSlice(c.Strings("allowed"))
	g.BlockedCountries = toLowerSlice(c.Strings("blocked"))
	g.Refresh = c.Duration("refresh_interval")
	go func() {
		if err := g.initializeGeoIP(); err != nil {
			g.logger.Error().Err(err).Msg("failed to initialize geoip")
		}
	}()
	return nil
}

// make the geoIP available at import time
func init() {
	availableACLs = append(availableACLs, &geoIP{})
}
