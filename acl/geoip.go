package acl

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/knadh/koanf"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"
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
func (g geoIP) getCountry(ipAddr string) (string, error) {
	ip := net.ParseIP(ipAddr)
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	} // Or any appropriate struct

	err := g.mmdb.Lookup(ip, &record)
	if err != nil {
		return "", err
	}
	return record.Country.ISOCode, nil
}

// initializeGeoIP loads the geolocation database from the specified g.Path.
func (g *geoIP) initializeGeoIP() error {

	g.logger.Info().Msg("Loading the domain from file/url")
	var scanner []byte
	if strings.HasPrefix(g.Path, "http://") || strings.HasPrefix(g.Path, "https://") {
		g.logger.Info().Msg("domain list is a URL, trying to fetch")
		resp, err := http.Get(g.Path)
		if err != nil {
			return err
		}
		g.logger.Info().Msgf("(re)fetching %s", g.Path)
		defer resp.Body.Close()
		scanner, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

	} else {
		g.logger.Info().Msgf("(re)loading File: %s", g.Path)
		var err error
		if scanner, err = ioutil.ReadFile(g.Path); err != nil {
			return err
		}
	}
	g.logger.Info().Msgf("geolocation database with %d bytes loaded", len(scanner))
	var err error
	if g.mmdb, err = maxminddb.FromBytes(scanner); err != nil {
		//g.logger.Warn("%d bytes read, %s", len(scanner), err)
		return err
	}
	g.logger.Info().Msg("Loaded MMDB")
	for range time.NewTicker(g.Refresh).C {
		if g.mmdb, err = maxminddb.FromBytes(scanner); err != nil {
			//g.logger.Warn("%d bytes read, %s", len(scanner), err)
			return err
		}
		g.logger.Info().Msgf("Loaded MMDB %v", g.mmdb)
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
// for example, if the blockedlist is [US] and the allowedlist is empty, a connection from
// CA will be allowed. but if blockedlist is empty and allowedlist is [US], a connection from
// CA will be rejected.
func (g geoIP) checkGeoIPSkip(addr net.Addr) bool {
	if g.mmdb == nil {
		return true
	}

	ipPort := strings.Split(addr.String(), ":")
	ip := ipPort[0]

	var country string
	country, err := g.getCountry(ip)
	country = strings.ToLower(country)
	g.logger.Debug().Msgf("incoming tcp connection from ip %s and country %s", ip, country)

	if err != nil {
		g.logger.Info().Msgf("Failed to get the geolocation of ip %s", ip)
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

	// othewise fail
	return false
}

// implement the ACL interface
func (g geoIP) Decide(c *ConnInfo) error {
	g.logger.Debug().Any("conn", c).Msg("deciding on geoip acl")
	// in checkGeoIPSkip, false is reject
	if !g.checkGeoIPSkip(c.SrcIP) {
		g.logger.Info().Msgf("rejecting connection from ip %s", c.SrcIP)
		c.Decision = Reject
	}
	g.logger.Debug().Any("conn", c).Msg("decided on geoip acl")
	return nil
}
func (g geoIP) Name() string {
	return "geoip"
}
func (g geoIP) Priority() uint {
	return g.priority
}

func (g *geoIP) ConfigAndStart(logger *zerolog.Logger, c *koanf.Koanf) error {
	c = c.Cut(fmt.Sprintf("acl.%s", g.Name()))
	g.logger = logger
	g.Path = c.String("path")
	g.priority = uint(c.Int("priority"))
	g.AllowedCountries = toLowerSlice(c.Strings("allowed"))
	g.BlockedCountries = toLowerSlice(c.Strings("blocked"))
	g.Refresh = c.Duration("refresh_interval")
	go g.initializeGeoIP()
	return nil
}

// make the geoIP available at import time
func init() {
	availableACLs = append(availableACLs, &geoIP{})
}
