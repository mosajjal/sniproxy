package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/exp/slices"
	slog "golang.org/x/exp/slog"
)

var geolog = slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue("geoip")}}))

// getCountry returns the country code for the given IP address.
func getCountry(ipAddr string) (string, error) {
	ip := net.ParseIP(ipAddr)
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	} // Or any appropriate struct

	err := c.mmdb.Lookup(ip, &record)
	if err != nil {
		return "", err
	}
	return record.Country.ISOCode, nil
}

// initializeGeoIP loads the geolocation database from the specified path.
func initializeGeoIP(path string) error {

	geolog.Info("Loading the domain from file/url")
	var scanner []byte
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		geolog.Info("domain list is a URL, trying to fetch")
		resp, err := http.Get(path)
		if err != nil {
			return err
		}
		geolog.Info("(re)fetching", "path", path)
		defer resp.Body.Close()
		scanner, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

	} else {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		geolog.Info("(re)loading File: ", path)
		defer file.Close()
		n, err := file.Read(scanner)
		if err != nil {
			return err
		}
		geolog.Info("geolocation database loaded", n)

	}
	var err error
	if c.mmdb, err = maxminddb.FromBytes(scanner); err != nil {
		//geolog.Warn("%d bytes read, %s", len(scanner), err)
		return err
	}
	geolog.Info("Loaded MMDB")
	for range time.NewTicker(c.GeoIPRefreshInterval).C {
		if c.mmdb, err = maxminddb.FromBytes(scanner); err != nil {
			//geolog.Warn("%d bytes read, %s", len(scanner), err)
			return err
		}
		geolog.Info("Loaded MMDB %v", c.mmdb)
	}
	return nil
}

// checkGeoIPSkip checks an IP address against the exclude and include lists and returns
// true if the IP address should be allowed to pass through.
func checkGeoIPSkip(ipport string) bool {
	if c.mmdb == nil {
		return true
	}

	ipPort := strings.Split(ipport, ":")
	ip := ipPort[0]

	var country string
	country, err := getCountry(ip)
	country = strings.ToLower(country)
	if err != nil {
		geolog.Info("Failed to get the geolocation of", "ip", ip, "country", country)
		return false
	}
	if slices.Contains(c.GeoIPExclude, country) {
		return false
	}
	if slices.Contains(c.GeoIPInclude, country) {
		return true
	}

	// if exclusion is provided, the rest will be allowed
	if len(c.GeoIPExclude) > 0 {
		return true
	}

	// othewise fail
	return false
}
