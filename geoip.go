package main

import (
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

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

func initializeGeoIP() {

	log.Info("Loading the domain from file/url")
	var scanner []byte
	if strings.HasPrefix(c.GeoIPPath, "http://") || strings.HasPrefix(c.GeoIPPath, "https://") {
		log.Info("domain list is a URL, trying to fetch")
		resp, err := http.Get(c.GeoIPPath)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("(re)fetching URL: ", c.GeoIPPath)
		defer resp.Body.Close()
		scanner, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

	} else {
		file, err := os.Open(c.GeoIPPath)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("(re)loading File: ", c.GeoIPPath)
		defer file.Close()
		n, err := file.Read(scanner)
		if err != nil {
			log.Fatal(err)
		} else {
			log.Infof("read %d bytes", n)
		}

	}
	var err error
	if c.mmdb, err = maxminddb.FromBytes(scanner); err != nil {
		log.Warnf("%d bytes read, %s", len(scanner), err)
	} else {
		log.Infof("Loaded MMDB")
	}
	for range time.NewTicker(c.GeoIPRefreshInterval).C {
		if c.mmdb, err = maxminddb.FromBytes(scanner); err != nil {
			log.Warnf("%d bytes read, %s", len(scanner), err)
		} else {
			log.Infof("Loaded MMDB %v", c.mmdb)
		}
	}
}

// check an IP against exclude and include list and returns if this IP should be included
// or excluded. returns true if this IP is allowed to pass through
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
		log.Infof("Failed to get the country of IP %s,%s", ip, country)
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
